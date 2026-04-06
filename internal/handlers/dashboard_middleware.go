package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// DashboardMiddleware authenticates requests using Supabase Auth JWTs.
// Supabase signs user tokens with ES256 (ECDSA). The public key is fetched
// from the project's JWKS endpoint and cached/refreshed automatically.
func DashboardMiddleware(supabaseURL string) fiber.Handler {
	// Build the JWKS endpoint URL
	jwksURL := fmt.Sprintf("%s/auth/v1/.well-known/jwks.json", strings.TrimRight(supabaseURL, "/"))
	logger.Info("Fetching JWKS from: ", jwksURL)

	// Create a JWKS keyfunc that auto-refreshes in the background.
	// keyfunc.NewDefault fetches the JWKS from the URL and keeps it fresh.
	k, err := keyfunc.NewDefault([]string{jwksURL})
	if err != nil {
		logger.Error("Failed to initialize JWKS keyfunc: ", err)
		// Return a middleware that always fails — server can't validate tokens
		return func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "authentication service unavailable",
			})
		}
	}

	logger.Info("JWKS keyfunc initialized successfully")

	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing Authorization header",
			})
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid Authorization format",
			})
		}

		tokenStr := parts[1]

		// Reject edgemask_live_ keys — this is the dashboard, not the proxy
		if strings.HasPrefix(tokenStr, "edgemask_live_") {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "API keys are not allowed on dashboard routes. Use your Supabase JWT.",
			})
		}

		// Parse and validate the Supabase JWT using JWKS
		token, err := jwt.Parse(tokenStr, k.KeyfuncCtx(c.Context()))

		if err != nil || !token.Valid {
			logger.Error("JWT validation failed: ", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid token claims",
			})
		}

		// Check expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "token has expired",
				})
			}
		}

		// Extract user ID from Supabase JWT (stored in "sub" claim)
		userID, ok := claims["sub"].(string)
		if !ok || userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing user ID in token",
			})
		}

		// Store in context for downstream handlers
		c.Locals("user_id", userID)

		return c.Next()
	}
}
