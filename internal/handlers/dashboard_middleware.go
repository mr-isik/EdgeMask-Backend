package handlers

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// DashboardMiddleware validates Supabase JWTs for dashboard routes.
// This is SEPARATE from AuthMiddleware — dashboard uses Supabase JWTs,
// while proxy uses edgemask_live_ API keys. They must NOT be mixed.
func DashboardMiddleware(jwtSecret string) fiber.Handler {
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

		// Parse and validate the Supabase JWT
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.NewError(fiber.StatusUnauthorized, "unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})

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
