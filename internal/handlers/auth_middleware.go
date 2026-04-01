package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// AuthMiddleware validates the Authorization: Bearer <edgemask_live_...> key
// using the AuthService before the request reaches the handler.
// On success, it stores the KeyLookupResult in Fiber's Locals for downstream use.
func AuthMiddleware(authService domain.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing Authorization header",
			})
		}

		// Extract Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid Authorization format, expected: Bearer <key>",
			})
		}

		rawKey := parts[1]

		// Validate prefix
		if !strings.HasPrefix(rawKey, domain.APIKeyPrefix) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid API key prefix",
			})
		}

		// Validate key via AuthService (Redis fast path → DB fallback)
		result, err := authService.ValidateKey(c.Context(), rawKey)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Store auth context for downstream handlers
		c.Locals("user_id", result.UserID)
		c.Locals("plan", result.Plan)
		c.Locals("key_hash", hashKey(rawKey))

		return c.Next()
	}
}

// hashKey computes the SHA-256 hash of a raw API key.
func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}
