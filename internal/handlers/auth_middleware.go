package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// AuthMiddleware validates the EdgeMask API key provided in the X-EdgeMask-Key header.
// The Authorization header is left untouched so the user's provider API key
// (e.g. OpenAI, Anthropic, Gemini) can be forwarded transparently.
func AuthMiddleware(authService domain.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		rawKey := strings.TrimSpace(c.Get("X-EdgeMask-Key"))
		if rawKey == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing X-EdgeMask-Key header",
			})
		}

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
		c.Locals("api_key_prefix", rawKey[:min(len(rawKey), len(domain.APIKeyPrefix)+4)])

		return c.Next()
	}
}

// hashKey computes the SHA-256 hash of a raw API key.
func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}
