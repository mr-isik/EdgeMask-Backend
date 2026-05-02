package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// DashboardHandler handles key management and billing for the EdgeMask dashboard.
// Provider key management has been removed — zero-trust architecture.
type DashboardHandler struct {
	keyRepo     domain.KeyRepository
}

// NewDashboardHandler creates a new DashboardHandler and registers routes.
func NewDashboardHandler(
	app fiber.Router,
	keyRepo domain.KeyRepository,
) {
	h := &DashboardHandler{
		keyRepo:     keyRepo,
	}

	app.Get("/keys", h.ListKeys)
	app.Post("/keys", h.CreateKey)
	app.Patch("/keys/:id/revoke", h.RevokeKey)


}



// ListKeys godoc
// @Summary      List all API keys
// @Description  Returns all EdgeMask API keys for the authenticated user.
// @Tags         Key Management
// @Produce      json
// @Success      200  {object}  ListKeysResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/keys [get]
func (h *DashboardHandler) ListKeys(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	keys, err := h.keyRepo.ListKeysByUserID(c.Context(), userID)
	if err != nil {
		logger.Error("Failed to list keys: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to retrieve keys",
		})
	}

	return c.JSON(fiber.Map{
		"keys": keys,
	})
}

type createKeyRequest struct {
	Name string `json:"name"`
}

// CreateKey godoc
// @Summary      Generate a new API key
// @Description  Creates a new edgemask_live_ API key. The raw key is returned ONLY ONCE — save it securely.
// @Tags         Key Management
// @Accept       json
// @Produce      json
// @Param        body  body      CreateKeyReq   true  "Key creation request"
// @Success      201   {object}  CreateKeyResp
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/keys [post]
func (h *DashboardHandler) CreateKey(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req createKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	if req.Name == "" {
		req.Name = "Default Key"
	}

	rawKey, err := h.keyRepo.CreateKey(c.Context(), userID, req.Name)
	if err != nil {
		logger.Error("Failed to create key: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to create API key",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"key":     rawKey,
		"message": "Save this key securely. It will NOT be shown again.",
	})
}

// RevokeKey godoc
// @Summary      Revoke an API key
// @Description  Marks an EdgeMask API key as inactive.
// @Tags         Key Management
// @Produce      json
// @Param        id   path      string  true  "Key ID to revoke"
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/keys/{id}/revoke [patch]
func (h *DashboardHandler) RevokeKey(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	keyID := c.Params("id")

	if keyID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "key ID is required",
		})
	}

	if err := h.keyRepo.RevokeKey(c.Context(), userID, keyID); err != nil {
		if err == domain.ErrKeyNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "key not found or already inactive",
			})
		}
		logger.Error("Failed to revoke key: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to revoke key",
		})
	}

	return c.JSON(fiber.Map{
		"message": "api key revoked successfully",
	})
}
