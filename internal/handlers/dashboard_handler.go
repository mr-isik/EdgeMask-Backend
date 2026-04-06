package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// DashboardHandler handles key management and provider key configuration.
type DashboardHandler struct {
	keyRepo      domain.KeyRepository
	providerRepo domain.ProviderKeyRepository
	encryption   domain.EncryptionService
}

// NewDashboardHandler creates a new DashboardHandler and registers routes.
func NewDashboardHandler(
	app fiber.Router,
	keyRepo domain.KeyRepository,
	providerRepo domain.ProviderKeyRepository,
	encryption domain.EncryptionService,
) {
	h := &DashboardHandler{
		keyRepo:      keyRepo,
		providerRepo: providerRepo,
		encryption:   encryption,
	}

	app.Get("/keys", h.ListKeys)
	app.Post("/keys", h.CreateKey)
	app.Patch("/keys/:id/revoke", h.RevokeKey)

	app.Get("/providers", h.ListProviderKeys)
	app.Post("/providers", h.SaveProviderKey)
	app.Put("/providers", h.SaveProviderKey)
	app.Delete("/providers/:provider", h.DeleteProviderKey)
}

// ListKeys godoc
// @Summary      List all API keys
// @Description  Returns all EdgeMask API keys for the authenticated user. Only prefixes are shown, never full keys or hashes.
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
	Name string `json:"name"` // Human label: "Production Key", etc.
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

type saveProviderKeyRequest struct {
	Provider string `json:"provider"` // "openai", "anthropic", "gemini"
	APIKey   string `json:"api_key"`  // Raw key from the customer
}

// SaveProviderKey godoc
// @Summary      Save or update a provider API key
// @Description  Encrypts and stores the customer's LLM provider key (OpenAI, Anthropic, or Gemini). Uses AES-256-GCM encryption at rest.
// @Tags         Provider Keys
// @Accept       json
// @Produce      json
// @Param        body  body      SaveProviderKeyReq   true  "Provider key to save"
// @Success      200   {object}  SaveProviderKeyResp
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/providers [post]
func (h *DashboardHandler) SaveProviderKey(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req saveProviderKeyRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	switch domain.ProviderID(req.Provider) {
	case domain.ProviderOpenAI, domain.ProviderAnthropic, domain.ProviderGemini:
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid provider. Must be: openai, anthropic, or gemini",
		})
	}

	if req.APIKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "api_key is required",
		})
	}

	encryptedKey, err := h.encryption.Encrypt(req.APIKey)
	if err != nil {
		logger.Error("Failed to encrypt provider key: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to encrypt key",
		})
	}

	keyHint := generateKeyHint(req.APIKey)

	if err := h.providerRepo.SaveProviderKey(
		c.Context(),
		userID,
		domain.ProviderID(req.Provider),
		encryptedKey,
		keyHint,
	); err != nil {
		logger.Error("Failed to save provider key: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to save provider key",
		})
	}

	return c.JSON(fiber.Map{
		"message":  "provider key saved successfully",
		"provider": req.Provider,
		"hint":     keyHint,
	})
}

func generateKeyHint(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// RevokeKey godoc
// @Summary      Revoke an API key
// @Description  Marks an EdgeMask API key as inactive. Subsequent proxy requests with this key will be rejected.
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

// DeleteProviderKey godoc
// @Summary      Delete a provider API key
// @Description  Hard deletes a customer's LLM provider API key from EdgeMask.
// @Tags         Provider Keys
// @Produce      json
// @Param        provider   path      string  true  "Provider ID to delete (openai, anthropic, gemini)"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  ErrorResponse
// @Failure      401  {object}  ErrorResponse
// @Failure      404  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/providers/{provider} [delete]
func (h *DashboardHandler) DeleteProviderKey(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	provider := c.Params("provider")

	if provider == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "provider is required",
		})
	}

	// Basic validation of provider name
	switch domain.ProviderID(provider) {
	case domain.ProviderOpenAI, domain.ProviderAnthropic, domain.ProviderGemini:
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid provider. Must be: openai, anthropic, or gemini",
		})
	}

	if err := h.providerRepo.DeleteProviderKey(c.Context(), userID, domain.ProviderID(provider)); err != nil {
		if err == domain.ErrProviderKeyMissing {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "provider key not found",
			})
		}
		logger.Error("Failed to delete provider key: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to delete provider key",
		})
	}

	return c.JSON(fiber.Map{
		"message":  "provider key deleted successfully",
		"provider": provider,
	})
}

// ListProviderKeys godoc
// @Summary      List configured provider API keys
// @Description  Returns all LLM provider API keys configured for the authenticated user (without revealing the actual secure key strings).
// @Tags         Provider Keys
// @Produce      json
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/providers [get]
func (h *DashboardHandler) ListProviderKeys(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	keys, err := h.providerRepo.ListProviderKeys(c.Context(), userID)
	if err != nil {
		logger.Error("Failed to list provider keys: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to list provider keys",
		})
	}

	return c.JSON(fiber.Map{
		"providers": keys,
	})
}
