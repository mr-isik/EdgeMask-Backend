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
	app.Post("/providers", h.SaveProviderKey)
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
