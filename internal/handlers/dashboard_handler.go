package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// DashboardHandler handles key management and billing for the EdgeMask dashboard.
// Provider key management has been removed — zero-trust architecture.
type DashboardHandler struct {
	keyRepo     domain.KeyRepository
	checkoutSvc domain.CheckoutService
}

// NewDashboardHandler creates a new DashboardHandler and registers routes.
func NewDashboardHandler(
	app fiber.Router,
	keyRepo domain.KeyRepository,
	checkoutSvc domain.CheckoutService,
) {
	h := &DashboardHandler{
		keyRepo:     keyRepo,
		checkoutSvc: checkoutSvc,
	}

	app.Get("/keys", h.ListKeys)
	app.Post("/keys", h.CreateKey)
	app.Patch("/keys/:id/revoke", h.RevokeKey)

	app.Post("/billing/checkout-session", h.CreateCheckoutSession)
	app.Post("/billing/customer-portal-session", h.CreateCustomerPortalSession)
}

type createCheckoutSessionRequest struct {
	ProductID     string `json:"product_id"`
	Quantity      int    `json:"quantity"`
	ReturnURL     string `json:"return_url"`
	CancelURL     string `json:"cancel_url"`
	CustomerEmail string `json:"customer_email"`
	CustomerName  string `json:"customer_name"`
}

type createCustomerPortalSessionRequest struct {
	ReturnURL string `json:"return_url"`
	SendEmail bool   `json:"send_email"`
}

// CreateCheckoutSession godoc
// @Summary      Create Dodo checkout session
// @Description  Creates a Dodo Payments checkout session and returns redirect URL.
// @Tags         Billing
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCheckoutSessionReq   true  "Checkout session request"
// @Success      200   {object}  CreateCheckoutSessionResp
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/billing/checkout-session [post]
func (h *DashboardHandler) CreateCheckoutSession(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	var req createCheckoutSessionRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
	}
	if req.ProductID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "product_id is required"})
	}
	if req.Quantity <= 0 {
		req.Quantity = 1
	}
	if h.checkoutSvc == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "checkout service unavailable"})
	}

	session, err := h.checkoutSvc.CreateSession(c.Context(), domain.CheckoutSessionRequest{
		UserID:        userID,
		ProductID:     req.ProductID,
		Quantity:      req.Quantity,
		ReturnURL:     req.ReturnURL,
		CancelURL:     req.CancelURL,
		CustomerEmail: req.CustomerEmail,
		CustomerName:  req.CustomerName,
	})
	if err != nil {
		logger.Error("Failed to create checkout session: ", err)
		statusCode := checkoutErrorStatus(err)
		return c.Status(statusCode).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"session_id":   session.SessionID,
		"checkout_url": session.CheckoutURL,
		"provider":     "dodopayments",
	})
}

// CreateCustomerPortalSession godoc
// @Summary      Create Dodo customer portal session
// @Description  Creates a dynamic Dodo Payments customer portal link for the authenticated user.
// @Tags         Billing
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCustomerPortalSessionReq   false  "Customer portal request"
// @Success      200   {object}  CreateCustomerPortalSessionResp
// @Failure      400   {object}  ErrorResponse
// @Failure      401   {object}  ErrorResponse
// @Failure      500   {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/billing/customer-portal-session [post]
func (h *DashboardHandler) CreateCustomerPortalSession(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)
	if h.checkoutSvc == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "checkout service unavailable"})
	}

	var req createCustomerPortalSessionRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
	}

	session, err := h.checkoutSvc.CreateCustomerPortalSession(c.Context(), domain.CustomerPortalSessionRequest{
		UserID:    userID,
		ReturnURL: req.ReturnURL,
		SendEmail: req.SendEmail,
	})
	if err != nil {
		logger.Error("Failed to create customer portal session: ", err)
		statusCode := checkoutErrorStatus(err)
		return c.Status(statusCode).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"portal_url": session.Link,
		"provider":   "dodopayments",
	})
}

// checkoutErrorStatus maps service-layer errors to appropriate HTTP status codes.
func checkoutErrorStatus(err error) int {
	if errors.Is(err, domain.ErrBillingMappingNotFound) {
		return fiber.StatusUnprocessableEntity // 422
	}
	msg := err.Error()
	validationPhrases := []string{
		"is required",
		"api key is required",
		"user id is required",
		"customer_email is required",
		"product_id is required",
	}
	for _, phrase := range validationPhrases {
		if strings.Contains(msg, phrase) {
			return fiber.StatusBadRequest // 400
		}
	}
	return fiber.StatusInternalServerError // 500
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
