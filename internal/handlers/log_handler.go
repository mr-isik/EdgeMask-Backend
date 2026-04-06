package handlers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// LogHandler provides filtered request log endpoints for the dashboard.
type LogHandler struct {
	logRepo domain.RequestLogRepository
}

// NewLogHandler creates a new LogHandler and registers routes.
func NewLogHandler(app fiber.Router, logRepo domain.RequestLogRepository) {
	h := &LogHandler{logRepo: logRepo}

	app.Get("/logs", h.GetLogs)
}

// GetLogs godoc
// @Summary      List filtered request logs
// @Description  Returns paginated request logs with PII redaction metadata. Raw prompts are NEVER stored or returned — only metadata such as PII categories, model, latency, and key prefix.
// @Tags         Logs
// @Produce      json
// @Param        page      query     int     false  "Page number (1-based)"    default(1)   minimum(1)
// @Param        per_page  query     int     false  "Items per page (max 100)" default(20)  minimum(1)  maximum(100)
// @Param        pii_only  query     bool    false  "Return only logs where PII was detected" default(false)
// @Success      200       {object}  LogListResponse
// @Failure      400       {object}  ErrorResponse
// @Failure      401       {object}  ErrorResponse
// @Failure      500       {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/logs [get]
func (h *LogHandler) GetLogs(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	page, _ := strconv.Atoi(c.Query("page", "1"))
	perPage, _ := strconv.Atoi(c.Query("per_page", "20"))
	piiOnly := c.Query("pii_only", "false") == "true"

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	filter := domain.RequestLogFilter{
		Page:    page,
		PerPage: perPage,
		PIIOnly: piiOnly,
	}

	result, err := h.logRepo.GetLogs(c.Context(), userID, filter)
	if err != nil {
		logger.Error("Failed to get request logs: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to retrieve request logs",
		})
	}

	return c.JSON(result)
}
