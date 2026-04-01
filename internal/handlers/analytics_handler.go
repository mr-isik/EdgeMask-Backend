package handlers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// AnalyticsHandler provides usage analytics endpoints for the dashboard.
type AnalyticsHandler struct {
	analyticsRepo domain.AnalyticsRepository
}

// NewAnalyticsHandler creates a new AnalyticsHandler and registers routes.
func NewAnalyticsHandler(app fiber.Router, analyticsRepo domain.AnalyticsRepository) {
	h := &AnalyticsHandler{analyticsRepo: analyticsRepo}

	app.Get("/stats", h.GetStats)
	app.Get("/usage-chart", h.GetUsageChart)
}

// GetStats godoc
// @Summary      Get aggregate statistics
// @Description  Returns total request count, total PII items redacted, and total tokens processed for the authenticated user.
// @Tags         Analytics
// @Produce      json
// @Success      200  {object}  AggregateStatsResp
// @Failure      401  {object}  ErrorResponse
// @Failure      500  {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/stats [get]
func (h *AnalyticsHandler) GetStats(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	stats, err := h.analyticsRepo.GetAggregateStats(c.Context(), userID)
	if err != nil {
		logger.Error("Failed to get stats: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to retrieve statistics",
		})
	}

	return c.JSON(stats)
}

// GetUsageChart godoc
// @Summary      Get usage chart data
// @Description  Returns time-series usage data grouped by day or hour, for building dashboard charts.
// @Tags         Analytics
// @Produce      json
// @Param        interval  query     string  false  "Grouping interval"  Enums(day, hour)  default(day)
// @Param        days      query     int     false  "Number of days to look back (1-90)"  default(7)  minimum(1)  maximum(90)
// @Success      200       {object}  UsageChartResp
// @Failure      400       {object}  ErrorResponse
// @Failure      401       {object}  ErrorResponse
// @Failure      500       {object}  ErrorResponse
// @Security     SupabaseJWT
// @Router       /api/usage-chart [get]
func (h *AnalyticsHandler) GetUsageChart(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(string)

	interval := c.Query("interval", "day")
	if interval != "day" && interval != "hour" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "interval must be 'day' or 'hour'",
		})
	}

	daysStr := c.Query("days", "7")
	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 || days > 90 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "days must be between 1 and 90",
		})
	}

	dataPoints, err := h.analyticsRepo.GetUsageChart(c.Context(), userID, interval, days)
	if err != nil {
		logger.Error("Failed to get usage chart: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to retrieve usage data",
		})
	}

	return c.JSON(fiber.Map{
		"interval": interval,
		"days":     days,
		"data":     dataPoints,
	})
}
