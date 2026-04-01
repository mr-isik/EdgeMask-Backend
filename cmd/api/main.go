package main

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/mr-isik/edgemask-backend/config"
	_ "github.com/mr-isik/edgemask-backend/docs"
	"github.com/mr-isik/edgemask-backend/internal/handlers"
	"github.com/mr-isik/edgemask-backend/internal/infrastructure/providers"
	"github.com/mr-isik/edgemask-backend/internal/services"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// @title           EdgeMask API
// @version         1.0
// @description     High-Performance B2B AI Proxy with PII Redaction. EdgeMask intercepts LLM API requests, scrubs PII data, and forwards them to OpenAI, Anthropic, or Gemini using customer-provided API keys (BYOK model).
// @termsOfService  https://edgemask.io/terms

// @contact.name   EdgeMask Support
// @contact.url    https://edgemask.io/support
// @contact.email  support@edgemask.io

// @license.name  Commercial
// @license.url   https://edgemask.io/license

// @host      localhost:3000
// @BasePath  /

// @securityDefinitions.apikey  EdgeMaskAPIKey
// @in                          header
// @name                        Authorization
// @description                 EdgeMask API Key. Format: `Bearer edgemask_live_...`

// @securityDefinitions.apikey  SupabaseJWT
// @in                          header
// @name                        Authorization
// @description                 Supabase JWT token for dashboard access. Format: `Bearer <jwt_token>`

// @tag.name         Proxy
// @tag.description  AI Proxy endpoints — forward requests to LLM providers with PII redaction

// @tag.name         Key Management
// @tag.description  Manage EdgeMask API keys (edgemask_live_...)

// @tag.name         Provider Keys
// @tag.description  Manage customer-owned LLM provider API keys (BYOK)

// @tag.name         Analytics
// @tag.description  Usage statistics and time-series analytics for the dashboard

func main() {
	cfg := config.LoadConfig()
	logger.Info("EdgeMask starting in ", cfg.AppEnv, " mode")

	app := fiber.New(fiber.Config{
		AppName:        "EdgeMask API",
		ReadBufferSize: 8192,
		Prefork:        false,
	})

	app.Use(recover.New())

	// ─── Swagger UI ────────────────────────────────────────────
	app.Get("/swagger/*", swagger.HandlerDefault)

	// ─── Health ────────────────────────────────────────────────
	// @Summary      Health check
	// @Description  Returns the health status of the EdgeMask service
	// @Tags         System
	// @Produce      json
	// @Success      200  {object}  docs.HealthResponse
	// @Router       /health [get]
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"service": "edgemask",
		})
	})

	// ─── Encryption ────────────────────────────────────────────
	encSvc, err := services.NewEncryptionService(cfg.MasterKey)
	if err != nil {
		logger.Error("Failed to initialize encryption service: ", err)
		panic(err)
	}
	_ = encSvc

	// ─── LLM Provider Adapters (stateless, BYOK) ──────────────
	openai := providers.NewOpenAIAdapter(cfg.OpenAIBaseURL)
	anthropic := providers.NewAnthropicAdapter(cfg.AnthropicBaseURL)
	gemini := providers.NewGeminiAdapter(cfg.GeminiBaseURL)
	_ = openai
	_ = anthropic
	_ = gemini

	// ─── Services ──────────────────────────────────────────────
	_ = services.NewScrubbingService()

	// ─── Routes: /v1/* (Proxy — edgemask_live_ key auth) ──────
	v1 := app.Group("/v1")
	_ = v1
	_ = handlers.AuthMiddleware
	_ = handlers.NewProxyHandler
	// TODO: Wire when DB is connected:
	// v1.Use(handlers.AuthMiddleware(authSvc))
	// handlers.NewProxyHandler(v1, proxySvc)

	// ─── Routes: /api/* (Dashboard — Supabase JWT auth) ───────
	api := app.Group("/api")
	api.Use(handlers.DashboardMiddleware(cfg.SupabaseJWTSecret))
	_ = api
	_ = handlers.NewDashboardHandler
	_ = handlers.NewAnalyticsHandler
	// TODO: Wire when DB is connected:
	// handlers.NewDashboardHandler(api, keyRepo, providerKeyRepo, encSvc)
	// handlers.NewAnalyticsHandler(api, analyticsRepo)

	// ─── Start Server ──────────────────────────────────────────
	addr := fmt.Sprintf(":%s", cfg.Port)
	logger.Info("Server listening on ", addr)
	logger.Info("Swagger UI: http://localhost:", cfg.Port, "/swagger/index.html")

	if err := app.Listen(addr); err != nil {
		logger.Error("Failed to start server: ", err)
	}
}
