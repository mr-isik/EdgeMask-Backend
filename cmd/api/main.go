package main

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	goredis "github.com/redis/go-redis/v9"

	"github.com/mr-isik/edgemask-backend/config"
	_ "github.com/mr-isik/edgemask-backend/docs"
	"github.com/mr-isik/edgemask-backend/internal/handlers"
	"github.com/mr-isik/edgemask-backend/internal/infrastructure/database"
	"github.com/mr-isik/edgemask-backend/internal/infrastructure/providers"
	pgRepo "github.com/mr-isik/edgemask-backend/internal/repository/postgres"
	redisRepo "github.com/mr-isik/edgemask-backend/internal/repository/redis"
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
//
// @tag.name         Billing
// @tag.description  Dodo Payments checkout and billing integration endpoints

func main() {
	cfg := config.LoadConfig()
	logger.Info("EdgeMask starting in ", cfg.AppEnv, " mode")

	// ─── Database (Supabase PostgreSQL) ────────────────────────
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		logger.Error("Failed to connect to database: ", err)
		panic(err)
	}
	defer db.Close()

	// ─── Run Migrations ─────────────────────────────────────────
	if err := database.RunMigrations(cfg.DatabaseURL, "./migrations"); err != nil {
		logger.Error("Failed to run migrations: ", err)
		panic(err)
	}

	// ─── Redis ─────────────────────────────────────────────────
	redisClient := goredis.NewClient(&goredis.Options{
		Addr:     cfg.RedisURL,
		Password: cfg.RedisPassword,
		DB:       0,
	})
	defer redisClient.Close()

	// ─── Repositories ──────────────────────────────────────────
	keyRepo := pgRepo.NewKeyRepository(db)
	providerKeyRepo := pgRepo.NewProviderKeyRepository(db)
	analyticsRepo := pgRepo.NewAnalyticsRepository(db)
	requestLogRepo := pgRepo.NewRequestLogRepository(db)
	userBillingRepo := pgRepo.NewUserBillingRepository(db)
	webhookEventRepo := pgRepo.NewWebhookEventRepository(db)
	keyCache := redisRepo.NewKeyCache(redisClient)
	semanticRepo := pgRepo.NewSemanticCacheRepository(db)
	semanticRespCache := redisRepo.NewSemanticResponseCache(redisClient)

	// ─── Services ──────────────────────────────────────────────
	encSvc, err := services.NewEncryptionService(cfg.MasterKey)
	if err != nil {
		logger.Error("Failed to initialize encryption service: ", err)
		panic(err)
	}

	scrubbingSvc := services.NewScrubbingService()
	authSvc := services.NewAuthService(keyRepo, keyCache)
	embeddingSvc := services.NewEmbeddingService(cfg.OpenAIBaseURL, cfg.SemanticCacheEmbeddingModel)
	billingSvc := services.NewBillingService(
		cfg.DodoPaymentsEnabled,
		cfg.DodoPaymentsAPIKey,
		cfg.DodoPaymentsBaseURL,
		cfg.DodoPaymentsEventName,
		userBillingRepo,
	)
	checkoutSvc := services.NewCheckoutService(
		cfg.DodoPaymentsAPIKey,
		cfg.DodoPaymentsBaseURL,
		userBillingRepo,
	)

	// ─── LLM Provider Adapters (stateless, BYOK) ──────────────
	openai := providers.NewOpenAIAdapter(cfg.OpenAIBaseURL)
	anthropic := providers.NewAnthropicAdapter(cfg.AnthropicBaseURL)
	gemini := providers.NewGeminiAdapter(cfg.GeminiBaseURL)

	proxySvc := services.NewProxyService(
		scrubbingSvc,
		encSvc,
		providerKeyRepo,
		cfg.SemanticCacheEnabled,
		time.Duration(cfg.SemanticCacheTTLSeconds)*time.Second,
		cfg.SemanticCacheSimilarityMinimum,
		semanticRepo,
		semanticRespCache,
		embeddingSvc,
		openai,
		anthropic,
		gemini,
	)

	// ─── Fiber App ─────────────────────────────────────────────
	app := fiber.New(fiber.Config{
		AppName:        "EdgeMask API",
		ReadBufferSize: 8192,
		Prefork:        false,
	})

	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3001",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS",
	}))

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

	// ─── Public Webhooks ───────────────────────────────────────
	handlers.NewDodoWebhookHandler(
		app,
		cfg.DodoWebhookSecret,
		time.Duration(cfg.DodoWebhookToleranceSeconds)*time.Second,
		webhookEventRepo,
	)

	// ─── Routes: /v1/* (Proxy — edgemask_live_ key auth) ──────
	v1 := app.Group("/v1")
	v1.Use(handlers.AuthMiddleware(authSvc))
	handlers.NewProxyHandler(v1, proxySvc, requestLogRepo, billingSvc)

	// ─── Routes: /api/* (Dashboard — Supabase JWT auth) ───────
	api := app.Group("/api")
	api.Use(handlers.DashboardMiddleware(cfg.SupabaseURL))
	handlers.NewDashboardHandler(api, keyRepo, providerKeyRepo, encSvc, checkoutSvc)
	handlers.NewAnalyticsHandler(api, analyticsRepo)
	handlers.NewLogHandler(api, requestLogRepo)

	// ─── Start Server ──────────────────────────────────────────
	addr := fmt.Sprintf(":%s", cfg.Port)
	logger.Info("Server listening on ", addr)
	logger.Info("Swagger UI: http://localhost:", cfg.Port, "/swagger/index.html")

	if err := app.Listen(addr); err != nil {
		logger.Error("Failed to start server: ", err)
	}
}
