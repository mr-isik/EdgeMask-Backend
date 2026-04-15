package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// Config holds all configuration values for the EdgeMask application.
type Config struct {
	// Server
	Port   string
	AppEnv string

	// Database (Supabase PostgreSQL via Pooler)
	DatabaseURL string

	// Redis
	RedisURL      string
	RedisPassword string

	// Security
	APIKeySecret string // Used for HMAC hashing of EdgeMask API keys
	MasterKey    string // 32-byte key for AES-256-GCM encryption of customer provider keys

	// Supabase
	SupabaseURL            string // Supabase project URL (e.g. https://xxx.supabase.co)
	SupabaseAnonKey        string // Client-side API key (anon role)
	SupabaseServiceRoleKey string // Server-side API key (service_role) — NEVER expose in client code
	SupabaseJWTSecret      string // JWT signing secret for verifying Supabase tokens

	// LLM Provider Base URLs (keys come from customer DB, NOT env)
	OpenAIBaseURL    string
	AnthropicBaseURL string
	GeminiBaseURL    string

	// Semantic cache
	SemanticCacheEnabled           bool
	SemanticCacheTTLSeconds        int
	SemanticCacheSimilarityMinimum float64
	SemanticCacheEmbeddingModel    string

	// Dodo Payments usage-based billing
	DodoPaymentsEnabled         bool
	DodoPaymentsAPIKey          string
	DodoPaymentsBaseURL         string
	DodoPaymentsEventName       string
	DodoWebhookSecret           string
	DodoWebhookToleranceSeconds int
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		logger.Info("No .env file found, reading from environment")
	}

	return &Config{
		Port:          getEnv("PORT", "3000"),
		AppEnv:        getEnv("APP_ENV", "development"),
		DatabaseURL:   getEnv("DATABASE_URL", ""),
		RedisURL:      getEnv("REDIS_URL", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		APIKeySecret:  getEnv("API_KEY_SECRET", ""),
		MasterKey:     getEnv("MASTER_KEY", ""),

		SupabaseURL:            getEnv("SUPABASE_URL", ""),
		SupabaseAnonKey:        getEnv("SUPABASE_ANON_KEY", ""),
		SupabaseServiceRoleKey: getEnv("SUPABASE_SERVICE_ROLE_KEY", ""),
		SupabaseJWTSecret:      getEnv("SUPABASE_JWT_SECRET", ""),

		OpenAIBaseURL:    getEnv("OPENAI_BASE_URL", "https://api.openai.com"),
		AnthropicBaseURL: getEnv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
		GeminiBaseURL:    getEnv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com"),

		SemanticCacheEnabled:           getEnvBool("SEMANTIC_CACHE_ENABLED", true),
		SemanticCacheTTLSeconds:        getEnvInt("SEMANTIC_CACHE_TTL_SECONDS", 3600),
		SemanticCacheSimilarityMinimum: getEnvFloat("SEMANTIC_CACHE_SIMILARITY_MIN", 0.92),
		SemanticCacheEmbeddingModel:    getEnv("SEMANTIC_CACHE_EMBEDDING_MODEL", "text-embedding-3-small"),

		DodoPaymentsEnabled:         getEnvBool("DODO_PAYMENTS_ENABLED", false),
		DodoPaymentsAPIKey:          getEnv("DODO_PAYMENTS_API_KEY", ""),
		DodoPaymentsBaseURL:         getEnv("DODO_PAYMENTS_BASE_URL", "https://test.dodopayments.com"),
		DodoPaymentsEventName:       getEnv("DODO_PAYMENTS_EVENT_NAME", "api.tokens.used"),
		DodoWebhookSecret:           getEnv("DODO_PAYMENTS_WEBHOOK_SECRET", ""),
		DodoWebhookToleranceSeconds: getEnvInt("DODO_PAYMENTS_WEBHOOK_TOLERANCE_SECONDS", 300),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvFloat(key string, fallback float64) float64 {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return b
}
