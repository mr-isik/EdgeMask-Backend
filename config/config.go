package config

import (
	"os"

	"github.com/joho/godotenv"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// Config holds all configuration values for the EdgeMask application.
type Config struct {
	// Server
	Port   string
	AppEnv string

	// PostgreSQL (Supabase)
	DatabaseURL string

	// Redis
	RedisURL      string
	RedisPassword string

	// Security
	APIKeySecret string // Used for HMAC hashing of EdgeMask API keys
	MasterKey    string // 32-byte key for AES-256-GCM encryption of customer provider keys

	// Supabase (Dashboard Auth)
	SupabaseJWTSecret string // Supabase JWT signing secret for dashboard auth

	// LLM Provider Base URLs (keys come from customer DB, NOT env)
	OpenAIBaseURL    string
	AnthropicBaseURL string
	GeminiBaseURL    string
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

		SupabaseJWTSecret: getEnv("SUPABASE_JWT_SECRET", ""),

		OpenAIBaseURL:    getEnv("OPENAI_BASE_URL", "https://api.openai.com"),
		AnthropicBaseURL: getEnv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
		GeminiBaseURL:    getEnv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com"),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
