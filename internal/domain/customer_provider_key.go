package domain

import "time"

// CustomerProviderKey represents a customer's API key for a specific LLM provider.
// Keys are AES-GCM encrypted at rest — NEVER stored in plain text.
type CustomerProviderKey struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	Provider     string    `json:"provider" db:"provider"`           // "openai", "anthropic", "gemini"
	EncryptedKey string    `json:"-" db:"encrypted_key"`             // AES-GCM encrypted, never serialized
	KeyHint      string    `json:"key_hint,omitempty" db:"key_hint"` // "sk-...1234" for display
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}
