package domain

import "time"

// User represents a B2B customer of the EdgeMask platform.
// Synced with Supabase Auth — the ID references auth.users(id).
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Plan      string    `json:"plan" db:"plan"` // "growth" or "enterprise"
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
