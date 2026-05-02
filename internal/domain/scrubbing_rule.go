package domain

// ScrubbingRule defines a PII detection pattern and its replacement.
type ScrubbingRule struct {
	ID          string `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`               // e.g., "CREDIT_CARD", "EMAIL", "AWS_KEY"
	Pattern     string `json:"pattern" db:"pattern"`           // Regex pattern
	Replacement string `json:"replacement" db:"replacement"`   // e.g., "[REDACTED_CC]"
	IsEnabled   bool   `json:"is_enabled" db:"is_enabled"`
}

// RedactedMatch records a single PII match found during scrubbing.
type RedactedMatch struct {
	Type     string `json:"type"`     // Rule name that matched
	Original string `json:"original"` // The original matched text
	Position int    `json:"position"` // Start index in the input string
}

// ScrubbingResult holds the output of a scrubbing operation, including
// which PII categories were detected. Used by the logging system.
type ScrubbingResult struct {
	RedactedText  string   // The text after PII replacement
	Count         int      // Total number of PII items replaced
	ScrubbedTypes []string // Unique PII category names found (e.g. "CREDIT_CARD", "EMAIL")
}

// DefaultScrubbingRules returns all 15 built-in detection rules.
// The actual compiled regex patterns live in services/scrubbing_service.go.
//
// Categories:
//
//	Secrets:    AWS_KEY, GITHUB_TOKEN, STRIPE_SECRET, SLACK_TOKEN, JWT
//	Financial:  CREDIT_CARD, IBAN, ETH_WALLET
//	Identity:   SSN, DATE_OF_BIRTH, EMAIL, PHONE, IPV4, MAC_ADDRESS, US_PASSPORT
func DefaultScrubbingRules() []ScrubbingRule {
	return []ScrubbingRule{
		// ─── Secrets ───────────────────────────────────────────────
		{Name: "AWS_KEY", Pattern: `(?:AKIA|ASIA)[0-9A-Z]{16}`, Replacement: "[REDACTED_AWS_KEY]", IsEnabled: true},
		{Name: "GITHUB_TOKEN", Pattern: `gh[pousr]_[A-Za-z0-9_]{36,255}`, Replacement: "[REDACTED_GITHUB_TOKEN]", IsEnabled: true},
		{Name: "STRIPE_SECRET", Pattern: `[sr]k_(live|test)_[A-Za-z0-9]{20,}`, Replacement: "[REDACTED_STRIPE_KEY]", IsEnabled: true},
		{Name: "SLACK_TOKEN", Pattern: `xo(?:xb|xp|xa|xo)-[0-9A-Za-z\-]{20,}`, Replacement: "[REDACTED_SLACK_TOKEN]", IsEnabled: true},
		{Name: "JWT", Pattern: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}`, Replacement: "[REDACTED_JWT]", IsEnabled: true},

		// ─── Financial ─────────────────────────────────────────────
		{Name: "CREDIT_CARD", Pattern: `\b(?:\d[ \-]*?){13,16}\b`, Replacement: "[REDACTED_CC]", IsEnabled: true},
		{Name: "IBAN", Pattern: `\b[A-Z]{2}\d{2}[\s\-]?[\dA-Z]{4}[\s\-]?(?:[\dA-Z]{4}[\s\-]?){1,7}[\dA-Z]{1,4}\b`, Replacement: "[REDACTED_IBAN]", IsEnabled: true},
		{Name: "ETH_WALLET", Pattern: `\b0x[0-9a-fA-F]{40}\b`, Replacement: "[REDACTED_ETH]", IsEnabled: true},

		// ─── Identity (PII) ────────────────────────────────────────
		{Name: "SSN", Pattern: `\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b`, Replacement: "[REDACTED_SSN]", IsEnabled: true},
		{Name: "DATE_OF_BIRTH", Pattern: `\b(?:0[1-9]|1[0-2])[\s/\-\.](0[1-9]|[12]\d|3[01])[\s/\-\.](19|20)\d{2}\b`, Replacement: "[REDACTED_DOB]", IsEnabled: true},
		{Name: "EMAIL", Pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, Replacement: "[REDACTED_EMAIL]", IsEnabled: true},
		{Name: "PHONE", Pattern: `\b(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{1,4}\)?[\s\-]?)?\d{2,4}[\s\-]\d{3,4}[\s\-]\d{3,4}\b|\b\+\d{1,3}[\s\-]?\d{6,14}\b|\b0\d{3}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`, Replacement: "[REDACTED_PHONE]", IsEnabled: true},
		{Name: "IPV4", Pattern: `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`, Replacement: "[REDACTED_IP]", IsEnabled: true},
		{Name: "MAC_ADDRESS", Pattern: `\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b`, Replacement: "[REDACTED_MAC]", IsEnabled: true},
		{Name: "US_PASSPORT", Pattern: `\b[A-Z]\d{8}\b`, Replacement: "[REDACTED_PASSPORT]", IsEnabled: true},
	}
}

