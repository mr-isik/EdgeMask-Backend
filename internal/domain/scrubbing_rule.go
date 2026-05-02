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

// DefaultScrubbingRules returns all built-in PII detection rules in the order
// they must be evaluated. Ordering is critical — longer/more specific patterns
// (secrets, tokens) run before shorter/generic digit patterns to avoid false
// positives. PHONE must run before SSN.
//
// Categories:
//
//	Secrets:    JWT, AWS_KEY, GITHUB_TOKEN, STRIPE_SECRET, SLACK_TOKEN
//	Financial:  ETH_WALLET, IBAN, CREDIT_CARD
//	Identity:   EMAIL, MAC_ADDRESS, IPV4, DATE_OF_BIRTH, US_PASSPORT, PHONE, SSN
func DefaultScrubbingRules() []ScrubbingRule {
	return []ScrubbingRule{

		// ─── Secrets (long tokens, specific prefixes — match first) ─────────
		// JWT — three base64url segments: header.payload.signature
		// e.g. eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxw...
		{Name: "JWT", Pattern: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}`, Replacement: "[REDACTED_JWT]", IsEnabled: true},

		// AWS Access Key ID — AKIA (long-term) or ASIA (STS): AKIAIOSFODNN7EXAMPLE
		{Name: "AWS_KEY", Pattern: `(?:AKIA|ASIA)[0-9A-Z]{16}`, Replacement: "[REDACTED_AWS_KEY]", IsEnabled: true},

		// GitHub tokens — ghp_, gho_, ghu_, ghs_, ghr_ + 36+ alphanumeric chars
		{Name: "GITHUB_TOKEN", Pattern: `gh[pousr]_[A-Za-z0-9_]{36,255}`, Replacement: "[REDACTED_GITHUB_TOKEN]", IsEnabled: true},

		// Stripe keys — sk_live_*, sk_test_*, rk_live_*, rk_test_*
		{Name: "STRIPE_SECRET", Pattern: `[sr]k_(?:live|test)_[A-Za-z0-9]{20,}`, Replacement: "[REDACTED_STRIPE_KEY]", IsEnabled: true},

		// Slack tokens — xoxb-*, xoxp-*, xoxa-*, xoxo-*
		{Name: "SLACK_TOKEN", Pattern: `xo(?:xb|xp|xa|xo)-[0-9A-Za-z\-]{20,}`, Replacement: "[REDACTED_SLACK_TOKEN]", IsEnabled: true},

		// ─── Financial (match before generic digit patterns) ─────────────────
		// Ethereum wallet — 0x + 40 hex chars
		{Name: "ETH_WALLET", Pattern: `\b0x[0-9a-fA-F]{40}\b`, Replacement: "[REDACTED_ETH]", IsEnabled: true},

		// IBAN — 2-letter country + 2 check digits + up to 30 alphanumeric BBAN
		// e.g. DE89 3704 0044 0532 0130 00
		{Name: "IBAN", Pattern: `\b[A-Z]{2}\d{2}[\s\-]?[\dA-Z]{4}[\s\-]?(?:[\dA-Z]{4}[\s\-]?){1,7}[\dA-Z]{1,4}\b`, Replacement: "[REDACTED_IBAN]", IsEnabled: true},

		// Credit card — 13–16 digits, optional spaces/dashes/dots between groups
		// e.g. 4111 1111 1111 1111 | 4111-1111-1111-1111 | 4111111111111111
		{Name: "CREDIT_CARD", Pattern: `\b(?:\d[\s\-\.]*?){13,16}\b`, Replacement: "[REDACTED_CC]", IsEnabled: true},

		// ─── Identity / PII (most specific first) ────────────────────────────
		// Email: user.name+tag@sub.domain.com
		{Name: "EMAIL", Pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, Replacement: "[REDACTED_EMAIL]", IsEnabled: true},

		// MAC address — six hex pairs separated by : or -
		// e.g. 00:1A:2B:3C:4D:5E | 00-1A-2B-3C-4D-5E
		{Name: "MAC_ADDRESS", Pattern: `\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b`, Replacement: "[REDACTED_MAC]", IsEnabled: true},

		// IPv4 — four octets (0–255) separated by dots
		// e.g. 192.168.1.1
		{Name: "IPV4", Pattern: `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`, Replacement: "[REDACTED_IP]", IsEnabled: true},

		// Date of birth — MM/DD/YYYY and common delimiter variations
		// e.g. 01/15/1990 | 01-15-1990 | 01.15.1990
		{Name: "DATE_OF_BIRTH", Pattern: `\b(?:0[1-9]|1[0-2])[\s/\-\.](0[1-9]|[12]\d|3[01])[\s/\-\.](19|20)\d{2}\b`, Replacement: "[REDACTED_DOB]", IsEnabled: true},

		// US Passport — 1 uppercase letter + 8 digits: C03005988
		{Name: "US_PASSPORT", Pattern: `\b[A-Z]\d{8}\b`, Replacement: "[REDACTED_PASSPORT]", IsEnabled: true},

		// Phone numbers — three sub-patterns via alternation:
		//   1) Separator-based intl/US: +1 (555) 123-4567 | +90 532 123 45 67
		//   2) Compact international:   +905321234567
		//   3) Turkish local:           0532 123 45 67 | 05321234567
		// NOTE: must run BEFORE SSN — SSN pattern can consume digit groups inside phone numbers
		{Name: "PHONE", Pattern: `\b(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{1,4}\)?[\s\-]?)?\d{2,4}[\s\-]\d{3,4}[\s\-]\d{3,4}\b|\b\+\d{1,3}[\s\-]?\d{6,14}\b|\b0\d{3}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`, Replacement: "[REDACTED_PHONE]", IsEnabled: true},

		// US SSN — 3-2-4 digit format: 123-45-6789 | 123 45 6789 | 123456789
		{Name: "SSN", Pattern: `\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b`, Replacement: "[REDACTED_SSN]", IsEnabled: true},
	}
}
