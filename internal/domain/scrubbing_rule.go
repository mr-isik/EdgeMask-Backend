package domain

// ScrubbingRule defines a PII detection pattern and its replacement.
type ScrubbingRule struct {
	ID          string `json:"id" db:"id"`
	Name        string `json:"name" db:"name"`               // e.g., "credit_card", "email", "ssn"
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

// DefaultScrubbingRules returns the built-in PII detection rules.
func DefaultScrubbingRules() []ScrubbingRule {
	return []ScrubbingRule{
		{
			Name:        "credit_card",
			Pattern:     `\b(?:\d[ -]*?){13,19}\b`,
			Replacement: "[REDACTED_CC]",
			IsEnabled:   true,
		},
		{
			Name:        "email",
			Pattern:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Replacement: "[REDACTED_EMAIL]",
			IsEnabled:   true,
		},
		{
			Name:        "ssn",
			Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
			Replacement: "[REDACTED_SSN]",
			IsEnabled:   true,
		},
		{
			Name:        "phone",
			Pattern:     `\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b`,
			Replacement: "[REDACTED_PHONE]",
			IsEnabled:   true,
		},
	}
}
