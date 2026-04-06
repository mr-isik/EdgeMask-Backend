package services

import (
	"regexp"
	"strings"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// piiPattern holds a pre-compiled regex, its replacement token, and a
// human-readable category name used for logging (e.g. "CREDIT_CARD").
type piiPattern struct {
	regex       *regexp.Regexp
	replacement string
	name        string // Category name written to request_logs.scrubbed_items
}

// scrubbingService implements domain.ScrubbingService with pre-compiled regex patterns.
type scrubbingService struct {
	patterns []piiPattern
}

// NewScrubbingService creates a new ScrubbingService with all regex patterns
// compiled once at construction time. This avoids re-compilation per request,
// which is critical for sub-millisecond performance.
func NewScrubbingService() domain.ScrubbingService {
	return &scrubbingService{
		patterns: []piiPattern{
			{
				// Emails — matched first to prevent partial matches by other patterns
				regex:       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
				replacement: "[REDACTED_EMAIL]",
				name:        "EMAIL",
			},
			{
				// Credit Card Numbers — 13 to 16 digits, optionally separated by spaces or dashes
				regex:       regexp.MustCompile(`\b(?:\d[ \-]*?){13,16}\b`),
				replacement: "[REDACTED_CARD]",
				name:        "CREDIT_CARD",
			},
			{
				// SSN / Turkish TC Kimlik No — 9 to 11 consecutive digits
				regex:       regexp.MustCompile(`\b\d{3}[\- ]?\d{2,3}[\- ]?\d{4}\b`),
				replacement: "[REDACTED_ID]",
				name:        "SSN",
			},
			{
				// Phone Numbers — international format with optional country code
				regex:       regexp.MustCompile(`(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}`),
				replacement: "[REDACTED_PHONE]",
				name:        "PHONE",
			},
		},
	}
}

// Redact replaces all detected PII in the input text with their corresponding
// replacement tokens. Returns a ScrubbingResult with redacted text, count, and
// the unique set of PII category names that were found.
func (s *scrubbingService) Redact(text string) domain.ScrubbingResult {
	totalRedacted := 0
	seen := make(map[string]struct{})
	var types []string

	for _, p := range s.patterns {
		matches := p.regex.FindAllStringIndex(text, -1)
		if len(matches) > 0 {
			totalRedacted += len(matches)
			text = p.regex.ReplaceAllString(text, p.replacement)

			upper := strings.ToUpper(p.name)
			if _, ok := seen[upper]; !ok {
				seen[upper] = struct{}{}
				types = append(types, upper)
			}
		}
	}

	return domain.ScrubbingResult{
		RedactedText:  text,
		Count:         totalRedacted,
		ScrubbedTypes: types,
	}
}

