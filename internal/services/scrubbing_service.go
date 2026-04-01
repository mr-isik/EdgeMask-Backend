package services

import (
	"regexp"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// piiPattern holds a pre-compiled regex and its replacement token.
type piiPattern struct {
	regex       *regexp.Regexp
	replacement string
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
			},
			{
				// Credit Card Numbers — 13 to 16 digits, optionally separated by spaces or dashes
				regex:       regexp.MustCompile(`\b(?:\d[ \-]*?){13,16}\b`),
				replacement: "[REDACTED_CARD]",
			},
			{
				// SSN / Turkish TC Kimlik No — 9 to 11 consecutive digits
				regex:       regexp.MustCompile(`\b\d{3}[\- ]?\d{2,3}[\- ]?\d{4}\b`),
				replacement: "[REDACTED_ID]",
			},
			{
				// Phone Numbers — international format with optional country code
				regex:       regexp.MustCompile(`(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}`),
				replacement: "[REDACTED_PHONE]",
			},
		},
	}
}

// Redact replaces all detected PII in the input text with their corresponding
// replacement tokens. Returns the redacted text and total count of items redacted.
func (s *scrubbingService) Redact(text string) (string, int) {
	totalRedacted := 0

	for _, p := range s.patterns {
		matches := p.regex.FindAllStringIndex(text, -1)
		totalRedacted += len(matches)

		if len(matches) > 0 {
			text = p.regex.ReplaceAllString(text, p.replacement)
		}
	}

	return text, totalRedacted
}
