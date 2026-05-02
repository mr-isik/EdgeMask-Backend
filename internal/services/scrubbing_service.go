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

// NewScrubbingService creates a ScrubbingService by compiling all patterns from
// domain.DefaultScrubbingRules() once at construction time. This avoids
// re-compilation per request, which is critical for sub-millisecond performance.
//
// Only enabled rules are compiled. Rule ordering (defined in domain) is preserved —
// longer/more specific patterns (secrets, tokens) are matched before shorter/generic
// ones (SSN, credit cards) to prevent false positives.
func NewScrubbingService() domain.ScrubbingService {
	rules := domain.DefaultScrubbingRules()
	patterns := make([]piiPattern, 0, len(rules))

	for _, r := range rules {
		if !r.IsEnabled {
			continue
		}
		patterns = append(patterns, piiPattern{
			regex:       regexp.MustCompile(r.Pattern),
			replacement: r.Replacement,
			name:        r.Name,
		})
	}

	return &scrubbingService{patterns: patterns}
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
