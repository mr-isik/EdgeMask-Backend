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

// NewScrubbingService creates a new ScrubbingService with all 15 regex patterns
// compiled once at construction time. This avoids re-compilation per request,
// which is critical for sub-millisecond performance.
//
// Pattern ordering is critical — longer / more specific patterns (JWTs, secrets)
// must be matched BEFORE shorter generic ones (SSN, credit cards) to prevent
// partial false-positive matches.
func NewScrubbingService() domain.ScrubbingService {
	return &scrubbingService{
		patterns: []piiPattern{

			// ═══════════════════════════════════════════════════════════
			//  SECRETS — match first (long tokens, specific prefixes)
			// ═══════════════════════════════════════════════════════════

			{
				// JWT — three base64url segments separated by dots
				// eyJhbGciOiJIUz...  (header.payload.signature)
				regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}`),
				replacement: "[REDACTED_JWT]",
				name:        "JWT",
			},
			{
				// AWS Access Key ID — always starts with AKIA (long-term) or ASIA (STS)
				// AKIAIOSFODNN7EXAMPLE
				regex:       regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
				replacement: "[REDACTED_AWS_KEY]",
				name:        "AWS_KEY",
			},
			{
				// GitHub Personal/OAuth/App tokens — ghp_, gho_, ghu_, ghs_, ghr_
				// ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (36+ chars)
				regex:       regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`),
				replacement: "[REDACTED_GITHUB_TOKEN]",
				name:        "GITHUB_TOKEN",
			},
			{
				// Stripe Secret/Restricted Keys — sk_live_*, sk_test_*, rk_live_*, rk_test_*
				regex:       regexp.MustCompile(`[sr]k_(?:live|test)_[A-Za-z0-9]{20,}`),
				replacement: "[REDACTED_STRIPE_KEY]",
				name:        "STRIPE_SECRET",
			},
			{
				// Slack Bot/User/App tokens — xoxb-*, xoxp-*, xoxa-*, xoxo-*
				regex:       regexp.MustCompile(`xo(?:xb|xp|xa|xo)-[0-9A-Za-z\-]{20,}`),
				replacement: "[REDACTED_SLACK_TOKEN]",
				name:        "SLACK_TOKEN",
			},

			// ═══════════════════════════════════════════════════════════
			//  FINANCIAL — match before generic digit patterns
			// ═══════════════════════════════════════════════════════════

			{
				// Ethereum Wallet Address — 0x followed by 40 hex chars
				// 0x32Be343B94f860124dC4fEe278FDCBD38C102D88
				regex:       regexp.MustCompile(`\b0x[0-9a-fA-F]{40}\b`),
				replacement: "[REDACTED_ETH]",
				name:        "ETH_WALLET",
			},
			{
				// IBAN — Country code (2 letters) + check digits (2) + BBAN (up to 30 alphanumeric)
				// Supports: DE89 3704 0044 0532 0130 00  or  DE89370400440532013000  or  DE89-3704-0044-...
				regex:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[\s\-]?[\dA-Z]{4}[\s\-]?(?:[\dA-Z]{4}[\s\-]?){1,7}[\dA-Z]{1,4}\b`),
				replacement: "[REDACTED_IBAN]",
				name:        "IBAN",
			},
			{
				// Credit Card Numbers — 13 to 16 digits, allowing spaces, dashes, or dots between groups
				// 4111 1111 1111 1111 | 4111-1111-1111-1111 | 4111111111111111
				regex:       regexp.MustCompile(`\b(?:\d[\s\-\.]*?){13,16}\b`),
				replacement: "[REDACTED_CC]",
				name:        "CREDIT_CARD",
			},

			// ═══════════════════════════════════════════════════════════
			//  IDENTITY (PII) — most specific first
			// ═══════════════════════════════════════════════════════════

			{
				// Email addresses — standard RFC 5321-ish pattern
				// user.name+tag@sub.domain.com
				regex:       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
				replacement: "[REDACTED_EMAIL]",
				name:        "EMAIL",
			},
			{
				// MAC Address — six groups of two hex digits separated by colons or dashes
				// 00:1A:2B:3C:4D:5E | 00-1A-2B-3C-4D-5E
				regex:       regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b`),
				replacement: "[REDACTED_MAC]",
				name:        "MAC_ADDRESS",
			},
			{
				// IPv4 Address — four octets (0-255) separated by dots
				// 192.168.1.1 | 10.0.0.1
				regex:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
				replacement: "[REDACTED_IP]",
				name:        "IPV4",
			},
			{
				// Date of Birth — MM/DD/YYYY and common variations
				// 01/15/1990 | 01-15-1990 | 01.15.1990 | 01 15 1990
				regex:       regexp.MustCompile(`\b(?:0[1-9]|1[0-2])[\s/\-\.](0[1-9]|[12]\d|3[01])[\s/\-\.](19|20)\d{2}\b`),
				replacement: "[REDACTED_DOB]",
				name:        "DATE_OF_BIRTH",
			},
			{
				// US Passport Number — 1 uppercase letter followed by 8 digits
				// C03005988
				regex:       regexp.MustCompile(`\b[A-Z]\d{8}\b`),
				replacement: "[REDACTED_PASSPORT]",
				name:        "US_PASSPORT",
			},
			{
				// US SSN — 3-2-4 digit format with flexible separators
				// 123-45-6789 | 123 45 6789 | 123456789
				regex:       regexp.MustCompile(`\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b`),
				replacement: "[REDACTED_SSN]",
				name:        "SSN",
			},
			{
				// International Phone Numbers — very flexible format
				// +1 (555) 123-4567 | +44 20 7946 0958 | +90 532 123 4567 | (555) 123-4567
				regex:       regexp.MustCompile(`(?:\+\d{1,3}[\s\-]?)?(?:\(?\d{1,4}\)?[\s\-]?)?\d{2,4}[\s\-]?\d{3,4}[\s\-]?\d{3,4}`),
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


