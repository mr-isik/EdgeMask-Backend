package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// VerifyDodoWebhook verifies Dodo standard webhook headers and payload.
func VerifyDodoWebhook(secret string, webhookID string, webhookTimestamp string, webhookSignature string, rawBody []byte, tolerance time.Duration) error {
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("missing dodo webhook secret")
	}
	if strings.TrimSpace(webhookID) == "" || strings.TrimSpace(webhookTimestamp) == "" || strings.TrimSpace(webhookSignature) == "" {
		return fmt.Errorf("missing required webhook signature headers")
	}

	ts, err := parseWebhookTimestamp(webhookTimestamp)
	if err != nil {
		return fmt.Errorf("invalid webhook timestamp: %w", err)
	}
	if tolerance > 0 {
		now := time.Now().UTC()
		if ts.Before(now.Add(-tolerance)) || ts.After(now.Add(tolerance)) {
			return fmt.Errorf("webhook timestamp outside tolerance")
		}
	}

	signed := webhookID + "." + webhookTimestamp + "." + string(rawBody)
	key, err := decodeWebhookSecret(secret)
	if err != nil {
		return fmt.Errorf("invalid dodo webhook secret: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signed))
	sum := mac.Sum(nil)

	expectedBase64 := base64.StdEncoding.EncodeToString(sum)
	expectedHex := hex.EncodeToString(sum)

	candidates := extractSignatureCandidates(webhookSignature)
	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expectedBase64)) == 1 {
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(expectedHex)) == 1 {
			return nil
		}
	}

	return fmt.Errorf("invalid webhook signature")
}

func parseWebhookTimestamp(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if unixSec, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return time.Unix(unixSec, 0).UTC(), nil
	}
	return time.Parse(time.RFC3339, trimmed)
}

func extractSignatureCandidates(header string) []string {
	var out []string
	fields := strings.Fields(strings.TrimSpace(header))
	for _, field := range fields {
		parts := strings.Split(field, ",")
		if len(parts) == 1 {
			out = append(out, strings.TrimSpace(parts[0]))
			continue
		}
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// Svix format is usually: "v1,<base64_signature>"
			if p == "v1" {
				continue
			}
			if strings.HasPrefix(p, "v1=") {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(p, "v1=")))
				continue
			}
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = append(out, strings.TrimSpace(header))
	}
	return out
}

func decodeWebhookSecret(secret string) ([]byte, error) {
	trimmed := strings.TrimSpace(secret)
	if strings.HasPrefix(trimmed, "whsec_") {
		encoded := strings.TrimPrefix(trimmed, "whsec_")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return []byte(trimmed), nil
}
