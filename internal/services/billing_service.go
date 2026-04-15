package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

type billingService struct {
	enabled     bool
	apiKey      string
	baseURL     string
	eventName   string
	httpClient  *http.Client
	billingRepo domain.UserBillingRepository
}

func NewBillingService(
	enabled bool,
	apiKey string,
	baseURL string,
	eventName string,
	billingRepo domain.UserBillingRepository,
) domain.BillingService {
	return &billingService{
		enabled:   enabled,
		apiKey:    apiKey,
		baseURL:   strings.TrimRight(baseURL, "/"),
		eventName: eventName,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		billingRepo: billingRepo,
	}
}

type dodoIngestRequest struct {
	Events []dodoUsageEvent `json:"events"`
}

type dodoUsageEvent struct {
	EventID    string                 `json:"event_id"`
	CustomerID string                 `json:"customer_id"`
	EventName  string                 `json:"event_name"`
	Timestamp  string                 `json:"timestamp,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

func (s *billingService) RecordUsage(ctx context.Context, event domain.UsageEvent) error {
	if !s.enabled {
		return nil
	}
	if strings.TrimSpace(s.apiKey) == "" {
		return fmt.Errorf("dodo payments is enabled but api key is missing")
	}
	if strings.TrimSpace(event.UserID) == "" {
		return fmt.Errorf("missing user id for billing usage event")
	}

	customerID, err := s.billingRepo.GetDodoCustomerID(ctx, event.UserID)
	if err != nil {
		if err == domain.ErrBillingMappingNotFound {
			return nil
		}
		return err
	}

	eventID := fmt.Sprintf(
		"usage_%s_%s_%d_%d",
		event.UserID,
		event.Provider,
		time.Now().UnixNano(),
		event.TokensProcessed,
	)

	payload := dodoIngestRequest{
		Events: []dodoUsageEvent{
			{
				EventID:    eventID,
				CustomerID: customerID,
				EventName:  s.eventName,
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Metadata: map[string]interface{}{
					"user_id":            event.UserID,
					"provider":           event.Provider,
					"model":              event.Model,
					"tokens_processed":   event.TokensProcessed,
					"status_code":        event.StatusCode,
					"latency_ms":         event.LatencyMs,
					"semantic_cache_hit": event.SemanticCacheHit,
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal dodo usage payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/events/ingest", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create dodo usage request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send dodo usage event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Dodo usage ingest non-success status: ", resp.StatusCode)
		return fmt.Errorf("dodo usage ingest failed with status %d", resp.StatusCode)
	}

	return nil
}
