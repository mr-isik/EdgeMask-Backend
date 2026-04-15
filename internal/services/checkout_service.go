package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

type checkoutService struct {
	apiKey      string
	baseURL     string
	billingRepo domain.UserBillingRepository
	httpClient  *http.Client
}

func NewCheckoutService(apiKey string, baseURL string, billingRepo domain.UserBillingRepository) domain.CheckoutService {
	return &checkoutService{
		apiKey:      apiKey,
		baseURL:     strings.TrimRight(baseURL, "/"),
		billingRepo: billingRepo,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

type dodoCheckoutRequest struct {
	ProductCart []dodoCheckoutProduct `json:"product_cart"`
	ReturnURL   string                `json:"return_url,omitempty"`
	CancelURL   string                `json:"cancel_url,omitempty"`
	Customer    map[string]string     `json:"customer,omitempty"`
	Metadata    map[string]string     `json:"metadata,omitempty"`
}

type dodoCheckoutProduct struct {
	ProductID string `json:"product_id"`
	Quantity  int    `json:"quantity"`
}

type dodoCheckoutResponse struct {
	SessionID   string `json:"session_id"`
	CheckoutURL string `json:"checkout_url"`
}

type dodoPortalSessionResponse struct {
	Link string `json:"link"`
}

func (s *checkoutService) CreateSession(ctx context.Context, req domain.CheckoutSessionRequest) (*domain.CheckoutSessionResponse, error) {
	if strings.TrimSpace(s.apiKey) == "" {
		return nil, fmt.Errorf("dodo api key is required")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return nil, fmt.Errorf("user id is required")
	}
	if strings.TrimSpace(req.ProductID) == "" {
		return nil, fmt.Errorf("product_id is required")
	}
	if req.Quantity <= 0 {
		req.Quantity = 1
	}

	payload := dodoCheckoutRequest{
		ProductCart: []dodoCheckoutProduct{
			{ProductID: req.ProductID, Quantity: req.Quantity},
		},
		ReturnURL: req.ReturnURL,
		CancelURL: req.CancelURL,
		Metadata: map[string]string{
			"user_id": req.UserID,
		},
	}

	customerID, err := s.billingRepo.GetDodoCustomerID(ctx, req.UserID)
	if err == nil && strings.TrimSpace(customerID) != "" {
		payload.Customer = map[string]string{"customer_id": customerID}
	} else {
		if err != nil && err != domain.ErrBillingMappingNotFound {
			return nil, fmt.Errorf("failed to resolve dodo customer mapping: %w", err)
		}
		if strings.TrimSpace(req.CustomerEmail) == "" {
			return nil, fmt.Errorf("customer_email is required when no dodo_customer_id mapping exists")
		}
		payload.Customer = map[string]string{
			"email": req.CustomerEmail,
		}
		if strings.TrimSpace(req.CustomerName) != "" {
			payload.Customer["name"] = req.CustomerName
		}
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode checkout payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/checkouts", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create checkout request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call dodo checkout api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dodo checkout api returned status %d", resp.StatusCode)
	}

	var out dodoCheckoutResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode checkout response: %w", err)
	}

	return &domain.CheckoutSessionResponse{
		SessionID:   out.SessionID,
		CheckoutURL: out.CheckoutURL,
	}, nil
}

func (s *checkoutService) CreateCustomerPortalSession(ctx context.Context, req domain.CustomerPortalSessionRequest) (*domain.CustomerPortalSessionResponse, error) {
	if strings.TrimSpace(s.apiKey) == "" {
		return nil, fmt.Errorf("dodo api key is required")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return nil, fmt.Errorf("user id is required")
	}

	customerID, err := s.billingRepo.GetDodoCustomerID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dodo customer mapping: %w", err)
	}
	if strings.TrimSpace(customerID) == "" {
		return nil, domain.ErrBillingMappingNotFound
	}

	query := url.Values{}
	if req.SendEmail {
		query.Set("send_email", "true")
	}
	if strings.TrimSpace(req.ReturnURL) != "" {
		query.Set("return_url", req.ReturnURL)
	}

	endpoint := fmt.Sprintf("%s/customers/%s/customer-portal/session", s.baseURL, customerID)
	if encoded := query.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create customer portal request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call dodo customer portal api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("dodo customer portal api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var out dodoPortalSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode customer portal response: %w", err)
	}
	if strings.TrimSpace(out.Link) == "" {
		return nil, fmt.Errorf("customer portal response did not include link")
	}

	return &domain.CustomerPortalSessionResponse{Link: out.Link}, nil
}
