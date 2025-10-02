package cloudflareoriginca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultCertificateAPIBaseURL = "https://api.cloudflare.com/client/v4/certificates"
)

// Client handles communication with the Cloudflare Origin CA API
type Client struct {
	serviceKey string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Cloudflare Origin CA API client
func NewClient(serviceKey string, options ...ClientOption) *Client {
	c := &Client{
		serviceKey: serviceKey,
		baseURL:    DefaultCertificateAPIBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

// ClientOption allows customization of the Client
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL for the API
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

type cloudflareRequest struct {
	CSR               string   `json:"csr"`
	Hostnames         []string `json:"hostnames"`
	RequestType       string   `json:"request_type"`
	RequestedValidity int      `json:"requested_validity,omitempty"`
}

type cloudflareResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		ID          string `json:"id"`
		Certificate string `json:"certificate"`
		ExpiresOn   string `json:"expires_on"`
	} `json:"result"`
}

type cloudflareRevokeResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		ID        string `json:"id"`
		RevokedAt string `json:"revoked_at"`
	} `json:"result"`
}

// RequestCertificate requests a new certificate from Cloudflare Origin CA
func (c *Client) RequestCertificate(ctx context.Context, csr string, hostnames []string, requestType string, requestedValidity int) (string, string, error) {
	reqBody := cloudflareRequest{
		CSR:         csr,
		Hostnames:   hostnames,
		RequestType: requestType,
	}

	// Only include requested validity if explicitly configured
	if requestedValidity > 0 {
		reqBody.RequestedValidity = requestedValidity
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-User-Service-Key", c.serviceKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	var cfResp cloudflareResponse
	if err := json.Unmarshal(body, &cfResp); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %w", err)
	}

	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			return "", "", fmt.Errorf("cloudflare API error: %s", cfResp.Errors[0].Message)
		}
		return "", "", fmt.Errorf("cloudflare API request failed")
	}

	return cfResp.Result.Certificate, cfResp.Result.ID, nil
}

// RevokeResult contains information about a revoked certificate
type RevokeResult struct {
	AlreadyRevoked bool
	NotFound       bool
	RevokedAt      string
}

// RevokeCertificate revokes a certificate by its ID
func (c *Client) RevokeCertificate(ctx context.Context, certID string) (*RevokeResult, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("%s/%s", c.baseURL, certID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-User-Service-Key", c.serviceKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var cfResp cloudflareRevokeResponse
	if err := json.Unmarshal(body, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse revocation response: %w", err)
	}

	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			// Handle specific error codes
			for _, e := range cfResp.Errors {
				switch e.Code {
				case 1014: // Certificate already revoked
					return &RevokeResult{AlreadyRevoked: true}, nil
				case 1101: // Failed to read certificate from Database
					return &RevokeResult{NotFound: true}, nil
				}
			}
			// For any other error, return it
			return nil, fmt.Errorf("revocation failed: %s (code: %d)", cfResp.Errors[0].Message, cfResp.Errors[0].Code)
		}
		return nil, fmt.Errorf("revocation failed with status %d", resp.StatusCode)
	}

	return &RevokeResult{
		RevokedAt: cfResp.Result.RevokedAt,
	}, nil
}
