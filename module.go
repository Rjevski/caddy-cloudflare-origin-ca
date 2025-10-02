package cloudflareoriginca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// according to the API error message:
// "Permitted values for the 'requested_validity' parameter (specified in days) are:
// 7, 30, 90, 365, 730, 1095, and 5475 (default)"
var allowedValidityPeriods = []int{7, 30, 90, 365, 730, 1095, 5475}

// maps our cert types to Cloudflare API cert types
var requestTypeMap = map[x509.PublicKeyAlgorithm]string{
	x509.RSA:   "origin-rsa",
	x509.ECDSA: "origin-ecc",
}

func init() {
	caddy.RegisterModule(CloudflareOriginCA{})
}

type CloudflareOriginCA struct {
	// Cloudflare Origin CA service key, a type of token
	// only allowed to manage certificates for a given zone
	ServiceKey string `json:"service_key,omitempty"`

	// RequestedValidity is the duration for certificate validity (optional, max 15 years)
	// If not specified, lets Cloudflare pick a default (currently 15 years)
	RequestedValidity int `json:"requested_validity,omitempty"`

	// BaseURL allows overriding the API endpoint (optional, for testing)
	BaseURL string `json:"base_url,omitempty"`

	logger *zap.Logger
	client *Client
}

func (CloudflareOriginCA) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.cloudflare_origin_ca",
		New: func() caddy.Module { return new(CloudflareOriginCA) },
	}
}

func (c *CloudflareOriginCA) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger(c)

	// Validate config
	if c.ServiceKey == "" {
		return fmt.Errorf("cloudflare service_key is required")
	}

	if c.RequestedValidity != 0 && !slices.Contains(allowedValidityPeriods, c.RequestedValidity) {
		return fmt.Errorf("validity_days must be one of: %v", allowedValidityPeriods)
	}

	// Initialize the client with options
	var opts []ClientOption
	if c.BaseURL != "" {
		opts = append(opts, WithBaseURL(c.BaseURL))
	}

	c.client = NewClient(c.ServiceKey, opts...)

	return nil
}

func (c *CloudflareOriginCA) IssuerKey() string {
	// TODO: somehow infer the account ID from the service key
	//  and make the account ID part of this, since certs are
	//  only equivalent within the same account.
	return "cloudflare_origin_ca"
}

// PreCheck checks to reject names that are not supported by Cloudflare
// note: it's likely wildcard names like these are a side effect of an incorrect Caddy config
func (c *CloudflareOriginCA) PreCheck(_ context.Context, names []string, _ bool) error {
	for _, domain := range names {
		// Skip bare wildcards and empty domains
		if domain == "*" || domain == "" {
			return fmt.Errorf("invalid domain: %s", domain)
		}
		// Skip domains that start with *. but don't have a domain after (like "*.")
		if strings.HasPrefix(domain, "*.") && len(domain) <= 2 {
			return fmt.Errorf("skipping invalid wildcard: %s", domain)
		}
	}
	return nil
}

func (c *CloudflareOriginCA) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	c.logger.Info("issuing certificate", zap.Strings("names", csr.DNSNames))

	// Determine request type based on the CSR's public key algorithm
	requestType, ok := requestTypeMap[csr.PublicKeyAlgorithm]
	if !ok {
		return nil, certmagic.ErrNoRetry{Err: fmt.Errorf("unsupported public key algorithm: %s (only RSA and ECDSA are supported)", csr.PublicKeyAlgorithm)}
	}

	// Encode the provided CSR to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	cert, certID, err := c.client.RequestCertificate(ctx, string(csrPEM), csr.DNSNames, requestType, c.RequestedValidity)
	if err != nil {
		return nil, fmt.Errorf("requesting certificate: %w", err)
	}

	c.logger.Debug("certificate issued successfully", zap.String("id", certID))

	return &certmagic.IssuedCertificate{
		Certificate: []byte(cert),
		// certificate ID is just the serial number, so no need to persist it out of band
		Metadata: nil,
	}, nil
}

func (c *CloudflareOriginCA) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	certPEM := cert.CertificatePEM
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	certID := parsedCert.SerialNumber.String()

	c.logger.Info("revoking certificate", zap.String("id", certID))

	result, err := c.client.RevokeCertificate(ctx, certID)
	if err != nil {
		return err
	}

	if result.AlreadyRevoked {
		c.logger.Info("certificate already revoked", zap.String("id", certID))
	} else if result.NotFound {
		c.logger.Warn("certificate not found in database, treating as already revoked", zap.String("id", certID))
	} else {
		c.logger.Info("certificate revoked successfully",
			zap.String("id", certID),
			zap.String("revoked_at", result.RevokedAt))
	}

	return nil
}

func (c *CloudflareOriginCA) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "service_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				c.ServiceKey = d.Val()
			case "validity":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var days int
				if _, err := fmt.Sscan(d.Val(), &days); err != nil {
					return d.Errf("invalid validity_days: %v", err)
				}
				c.RequestedValidity = days
			default:
				return d.Errf("unrecognized option: %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ certmagic.Issuer      = (*CloudflareOriginCA)(nil)
	_ certmagic.Revoker     = (*CloudflareOriginCA)(nil)
	_ certmagic.PreChecker  = (*CloudflareOriginCA)(nil)
	_ caddy.Provisioner     = (*CloudflareOriginCA)(nil)
	_ caddyfile.Unmarshaler = (*CloudflareOriginCA)(nil)
)
