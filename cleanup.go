package cloudflareoriginca

import (
	"context"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// issuedCerts is a process-global tracker for certificates issued during this
// Caddy process's lifetime. It allows us to revoke all outstanding certificates
// when the process exits gracefully, preventing orphaned certificates from
// accumulating in the Cloudflare account.
//
// This is intentionally process-global (not per-module-instance) because:
//  1. Config reloads create new module instances, but we want to track certs
//     across the entire process lifetime
//  2. The OnExit callback is registered once in init() and needs access to all
//     certificates issued by any instance
var issuedCerts = newIssuedCertTracker()

// issuedCertTracker tracks certificates issued during the process lifetime
// so they can be revoked on graceful shutdown.
type issuedCertTracker struct {
	mu      sync.Mutex
	entries map[*Client]*issuedCertEntry
}

type issuedCertEntry struct {
	ids    map[string]struct{}
	logger *zap.Logger
}

func newIssuedCertTracker() *issuedCertTracker {
	return &issuedCertTracker{
		entries: make(map[*Client]*issuedCertEntry),
	}
}

// track records a newly issued certificate for later cleanup.
func (t *issuedCertTracker) track(logger *zap.Logger, client *Client, certID string) {
	if client == nil || certID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := t.entries[client]
	if entry == nil {
		entry = &issuedCertEntry{
			ids: make(map[string]struct{}),
		}
		t.entries[client] = entry
	}

	entry.ids[certID] = struct{}{}
	if logger != nil {
		entry.logger = logger
	}
}

// forget removes a certificate from tracking (e.g., after explicit revocation).
func (t *issuedCertTracker) forget(client *Client, certID string) {
	if client == nil || certID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := t.entries[client]
	if entry == nil {
		return
	}

	delete(entry.ids, certID)
	if len(entry.ids) == 0 {
		delete(t.entries, client)
	}
}

// cleanup revokes all tracked certificates. Called during process exit.
func (t *issuedCertTracker) cleanup(ctx context.Context) {
	snapshot := t.snapshot()
	if len(snapshot) == 0 {
		return
	}

	for client, entry := range snapshot {
		logger := entry.logger
		if logger == nil {
			logger = caddy.Log()
		}

		for certID := range entry.ids {
			logger.Info("revoking certificate during process exit", zap.String("id", certID))

			result, err := client.RevokeCertificate(ctx, certID)
			if err != nil {
				logger.Error("failed to revoke certificate during process exit", zap.String("id", certID), zap.Error(err))
				continue
			}

			logRevocationResult(logger, certID, result)
		}
	}
}

// snapshot atomically retrieves and clears all tracked certificates.
// This ensures we don't attempt to revoke the same certificates twice.
func (t *issuedCertTracker) snapshot() map[*Client]*issuedCertEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.entries) == 0 {
		return nil
	}

	result := make(map[*Client]*issuedCertEntry, len(t.entries))
	for client, entry := range t.entries {
		idsCopy := make(map[string]struct{}, len(entry.ids))
		for id := range entry.ids {
			idsCopy[id] = struct{}{}
		}

		result[client] = &issuedCertEntry{
			ids:    idsCopy,
			logger: entry.logger,
		}
	}

	// Clear the tracker to prevent double-revocation
	t.entries = make(map[*Client]*issuedCertEntry)
	return result
}

func logRevocationResult(logger *zap.Logger, certID string, result *RevokeResult) {
	if result == nil {
		return
	}

	if logger == nil {
		logger = caddy.Log()
	}

	switch {
	case result.AlreadyRevoked:
		logger.Info("certificate already revoked", zap.String("id", certID))
	case result.NotFound:
		logger.Warn("certificate not found in database, treating as already revoked", zap.String("id", certID))
	default:
		logger.Info("certificate revoked successfully",
			zap.String("id", certID),
			zap.String("revoked_at", result.RevokedAt))
	}
}
