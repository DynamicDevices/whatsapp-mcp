package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	defaultLeasePath  = "/home/ajlennon/.local/share/whatsapp-mcp/chat-leases.json"
	leaseHeartbeatTTL = 3 * time.Minute
)

type leaseStoreFile struct {
	Leases map[string]chatLease `json:"leases"`
}

type chatLease struct {
	OwnerToken  string `json:"owner_token"`
	PID         int    `json:"pid"`
	Host        string `json:"host"`
	ClaimedAt   string `json:"claimed_at"`
	HeartbeatAt string `json:"heartbeat_at"`
	ExpiresAt   string `json:"expires_at"`
}

type leaseDecision struct {
	Allow  bool
	Reason string
}

type LeasePolicy struct {
	path string
}

func loadLeasePolicy() *LeasePolicy {
	return &LeasePolicy{
		path: envOr("BRIAR_LEASES_PATH", defaultLeasePath),
	}
}

func localHostname() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.SplitN(host, ".", 2)[0]
}

func parseLeaseTime(raw string) (time.Time, bool) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	return t, err == nil
}

func leasePIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func leaseLive(lease chatLease, now time.Time) bool {
	if expires, ok := parseLeaseTime(lease.ExpiresAt); ok && expires.Before(now) {
		return false
	}
	heartbeatRaw := lease.HeartbeatAt
	if heartbeatRaw == "" {
		heartbeatRaw = lease.ClaimedAt
	}
	if heartbeat, ok := parseLeaseTime(heartbeatRaw); ok {
		if now.Sub(heartbeat) > leaseHeartbeatTTL {
			return false
		}
	}
	if lease.Host != "" && lease.Host != localHostname() {
		// v1 remote leases are conservative: live until expiry.
		return true
	}
	if lease.PID > 0 && !leasePIDAlive(lease.PID) {
		return false
	}
	return true
}

func secureTokenEqual(expected, supplied string) bool {
	if expected == "" || supplied == "" || len(expected) != len(supplied) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(supplied)) == 1
}

func isAlexRecipient(jid string) bool {
	user := strings.SplitN(normalizeJID(jid), "@", 2)[0]
	return user == "447478346120"
}

func (p *LeasePolicy) check(recipient, ownerToken string) leaseDecision {
	// Existing ops-alert carve-out: Alex self-DM is never blocked by a lease.
	if isAlexRecipient(recipient) {
		return leaseDecision{Allow: true, Reason: "alex_carveout"}
	}
	data, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return leaseDecision{Allow: true, Reason: "unleased"}
	}
	if err != nil {
		return leaseDecision{Allow: false, Reason: "lease_policy_unavailable"}
	}
	var store leaseStoreFile
	if err := json.Unmarshal(data, &store); err != nil {
		return leaseDecision{Allow: false, Reason: "lease_policy_unavailable"}
	}
	jid := normalizeJID(recipient)
	lease, ok := store.Leases[jid]
	if !ok {
		return leaseDecision{Allow: true, Reason: "unleased"}
	}
	if !leaseLive(lease, time.Now().UTC()) {
		return leaseDecision{Allow: true, Reason: "stale_lease"}
	}
	if !secureTokenEqual(lease.OwnerToken, ownerToken) {
		return leaseDecision{Allow: false, Reason: "chat_lease_owner_token_required"}
	}
	return leaseDecision{Allow: true, Reason: "lease_owner"}
}
