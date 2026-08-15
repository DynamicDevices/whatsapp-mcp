package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLeaseTestStore(t *testing.T, path, jid, token, heartbeat string, pid int) {
	t.Helper()
	body := fmt.Sprintf(`{
	  "version": 2,
	  "leases": {
	    %q: {
	      "owner_token": %q,
	      "pid": %d,
	      "host": %q,
	      "claimed_at": %q,
	      "heartbeat_at": %q,
	      "expires_at": %q
	    }
	  }
	}`, jid, token, pid, localHostname(), heartbeat, heartbeat, time.Now().UTC().Add(12*time.Hour).Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLeasePolicyRequiresExactOwnerToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	jid := "120363430911014713@g.us"
	token := "owner-capability-token"
	writeLeaseTestStore(t, path, jid, token, time.Now().UTC().Format(time.RFC3339), os.Getpid())
	t.Setenv("BRIAR_LEASES_PATH", path)
	p := loadLeasePolicy()

	if d := p.check(jid, ""); d.Allow || d.Reason != "chat_lease_owner_token_required" {
		t.Fatalf("missing token: %+v", d)
	}
	if d := p.check(jid, "wrong"); d.Allow || d.Reason != "chat_lease_owner_token_required" {
		t.Fatalf("wrong token: %+v", d)
	}
	if d := p.check(jid, token); !d.Allow || d.Reason != "lease_owner" {
		t.Fatalf("owner token: %+v", d)
	}
}

func TestLeasePolicyStaleAndUnleasedAllow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	jid := "120363430911014713@g.us"
	old := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	writeLeaseTestStore(t, path, jid, "token", old, 999999)
	t.Setenv("BRIAR_LEASES_PATH", path)
	p := loadLeasePolicy()

	if d := p.check(jid, ""); !d.Allow || d.Reason != "stale_lease" {
		t.Fatalf("stale lease: %+v", d)
	}
	if d := p.check("120363499999999999@g.us", ""); !d.Allow || d.Reason != "unleased" {
		t.Fatalf("unleased: %+v", d)
	}
}

func TestLeasePolicyFailsClosedOnCorruptionAndExemptsAlex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	if err := os.WriteFile(path, []byte(`{"leases":`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BRIAR_LEASES_PATH", path)
	p := loadLeasePolicy()
	if d := p.check("120363430911014713@g.us", ""); d.Allow || d.Reason != "lease_policy_unavailable" {
		t.Fatalf("corrupt store: %+v", d)
	}
	if d := p.check("447478346120@s.whatsapp.net", ""); !d.Allow || d.Reason != "alex_carveout" {
		t.Fatalf("Alex carve-out: %+v", d)
	}
}
