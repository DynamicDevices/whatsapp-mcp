package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeJID(t *testing.T) {
	if got := normalizeJID("447478346120"); got != "447478346120@s.whatsapp.net" {
		t.Fatalf("got %q", got)
	}
}

func TestSendPolicyDenyUnknownAndGroups(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	_ = os.WriteFile(al, []byte(`{
	  "admin":[{"jid":"447478346120@s.whatsapp.net","name":"Alex"}],
	  "family":[{"jid":"447948173289@s.whatsapp.net","name":"Dionne"}],
	  "friends":[],"work":[],"known":[],"tester":[],
	  "groups":[
	    {"jid":"120363427935538418@g.us","name":"Dionne / Briar chat","post_allowed":true},
	    {"jid":"120363430911014713@g.us","name":"Kettle Companion"}
	  ],
	  "rate_limit_seconds":{"friends":1,"admin":0,"family":0,"groups":0}
	}`), 0o600)
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "no-such-flag"))
	p := loadSendPolicy()

	d := p.check("999999999@s.whatsapp.net", "hi")
	if d.Allow || d.Reason != "recipient_not_in_allowlist" {
		t.Fatalf("unknown: %+v", d)
	}
	d = p.check("120363412221047647@g.us", "hi")
	if d.Allow || d.Reason != "group_not_observed" {
		t.Fatalf("group: %+v", d)
	}
	d = p.check("120363430911014713@g.us", "hi")
	if d.Allow || d.Reason != "group_post_not_allowed" {
		t.Fatalf("observed-only group: %+v", d)
	}
	d = p.check("120363427935538418@g.us", "hi")
	if !d.Allow || d.Tier != "groups" {
		t.Fatalf("allowlisted group: %+v", d)
	}
	d = p.check("447478346120@s.whatsapp.net", "hello")
	if !d.Allow || d.Tier != "admin" {
		t.Fatalf("admin: %+v", d)
	}
}

func TestSendPolicyLightCapAndRate(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	_ = os.WriteFile(al, []byte(`{
	  "admin":[],"family":[],
	  "friends":[{"jid":"447727653206@s.whatsapp.net","name":"Max"}],
	  "work":[],"known":[],"tester":[],"groups":[],
	  "rate_limit_seconds":{"friends":3600}
	}`), 0o600)
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_LIGHT_MAX_RUNES", "5")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "nope"))
	p := loadSendPolicy()

	long := "abcdef"
	d := p.check("447727653206@s.whatsapp.net", long)
	if d.Allow {
		t.Fatalf("expected light cap deny: %+v", d)
	}
	d = p.check("447727653206@s.whatsapp.net", "hi")
	if !d.Allow {
		t.Fatalf("short ok: %+v", d)
	}
	p.recordSuccess("447727653206@s.whatsapp.net")
	p.lastSend["447727653206@s.whatsapp.net"] = time.Now()
	d = p.check("447727653206@s.whatsapp.net", "hi")
	if d.Allow {
		t.Fatalf("expected rate limit: %+v", d)
	}
}

func TestSendDisabledFlag(t *testing.T) {
	dir := t.TempDir()
	flag := filepath.Join(dir, "SEND_DISABLED")
	_ = os.WriteFile(flag, []byte("1"), 0o600)
	t.Setenv("SEND_DISABLED_FLAG", flag)
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("BRIDGE_ALLOWLIST_PATH", filepath.Join(dir, "missing.json"))
	p := loadSendPolicy()
	d := p.check("447478346120@s.whatsapp.net", "x")
	if d.Allow || d.Reason != "SEND_DISABLED" {
		t.Fatalf("%+v", d)
	}
}

func TestGroupPostCannotBeEnabledByEnvironment(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	_ = os.WriteFile(al, []byte(`{
	  "admin":[],"family":[],"friends":[],"work":[],"known":[],"tester":[],
	  "groups":[{"jid":"120363430911014713@g.us","name":"Observed only"}]
	}`), 0o600)
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_ALLOW_GROUPS", "true")
	t.Setenv("SEND_POLICY_OFF", "true")
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "no-such-flag"))

	p := loadSendPolicy()
	d := p.check("120363430911014713@g.us", "must stay denied")
	if d.Allow || d.Reason != "group_post_not_allowed" {
		t.Fatalf("runtime env bypassed hard group lock: %+v", d)
	}
}

func TestGroupPostRevocationTakesEffectWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	writePolicy := func(allowed bool) {
		value := "false"
		if allowed {
			value = "true"
		}
		body := `{
		  "admin":[],"family":[],"friends":[],"work":[],"known":[],"tester":[],
		  "groups":[{"jid":"120363430911014713@g.us","name":"Test","post_allowed":` + value + `}]
		}`
		if err := os.WriteFile(al, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "no-such-flag"))
	writePolicy(true)
	p := loadSendPolicy()
	if d := p.check("120363430911014713@g.us", "first"); !d.Allow {
		t.Fatalf("expected explicit capability to allow: %+v", d)
	}
	writePolicy(false)
	if d := p.check("120363430911014713@g.us", "second"); d.Allow || d.Reason != "group_post_not_allowed" {
		t.Fatalf("revocation did not apply live: %+v", d)
	}
}
