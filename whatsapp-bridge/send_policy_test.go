package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeJID(t *testing.T) {
	if got := normalizeJID("447478346120"); got != "447478346120@s.whatsapp.net" {
		t.Fatalf("got %q", got)
	}
}

func TestSendPolicyDenyUnknownAndGroups(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	groupAllowlist := filepath.Join(dir, "allowed-groups.json")
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
	_ = os.WriteFile(groupAllowlist, []byte(`{
	  "groups":["120363427935538418@g.us","120363430911014713@g.us"]
	}`), 0o600)
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "no-such-flag"))
	p := loadSendPolicy()
	p.groupAllowlistPath = groupAllowlist

	d := p.check("999999999@s.whatsapp.net", "hi")
	if d.Allow || d.Reason != hardRecipientDeny {
		t.Fatalf("unknown: %+v", d)
	}
	d = p.check("120363412221047647@g.us", "hi")
	if d.Allow || d.Reason != hardRecipientDeny {
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

func TestHardRecipientGateBlocksMichaelAndEveryOtherPersonalJID(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	_ = os.WriteFile(al, []byte(`{
	  "admin":[{"jid":"447478346120@s.whatsapp.net","name":"Alex"}],
	  "family":[{"jid":"447948173289@s.whatsapp.net","name":"Dionne"}],
	  "friends":[{"jid":"447727653206@s.whatsapp.net","name":"Max"}],
	  "work":[{"jid":"447970314781@s.whatsapp.net","name":"Michael"}],
	  "known":[],"tester":[],"groups":[]
	}`), 0o600)
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "nope"))
	p := loadSendPolicy()

	for _, jid := range []string{
		"447970314781@s.whatsapp.net",
		"447948173289@s.whatsapp.net",
		"447727653206@s.whatsapp.net",
		"123456789@lid",
	} {
		d := p.check(jid, "must never send")
		if d.Allow || d.Reason != hardRecipientDeny {
			t.Fatalf("%s was not hard-blocked: %+v", jid, d)
		}
	}
	if d := p.check("447478346120@s.whatsapp.net", "dry-run"); !d.Allow || d.Tier != "admin" {
		t.Fatalf("Alex DM should remain allowed: %+v", d)
	}
}

func TestHardRecipientGateGroupsFailClosed(t *testing.T) {
	dir := t.TempDir()
	jid := "120363430911014713@g.us"

	for name, contents := range map[string]*string{
		"missing":   nil,
		"malformed": ptrString(`{"groups":`),
		"empty":     ptrString(`{"groups":[]}`),
		"wrong":     ptrString(`{"groups":["120363999999999999@g.us"]}`),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if contents != nil {
				if err := os.WriteFile(path, []byte(*contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d := hardRecipientDecisionAt(jid, path)
			if d.Allow || d.Reason != hardRecipientDeny {
				t.Fatalf("group gate did not fail closed: %+v", d)
			}
		})
	}

	allowed := filepath.Join(dir, "allowed.json")
	if err := os.WriteFile(allowed, []byte(`{"groups":["120363430911014713@g.us"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := hardRecipientDecisionAt(jid, allowed); !d.Allow || d.Tier != "groups" {
		t.Fatalf("explicitly allowlisted group denied: %+v", d)
	}
}

func ptrString(value string) *string {
	return &value
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
	groupAllowlist := filepath.Join(dir, "allowed-groups.json")
	_ = os.WriteFile(al, []byte(`{
	  "admin":[],"family":[],"friends":[],"work":[],"known":[],"tester":[],
	  "groups":[{"jid":"120363430911014713@g.us","name":"Observed only"}]
	}`), 0o600)
	_ = os.WriteFile(groupAllowlist, []byte(`{"groups":["120363430911014713@g.us"]}`), 0o600)
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_ALLOW_GROUPS", "true")
	t.Setenv("SEND_POLICY_OFF", "true")
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "no-such-flag"))

	p := loadSendPolicy()
	p.groupAllowlistPath = groupAllowlist
	d := p.check("120363430911014713@g.us", "must stay denied")
	if d.Allow || d.Reason != "group_post_not_allowed" {
		t.Fatalf("runtime env bypassed hard group lock: %+v", d)
	}
}

func TestGroupPostRevocationTakesEffectWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	groupAllowlist := filepath.Join(dir, "allowed-groups.json")
	if err := os.WriteFile(groupAllowlist, []byte(`{"groups":["120363430911014713@g.us"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
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
	p.groupAllowlistPath = groupAllowlist
	if d := p.check("120363430911014713@g.us", "first"); !d.Allow {
		t.Fatalf("expected explicit capability to allow: %+v", d)
	}
	writePolicy(false)
	if d := p.check("120363430911014713@g.us", "second"); d.Allow || d.Reason != "group_post_not_allowed" {
		t.Fatalf("revocation did not apply live: %+v", d)
	}
}
