package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Outbound send policy (Track A): deny-by-default for unknown recipients,
// group deny unless explicitly enabled, light caps, per-tier rate limits,
// SEND_DISABLED kill switch. Never trust agent intent — enforce here.

const (
	defaultLightMaxRunes = 280
	// Live allowlist — outside git skill tree (briar-live-state-preserve).
	defaultAllowlistPath = "/home/ajlennon/.config/cursorpa/wake-allowlist.json"
	defaultDenyLogPath   = "/home/ajlennon/.local/share/briar/send-policy-denies.jsonl"
	defaultNotifyFlag    = "/home/ajlennon/.local/share/briar/send-policy-NOTIFY"
)

type wakeAllowlistFile struct {
	Admin   []allowEntry   `json:"admin"`
	Family  []allowEntry   `json:"family"`
	Friends []allowEntry   `json:"friends"`
	Work    []allowEntry   `json:"work"`
	Known   []allowEntry   `json:"known"`
	Tester  []allowEntry   `json:"tester"`
	Groups  []allowEntry   `json:"groups"`
	Rates   map[string]int `json:"rate_limit_seconds"`
}

type allowEntry struct {
	JID         string `json:"jid"`
	Name        string `json:"name"`
	PostAllowed bool   `json:"post_allowed"`
}

type SendPolicy struct {
	mu            sync.Mutex
	byJID         map[string]string // normalized jid -> tier
	groupPost     map[string]bool   // explicit outbound capability; inbound listing is insufficient
	rates         map[string]int
	lastSend      map[string]time.Time
	lightMax      int
	allowlistPath string
	denyLogPath   string
	notifyPath    string
	burstWindow   time.Duration
	burstCount    int
	burstHits     []time.Time
}

type policyDecision struct {
	Allow  bool
	Tier   string
	Reason string
}

func loadSendPolicy() *SendPolicy {
	p := &SendPolicy{
		byJID:         map[string]string{},
		groupPost:     map[string]bool{},
		rates:         map[string]int{},
		lastSend:      map[string]time.Time{},
		lightMax:      envInt("SEND_LIGHT_MAX_RUNES", defaultLightMaxRunes),
		allowlistPath: envOr("BRIDGE_ALLOWLIST_PATH", defaultAllowlistPath),
		denyLogPath:   envOr("SEND_DENY_LOG", defaultDenyLogPath),
		notifyPath:    envOr("SEND_NOTIFY_FLAG", defaultNotifyFlag),
		burstWindow:   time.Duration(envInt("SEND_BURST_WINDOW_SEC", 60)) * time.Second,
		burstCount:    envInt("SEND_BURST_DENIES", 5),
	}
	path := p.allowlistPath
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("send_policy: allowlist read %s: %v (deny-unknown still active)\n", path, err)
		return p
	}
	var wl wakeAllowlistFile
	if err := json.Unmarshal(data, &wl); err != nil {
		fmt.Printf("send_policy: allowlist parse: %v\n", err)
		return p
	}
	add := func(tier string, entries []allowEntry) {
		for _, e := range entries {
			j := normalizeJID(e.JID)
			if j != "" {
				p.byJID[j] = tier
			}
		}
	}
	add("admin", wl.Admin)
	add("family", wl.Family)
	add("friends", wl.Friends)
	add("work", wl.Work)
	add("known", wl.Known)
	add("tester", wl.Tester)
	for _, e := range wl.Groups {
		j := normalizeJID(e.JID)
		if j != "" {
			p.byJID[j] = "groups"
			p.groupPost[j] = e.PostAllowed
		}
	}
	if wl.Rates != nil {
		p.rates = wl.Rates
	}
	allowedGroups := 0
	for _, allowed := range p.groupPost {
		if allowed {
			allowedGroups++
		}
	}
	fmt.Printf(
		"send_policy: loaded %d JIDs from %s (group_post_allowed=%d/%d)\n",
		len(p.byJID), path, allowedGroups, len(p.groupPost),
	)
	return p
}

func (p *SendPolicy) liveGroupPostDecision(jid string) policyDecision {
	data, err := os.ReadFile(p.allowlistPath)
	if err != nil {
		return policyDecision{Allow: false, Tier: "groups", Reason: "group_policy_unavailable"}
	}
	var wl wakeAllowlistFile
	if err := json.Unmarshal(data, &wl); err != nil {
		return policyDecision{Allow: false, Tier: "groups", Reason: "group_policy_unavailable"}
	}
	for _, entry := range wl.Groups {
		if normalizeJID(entry.JID) != jid {
			continue
		}
		if !entry.PostAllowed {
			return policyDecision{Allow: false, Tier: "groups", Reason: "group_post_not_allowed"}
		}
		return policyDecision{Allow: true, Tier: "groups", Reason: "ok"}
	}
	return policyDecision{Allow: false, Tier: "groups", Reason: "group_not_observed"}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func normalizeJID(j string) string {
	j = strings.TrimSpace(strings.ToLower(j))
	if j == "" {
		return ""
	}
	if !strings.Contains(j, "@") {
		j = j + "@s.whatsapp.net"
	}
	return j
}

func sendDisabled() bool {
	if getEnvBool("SEND_DISABLED", false) {
		return true
	}
	flag := envOr("SEND_DISABLED_FLAG", "/home/ajlennon/.local/share/briar/SEND_DISABLED")
	if st, err := os.Stat(flag); err == nil && !st.IsDir() {
		return true
	}
	return false
}

func (p *SendPolicy) check(recipient, message string) policyDecision {
	if sendDisabled() {
		return policyDecision{Allow: false, Tier: "", Reason: "SEND_DISABLED"}
	}
	jid := normalizeJID(recipient)
	if jid == "" {
		return policyDecision{Allow: false, Reason: "empty_recipient"}
	}
	isGroup := strings.HasSuffix(jid, "@g.us")

	tier, ok := p.byJID[jid]
	if !ok {
		user := strings.Split(jid, "@")[0]
		for k, t := range p.byJID {
			if strings.Split(k, "@")[0] == user {
				tier, ok = t, true
				break
			}
		}
	}

	// Group observation and posting are separate capabilities. Merely listing
	// a group for inbound wake/monitoring never permits outbound interaction.
	// There is intentionally no environment-variable bypass for group posts.
	if isGroup {
		groupDecision := p.liveGroupPostDecision(jid)
		if !groupDecision.Allow {
			return groupDecision
		}
		tier = "groups"
	} else if !ok {
		return policyDecision{Allow: false, Tier: "unknown", Reason: "recipient_not_in_allowlist"}
	}

	if tier == "family" || tier == "friends" {
		if message != "" && utf8.RuneCountInString(message) > p.lightMax {
			return policyDecision{
				Allow:  false,
				Tier:   tier,
				Reason: fmt.Sprintf("light_cap_exceeded_max_%d_runes", p.lightMax),
			}
		}
	}

	sec := 0
	if p.rates != nil {
		sec = p.rates[tier]
	}
	if sec > 0 {
		p.mu.Lock()
		last := p.lastSend[jid]
		p.mu.Unlock()
		if !last.IsZero() && time.Since(last) < time.Duration(sec)*time.Second {
			return policyDecision{Allow: false, Tier: tier, Reason: fmt.Sprintf("rate_limited_%ds", sec)}
		}
	}
	return policyDecision{Allow: true, Tier: tier, Reason: "ok"}
}

func (p *SendPolicy) recordSuccess(recipient string) {
	jid := normalizeJID(recipient)
	p.mu.Lock()
	p.lastSend[jid] = time.Now()
	p.mu.Unlock()
}

func (p *SendPolicy) recordDeny(recipient, reason, tier string) {
	_ = os.MkdirAll(filepath.Dir(p.denyLogPath), 0o700)
	rec := map[string]interface{}{
		"ts":        time.Now().UTC().Format(time.RFC3339),
		"recipient": normalizeJID(recipient),
		"tier":      tier,
		"reason":    reason,
	}
	b, _ := json.Marshal(rec)
	f, err := os.OpenFile(p.denyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	fmt.Printf("send_policy: DENY recipient=%q tier=%q reason=%q\n", recipient, tier, reason)

	p.mu.Lock()
	now := time.Now()
	p.burstHits = append(p.burstHits, now)
	cut := now.Add(-p.burstWindow)
	n := 0
	for _, t := range p.burstHits {
		if t.After(cut) {
			p.burstHits[n] = t
			n++
		}
	}
	p.burstHits = p.burstHits[:n]
	burst := len(p.burstHits) >= p.burstCount
	p.mu.Unlock()

	_ = os.MkdirAll(filepath.Dir(p.notifyPath), 0o700)
	msg := fmt.Sprintf("Briar send denied: %s (%s)\n", reason, normalizeJID(recipient))
	if burst {
		msg = "BURST: " + msg
	}
	_ = os.WriteFile(p.notifyPath, []byte(msg), 0o600)
	if path, err := exec.LookPath("notify-send"); err == nil {
		_ = exec.Command(path, "Briar send policy", strings.TrimSpace(msg)).Run()
	}
}
