package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestSigners(t *testing.T, dir, keyID, pubLine string) string {
	t.Helper()
	path := filepath.Join(dir, "allowed_signers")
	line := keyID + ` namespaces="briar-send-cap" ` + strings.TrimSpace(pubLine) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func genTestSSHKey(t *testing.T, dir string) (priv, pubLine string) {
	t.Helper()
	priv = filepath.Join(dir, "id_ed25519")
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-C", "test-send-cap", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v (%s)", err, out)
	}
	raw, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(string(raw))
	if len(parts) < 2 {
		t.Fatalf("bad pubkey: %s", raw)
	}
	return priv, parts[0] + " " + parts[1]
}

func mintTestCapability(
	t *testing.T,
	priv, keyID, serial string,
	cap map[string]interface{},
	capDir string,
) string {
	t.Helper()
	msg, err := json.Marshal(cap)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	msgPath := filepath.Join(tmp, "payload")
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", priv, "-n", sendCapNamespace, msgPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sign: %v (%s)", err, out)
	}
	sig, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	file := SendCapabilityFile{
		Namespace:  sendCapNamespace,
		Capability: cap,
		Signature:  string(sig),
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(capDir, "cap.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseSendCap(recipient, reqHash, nonce string, now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"v":                sendCapVersion,
		"op":               "send",
		"recipient":        normalizeJID(recipient),
		"request_hash":     reqHash,
		"media_hash":       "",
		"lease_token_hash": "",
		"iat":              now.UTC().Format(time.RFC3339),
		"exp":              now.UTC().Add(90 * time.Second).Format(time.RFC3339),
		"nonce":            nonce,
		"yk_serial":        "38907480",
		"key_id":           "test-key",
	}
}

func newTestVerifier(t *testing.T, signersPath, noncePath string, serials map[string]string) *SendCapVerifier {
	t.Helper()
	return &SendCapVerifier{
		keysPath:           filepath.Join(t.TempDir(), "keys.json"),
		allowedSignersPath: signersPath,
		noncePath:          noncePath,
		capDir:             filepath.Dir(signersPath),
		allowedSerials:     serials,
		verifyFn:           sshVerifySignature,
		nowFn:              func() time.Time { return time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC) },
	}
}

func TestReadCapabilitySidecarConfinesPath(t *testing.T) {
	capDir := t.TempDir()
	inside := filepath.Join(capDir, "cap.json")
	raw := []byte(`{"namespace":"briar-send-cap","capability":{"v":1},"signature":"signed"}`)
	if err := os.WriteFile(inside, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapabilitySidecar(inside, capDir); err != nil {
		t.Fatalf("trusted sidecar rejected: %v", err)
	}

	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "cap.json")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapabilitySidecar(outside, capDir); err == nil {
		t.Fatal("sidecar outside trusted directory must be rejected")
	}
}

func TestSHA256HexFileConfinesMediaPath(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "media.txt")
	if err := os.WriteFile(inside, []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sha256HexFile(inside, []string{root}); err != nil {
		t.Fatalf("trusted media rejected: %v", err)
	}

	outside := filepath.Join(t.TempDir(), "media.txt")
	if err := os.WriteFile(outside, []byte("denied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sha256HexFile(outside, []string{root}); err == nil {
		t.Fatal("media outside trusted roots must be rejected")
	}
}

func TestCapabilityRequiredCarveouts(t *testing.T) {
	if capabilityRequired("admin", "447478346120@s.whatsapp.net", true) {
		t.Fatal("alex must be exempt even with media")
	}
	if capabilityRequired("family", "447700900001@s.whatsapp.net", false) {
		t.Fatal("family text should not require capability")
	}
	if !capabilityRequired("family", "447700900001@s.whatsapp.net", true) {
		t.Fatal("family media requires capability")
	}
	if !capabilityRequired("work", "447700900002@s.whatsapp.net", false) {
		t.Fatal("work requires capability")
	}
	if !capabilityRequired("groups", "120363012345678901@g.us", false) {
		t.Fatal("groups require capability")
	}
}

func TestRequestHashMatchesPythonCanonical(t *testing.T) {
	fields := requestHashFields(
		"send",
		"447478346120",
		"hello",
		"",
		"",
		"",
		nil,
		"",
		"",
		"",
		false,
		"",
	)
	got, err := requestHash(fields)
	if err != nil {
		t.Fatal(err)
	}
	// Live check via python for exact match
	cmd := exec.Command("python3", "-c", `
from ask_question_mcp.send_capability import request_hash
print(request_hash({"op":"send","recipient":"447478346120","message":"hello"}))
`)
	cmd.Env = append(os.Environ(), "PYTHONPATH=/data_drive/dd/ask-question-mcp/src")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python hash: %v (%s)", err, out)
	}
	py := strings.TrimSpace(string(out))
	if got != py {
		t.Fatalf("hash mismatch go=%s py=%s fields=%v", got, py, fields)
	}
}

func TestSendCapVerifierHappyPathAndReplay(t *testing.T) {
	dir := t.TempDir()
	priv, pub := genTestSSHKey(t, dir)
	keyID := "test-key"
	signers := writeTestSigners(t, dir, keyID, pub)
	noncePath := filepath.Join(dir, "nonces.json")
	v := newTestVerifier(t, signers, noncePath, map[string]string{"38907480": keyID})
	now := v.nowFn()

	fields := requestHashFields("send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "")
	rh, err := requestHash(fields)
	if err != nil {
		t.Fatal(err)
	}
	cap := baseSendCap("447970314781@s.whatsapp.net", rh, "nonce-one", now)
	cap["key_id"] = keyID
	capPath := mintTestCapability(t, priv, keyID, "38907480", cap, dir)

	d := v.check(capPath, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
	if !d.Allow {
		t.Fatalf("expected allow, got %s", d.Reason)
	}
	d2 := v.check(capPath, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
	if d2.Allow || !strings.Contains(d2.Reason, "replay") {
		t.Fatalf("expected replay deny, got %+v", d2)
	}
}

func TestSendCapVerifierDenies(t *testing.T) {
	dir := t.TempDir()
	priv, pub := genTestSSHKey(t, dir)
	keyID := "test-key"
	signers := writeTestSigners(t, dir, keyID, pub)
	v := newTestVerifier(t, signers, filepath.Join(dir, "nonces.json"), map[string]string{"38907480": keyID})
	now := v.nowFn()
	fields := requestHashFields("send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "")
	rh, _ := requestHash(fields)

	t.Run("missing_file", func(t *testing.T) {
		d := v.check("", true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || d.Reason != "send_capability_required" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("payload_mismatch", func(t *testing.T) {
		cap := baseSendCap("447970314781@s.whatsapp.net", rh, "n-payload", now)
		cap["key_id"] = keyID
		path := mintTestCapability(t, priv, keyID, "38907480", cap, dir)
		d := v.check(path, true, "send", "447970314781@s.whatsapp.net", "DIFFERENT", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || d.Reason != "send_capability_request_mismatch" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("expired", func(t *testing.T) {
		cap := baseSendCap("447970314781@s.whatsapp.net", rh, "n-exp", now.Add(-2*time.Minute))
		cap["iat"] = now.Add(-3 * time.Minute).UTC().Format(time.RFC3339)
		cap["exp"] = now.Add(-1 * time.Minute).UTC().Format(time.RFC3339)
		cap["key_id"] = keyID
		path := mintTestCapability(t, priv, keyID, "38907480", cap, dir)
		d := v.check(path, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || d.Reason != "send_capability_expired" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("wrong_serial", func(t *testing.T) {
		cap := baseSendCap("447970314781@s.whatsapp.net", rh, "n-ser", now)
		cap["yk_serial"] = "38907389"
		cap["key_id"] = keyID
		path := mintTestCapability(t, priv, keyID, "38907480", cap, dir)
		d := v.check(path, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || d.Reason != "send_capability_serial_not_enrolled" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("bad_signature", func(t *testing.T) {
		cap := baseSendCap("447970314781@s.whatsapp.net", rh, "n-sig", now)
		cap["key_id"] = keyID
		path := mintTestCapability(t, priv, keyID, "38907480", cap, dir)
		raw, _ := os.ReadFile(path)
		var file SendCapabilityFile
		_ = json.Unmarshal(raw, &file)
		file.Signature = strings.Replace(file.Signature, "A", "B", 1)
		out, _ := json.MarshalIndent(file, "", "  ")
		_ = os.WriteFile(path, out, 0o600)
		d := v.check(path, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || d.Reason != "send_capability_bad_signature" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("corrupt_nonce_store", func(t *testing.T) {
		noncePath := filepath.Join(dir, "corrupt-nonces.json")
		if err := os.WriteFile(noncePath, []byte("{not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		v2 := newTestVerifier(t, signers, noncePath, map[string]string{"38907480": keyID})
		cap := baseSendCap("447970314781@s.whatsapp.net", rh, "n-corrupt", now)
		cap["key_id"] = keyID
		path := mintTestCapability(t, priv, keyID, "38907480", cap, dir)
		d := v2.check(path, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || !strings.Contains(d.Reason, "corrupt") {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("sidecar_perms", func(t *testing.T) {
		cap := baseSendCap("447970314781@s.whatsapp.net", rh, "n-perm", now)
		cap["key_id"] = keyID
		path := mintTestCapability(t, priv, keyID, "38907480", cap, dir)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		d := v.check(path, true, "send", "447970314781@s.whatsapp.net", "probe", "", "", "", nil, "", "", "", false, "", "")
		if d.Allow || !strings.Contains(d.Reason, "0600") {
			t.Fatalf("%+v", d)
		}
	})
}

func TestReactHandler_GroupReactionPostAllowedMissingCapability_Returns403(t *testing.T) {
	dir := t.TempDir()
	al := filepath.Join(dir, "allow.json")
	if err := os.WriteFile(al, []byte(`{
  "admin": [{"jid":"447478346120@s.whatsapp.net"}],
  "groups": [{"jid":"120363012345678901@g.us","name":"t","post_allowed":true}]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BRIDGE_ALLOWLIST_PATH", al)
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(dir, "no-such-flag"))
	t.Setenv("BRIAR_SEND_CAP_KEYS", filepath.Join(dir, "missing-keys.json"))
	t.Setenv("BRIAR_SEND_CAP_ALLOWED_SIGNERS", filepath.Join(dir, "missing-signers"))
	t.Setenv("BRIAR_SEND_CAP_NONCES", filepath.Join(dir, "nonces.json"))

	const token = "supersecrettoken1234567890abcdef"
	handler := newRESTMux(newTestClient(&mockLIDStore{}), newTestMessageStore(t), 8080, token, nil)

	body := `{"recipient":"120363012345678901@g.us","message_id":"3AABCDEF01234567","emoji":"👍","from_me":false}`
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/react", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 capability deny, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "send_capability") {
		t.Fatalf("expected send_capability reason, got %s", resp.Body.String())
	}
}
