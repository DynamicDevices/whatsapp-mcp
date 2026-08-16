package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sendCapNamespace       = "briar-send-cap"
	sendCapVersion         = 1
	defaultSendCapKeysPath = "/home/ajlennon/.config/cursorpa/send-cap-keys.json"
	defaultSendCapSigners  = "/home/ajlennon/.config/cursorpa/send-cap-allowed_signers"
	defaultSendCapNonces   = "/home/ajlennon/.local/share/briar/send-cap-nonces.json"
	defaultSendCapDir      = "/home/ajlennon/.local/share/whatsapp-mcp/send-caps"
)

// SendCapabilityFile is the mode-0600 sidecar written by ask-question minting.
type SendCapabilityFile struct {
	Namespace  string                 `json:"namespace"`
	Capability map[string]interface{} `json:"capability"`
	Signature  string                 `json:"signature"`
}

type sendCapKeysFile struct {
	Namespace          string `json:"namespace"`
	AllowedSignersPath string `json:"allowed_signers_path"`
	NonceStorePath     string `json:"nonce_store_path"`
	Keys               []struct {
		Serial        string `json:"serial"`
		KeyID         string `json:"key_id"`
		PublicKeyPath string `json:"public_key_path"`
	} `json:"keys"`
}

type nonceStoreFile struct {
	Consumed map[string]string `json:"consumed"`
}

type SendCapVerifier struct {
	mu                 sync.Mutex
	keysPath           string
	allowedSignersPath string
	noncePath          string
	capDir             string
	mediaRoots         []string
	allowedSerials     map[string]string // serial -> key_id
	verifyFn           func(message []byte, signature, principal, signersPath string) error
	nowFn              func() time.Time
}

type sendCapDecision struct {
	Allow  bool
	Reason string
}

func loadSendCapVerifier(mediaRoots []string) *SendCapVerifier {
	keysPath := envOr("BRIAR_SEND_CAP_KEYS", defaultSendCapKeysPath)
	v := &SendCapVerifier{
		keysPath:           keysPath,
		allowedSignersPath: envOr("BRIAR_SEND_CAP_ALLOWED_SIGNERS", defaultSendCapSigners),
		noncePath:          envOr("BRIAR_SEND_CAP_NONCES", defaultSendCapNonces),
		capDir:             envOr("BRIAR_SEND_CAP_DIR", defaultSendCapDir),
		mediaRoots:         mediaRoots,
		allowedSerials:     map[string]string{},
		verifyFn:           sshVerifySignature,
		nowFn:              func() time.Time { return time.Now().UTC() },
	}
	data, err := os.ReadFile(keysPath)
	if err != nil {
		fmt.Printf("send_cap: keys file %s: %v (fail-closed when required)\n", keysPath, err)
		return v
	}
	var cfg sendCapKeysFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("send_cap: keys parse: %v\n", err)
		return v
	}
	if cfg.AllowedSignersPath != "" {
		v.allowedSignersPath = cfg.AllowedSignersPath
	}
	if cfg.NonceStorePath != "" {
		v.noncePath = cfg.NonceStorePath
	}
	for _, k := range cfg.Keys {
		if k.Serial != "" && k.KeyID != "" {
			v.allowedSerials[k.Serial] = k.KeyID
		}
	}
	fmt.Printf("send_cap: loaded %d enrolled key(s); signers=%s\n", len(v.allowedSerials), v.allowedSignersPath)
	return v
}

func capabilityRequired(tier, recipient string, hasMedia bool) bool {
	if isAlexRecipient(recipient) {
		return false
	}
	jid := normalizeJID(recipient)
	if strings.HasSuffix(jid, "@g.us") {
		return true
	}
	if hasMedia {
		return true
	}
	switch tier {
	case "work", "known", "tester":
		return true
	case "family", "friends", "admin":
		return false
	default:
		// Fail closed for unexpected tiers that somehow passed send_policy.
		return true
	}
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sha256HexFile(path string, allowedRoots []string) (string, error) {
	resolved, err := validateMediaPath(path, allowedRoots)
	if err != nil {
		return "", err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func leaseTokenHash(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	return sha256HexBytes([]byte(token))
}

// requestHashFields mirrors ask_question_mcp.send_capability.canonical_request_fields.
func requestHashFields(op, recipient, message, quotedMessageID, quotedSenderJID, quotedContent string,
	mentions []string, mediaPath, messageID, emoji string, fromMe bool, senderJID string) map[string]interface{} {
	ment := make([]interface{}, 0, len(mentions))
	for _, m := range mentions {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		ment = append(ment, normalizeJID(m))
	}
	return map[string]interface{}{
		"emoji":             emoji,
		"from_me":           fromMe,
		"media_path":        mediaPath,
		"mentions":          ment,
		"message":           message,
		"message_id":        messageID,
		"op":                strings.ToLower(strings.TrimSpace(op)),
		"quoted_content":    quotedContent,
		"quoted_message_id": quotedMessageID,
		"quoted_sender_jid": normalizeJID(quotedSenderJID),
		"recipient":         normalizeJID(recipient),
		"sender_jid":        normalizeJID(senderJID),
	}
}

func requestHash(fields map[string]interface{}) (string, error) {
	raw, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return sha256HexBytes(raw), nil
}

func capabilitySigningBytes(cap map[string]interface{}) ([]byte, error) {
	return json.Marshal(cap)
}

func sshVerifySignature(message []byte, signature, principal, signersPath string) error {
	if strings.TrimSpace(signersPath) == "" {
		return fmt.Errorf("allowed_signers missing")
	}
	if st, err := os.Stat(signersPath); err != nil || st.IsDir() || st.Size() == 0 {
		return fmt.Errorf("allowed_signers unavailable")
	}
	tmp, err := os.MkdirTemp("", "briar-send-cap-verify-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmp)
	}()
	msgPath := filepath.Join(tmp, "payload")
	sigPath := filepath.Join(tmp, "payload.sig")
	if err := os.WriteFile(msgPath, message, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, []byte(signature), 0o600); err != nil {
		return err
	}
	cmd := exec.Command(
		"ssh-keygen", "-Y", "verify",
		"-f", signersPath,
		"-I", principal,
		"-n", sendCapNamespace,
		"-s", sigPath,
	)
	cmd.Stdin = strings.NewReader(string(message))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("signature verify failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func readCapabilitySidecar(path, capDir string) (*SendCapabilityFile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("send_capability_file required")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("send_capability_file must be absolute")
	}
	resolvedDir, err := filepath.EvalSymlinks(capDir)
	if err != nil {
		return nil, fmt.Errorf("send_capability directory unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil ||
		(resolved != resolvedDir &&
			!strings.HasPrefix(resolved, resolvedDir+string(os.PathSeparator))) {
		return nil, fmt.Errorf("send_capability_file outside trusted directory")
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("send_capability_file unreadable")
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("send_capability_file must be a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("send_capability_file must be mode 0600")
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("send_capability_file unreadable")
	}
	var file SendCapabilityFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("send_capability_file malformed")
	}
	if file.Namespace != "" && file.Namespace != sendCapNamespace {
		return nil, fmt.Errorf("send_capability namespace mismatch")
	}
	if file.Capability == nil || strings.TrimSpace(file.Signature) == "" {
		return nil, fmt.Errorf("send_capability_file incomplete")
	}
	return &file, nil
}

func (v *SendCapVerifier) consumeNonce(nonce string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if strings.TrimSpace(nonce) == "" {
		return fmt.Errorf("nonce missing")
	}
	if err := os.MkdirAll(filepath.Dir(v.noncePath), 0o700); err != nil {
		return fmt.Errorf("nonce store unavailable")
	}
	store := nonceStoreFile{Consumed: map[string]string{}}
	raw, err := os.ReadFile(v.noncePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("nonce store unavailable")
	}
	if err == nil {
		if len(raw) == 0 {
			return fmt.Errorf("nonce store corrupt")
		}
		if err := json.Unmarshal(raw, &store); err != nil {
			return fmt.Errorf("nonce store corrupt")
		}
		if store.Consumed == nil {
			return fmt.Errorf("nonce store corrupt")
		}
	}
	if _, exists := store.Consumed[nonce]; exists {
		return fmt.Errorf("nonce replay")
	}
	store.Consumed[nonce] = v.nowFn().Format(time.RFC3339)
	out, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("nonce store unavailable")
	}
	tmp := v.noncePath + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("nonce store unavailable")
	}
	if err := os.Rename(tmp, v.noncePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("nonce store unavailable")
	}
	return nil
}

func asString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		// JSON numbers — reject for string fields by stringifying only ints that look like serials
		return fmt.Sprintf("%v", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func asInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	default:
		return 0
	}
}

func (v *SendCapVerifier) check(
	capPath string,
	required bool,
	op string,
	recipient string,
	message string,
	quotedMessageID, quotedSenderJID, quotedContent string,
	mentions []string,
	mediaPath string,
	messageID string,
	emoji string,
	fromMe bool,
	senderJID string,
	leaseOwnerToken string,
) sendCapDecision {
	if !required {
		return sendCapDecision{Allow: true, Reason: "not_required"}
	}
	if strings.TrimSpace(capPath) == "" {
		return sendCapDecision{Allow: false, Reason: "send_capability_required"}
	}
	if len(v.allowedSerials) == 0 {
		return sendCapDecision{Allow: false, Reason: "send_capability_keys_unavailable"}
	}
	if st, err := os.Stat(v.allowedSignersPath); err != nil || st.IsDir() || st.Size() == 0 {
		return sendCapDecision{Allow: false, Reason: "send_capability_signers_unavailable"}
	}

	file, err := readCapabilitySidecar(capPath, v.capDir)
	if err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_invalid: " + err.Error()}
	}
	cap := file.Capability
	if asInt(cap, "v") != sendCapVersion {
		return sendCapDecision{Allow: false, Reason: "send_capability_version"}
	}
	capOp := strings.ToLower(asString(cap, "op"))
	if capOp != strings.ToLower(strings.TrimSpace(op)) {
		return sendCapDecision{Allow: false, Reason: "send_capability_op_mismatch"}
	}
	if normalizeJID(asString(cap, "recipient")) != normalizeJID(recipient) {
		return sendCapDecision{Allow: false, Reason: "send_capability_recipient_mismatch"}
	}
	serial := asString(cap, "yk_serial")
	keyID := asString(cap, "key_id")
	expectedKeyID, ok := v.allowedSerials[serial]
	if !ok {
		return sendCapDecision{Allow: false, Reason: "send_capability_serial_not_enrolled"}
	}
	if keyID == "" || keyID != expectedKeyID {
		return sendCapDecision{Allow: false, Reason: "send_capability_key_id_mismatch"}
	}

	iat, err := time.Parse(time.RFC3339, asString(cap, "iat"))
	if err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_iat_invalid"}
	}
	exp, err := time.Parse(time.RFC3339, asString(cap, "exp"))
	if err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_exp_invalid"}
	}
	now := v.nowFn()
	if iat.After(now.Add(30 * time.Second)) {
		return sendCapDecision{Allow: false, Reason: "send_capability_iat_future"}
	}
	if !exp.After(now) {
		return sendCapDecision{Allow: false, Reason: "send_capability_expired"}
	}

	fields := requestHashFields(op, recipient, message, quotedMessageID, quotedSenderJID, quotedContent,
		mentions, mediaPath, messageID, emoji, fromMe, senderJID)
	wantHash, err := requestHash(fields)
	if err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_hash_error"}
	}
	if asString(cap, "request_hash") != wantHash {
		return sendCapDecision{Allow: false, Reason: "send_capability_request_mismatch"}
	}

	wantMedia := ""
	if strings.TrimSpace(mediaPath) != "" {
		wantMedia, err = sha256HexFile(mediaPath, v.mediaRoots)
		if err != nil {
			return sendCapDecision{Allow: false, Reason: "send_capability_media_unreadable"}
		}
	}
	if asString(cap, "media_hash") != wantMedia {
		return sendCapDecision{Allow: false, Reason: "send_capability_media_mismatch"}
	}
	if asString(cap, "lease_token_hash") != leaseTokenHash(leaseOwnerToken) {
		return sendCapDecision{Allow: false, Reason: "send_capability_lease_mismatch"}
	}

	msg, err := capabilitySigningBytes(cap)
	if err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_sign_bytes"}
	}
	if err := v.verifyFn(msg, file.Signature, keyID, v.allowedSignersPath); err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_bad_signature"}
	}

	nonce := asString(cap, "nonce")
	if err := v.consumeNonce(nonce); err != nil {
		return sendCapDecision{Allow: false, Reason: "send_capability_" + err.Error()}
	}
	return sendCapDecision{Allow: true, Reason: "ok"}
}
