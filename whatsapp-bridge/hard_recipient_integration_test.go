package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestSendHandlerRejectsMichaelBeforeWhatsAppTransport(t *testing.T) {
	const token = "test-bridge-token-not-a-secret"
	t.Setenv("SEND_DISABLED", "false")
	t.Setenv("SEND_DISABLED_FLAG", filepath.Join(t.TempDir(), "no-such-flag"))

	handler := newRESTMux(
		newTestClient(&mockLIDStore{}),
		newTestMessageStore(t),
		8080,
		token,
		nil,
	)
	body := `{"recipient":"447970314781@s.whatsapp.net","message":"must not be sent"}`
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/send", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got %d: %s", resp.Code, resp.Body.String())
	}
	var result SendMessageResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	want := "send policy denied: " + hardRecipientDeny
	if result.Success || result.Message != want {
		t.Fatalf("unexpected denial response: %+v", result)
	}
}
