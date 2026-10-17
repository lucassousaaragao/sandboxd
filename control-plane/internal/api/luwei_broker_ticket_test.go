package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestLuweiBrokerCapability(t *testing.T) {
	key := "test-only-broker-secret-12345678901234567"
	t.Setenv("SANDBOXD_SESSION_HMAC_SECRET", key)
	payload, _ := json.Marshal(map[string]any{
		"iss": "luweidev-harness", "aud": "luweidev-opencode-broker",
		"sessionId": "session-A", "sandboxId": "sandbox-A", "runId": "run-A",
		"projectId": "project-A", "modelId": "model-A", "providerId": "provider-A",
		"modelKey": "gpt-5.4", "iat": time.Now().Unix(), "exp": time.Now().Unix() + 100,
	})
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(encoded))
	ticket := encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !verifyLuweiBrokerCapability(ticket, "sandbox-A", "session-A", "openai/gpt-5.4") {
		t.Fatal("valid ticket rejected")
	}
	if verifyLuweiBrokerCapability(ticket, "sandbox-B", "session-A", "openai/gpt-5.4") ||
		verifyLuweiBrokerCapability(ticket, "sandbox-A", "session-B", "openai/gpt-5.4") ||
		verifyLuweiBrokerCapability(ticket, "sandbox-A", "session-A", "openai/gpt-5.3") ||
		verifyLuweiBrokerCapability(ticket+"a", "sandbox-A", "session-A", "openai/gpt-5.4") {
		t.Fatal("ticket scope bypass")
	}
}
