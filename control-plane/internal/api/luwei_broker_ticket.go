package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"time"
)

type brokerClaims struct {
	Iss        string `json:"iss"`
	Aud        string `json:"aud"`
	RunID      string `json:"runId"`
	SessionID  string `json:"sessionId"`
	SandboxID  string `json:"sandboxId"`
	ProjectID  string `json:"projectId"`
	ModelID    string `json:"modelId"`
	ProviderID string `json:"providerId"`
	ModelKey   string `json:"modelKey"`
	IAT        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
}

func verifyLuweiBrokerCapability(ticket, sandboxID, sessionID, model string) bool {
	secret := os.Getenv("SANDBOXD_SESSION_HMAC_SECRET")
	if len(secret) < 32 || sessionID == "" || sandboxID == "" || len(ticket) > 4096 {
		return false
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 2 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) > 3072 {
		return false
	}
	var claims brokerClaims
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	now := time.Now().Unix()
	return claims.Iss == "luweidev-harness" &&
		claims.Aud == "luweidev-opencode-broker" &&
		claims.SessionID == sessionID && claims.SandboxID == sandboxID &&
		claims.RunID != "" && claims.ProjectID != "" && claims.ModelID != "" &&
		claims.ProviderID != "" && model == "openai/"+claims.ModelKey &&
		claims.Exp > now && claims.IAT <= now+30 && claims.Exp-claims.IAT <= 900
}

// The bearer is a capability limited to a session/model/15m, never the real API key.
func brokerTaskEnv(ticket string) map[string]string {
	if ticket == "" {
		return nil
	}
	return map[string]string{"LUWEI_BROKER_TICKET": ticket}
}
