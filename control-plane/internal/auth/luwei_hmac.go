package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var ErrLuweiSessionSignature = errors.New("invalid session signature")

// VerifyLuweiSessionSignature validates the wire contract emitted by runtime-session.
// Callers must separately resolve and authorize the session against the sandbox resource.
// This verifier deliberately does not activate on a running server without a tested ownership gate.
func VerifyLuweiSessionSignature(r *http.Request, secret string, now time.Time) (string, error) {
	id := r.Header.Get("X-Luwei-Session-ID")
	ts := r.Header.Get("X-Luwei-Session-Timestamp")
	sig := r.Header.Get("X-Luwei-Session-Signature")
	if secret == "" || id == "" || ts == "" || sig == "" || strings.ContainsAny(id, "\r\n") {
		return "", ErrLuweiSessionSignature
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec <= 0 || sec < now.Unix()-60 || sec > now.Unix()+60 {
		return "", ErrLuweiSessionSignature
	}
	raw, err := hex.DecodeString(sig)
	if err != nil || len(raw) != sha256.Size {
		return "", ErrLuweiSessionSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.Join([]string{id, r.Method, r.URL.EscapedPath(), ts}, "\n")))
	if !hmac.Equal(raw, mac.Sum(nil)) {
		return "", ErrLuweiSessionSignature
	}
	return id, nil
}
