package auth

import (
	"testing"
	"time"
)

func TestLuweiReplayGuard(t *testing.T) {
	var guard LuweiReplayGuard
	now := time.Unix(1792232400, 0)
	if !guard.Accept("valid-unique-signature", now) {
		t.Fatal("first request denied")
	}
	if guard.Accept("valid-unique-signature", now) {
		t.Fatal("replayed request accepted")
	}
	if guard.Accept("", now) {
		t.Fatal("empty signature accepted")
	}
	if !guard.Accept("different-signature", now) {
		t.Fatal("new signature denied")
	}
	if !guard.Accept("valid-unique-signature", now.Add(3*time.Minute)) {
		t.Fatal("expired entry not released")
	}
}
