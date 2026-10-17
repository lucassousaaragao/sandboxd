package auth

import "testing"

func TestLuweiSandboxOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, signed, stored string
		allowed              bool
	}{
		{"owner", "session-a", "session-a", true},
		{"foreign", "session-b", "session-a", false},
		{"missing stored", "session-a", "", false},
		{"missing signed", "", "session-a", false},
		{"both empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeLuweiSandbox(tc.signed, tc.stored)
			if (err == nil) != tc.allowed {
				t.Fatalf("unexpected ownership result: %v", err)
			}
		})
	}
}
