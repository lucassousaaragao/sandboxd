package auth

import "errors"

var ErrLuweiSessionOwnership = errors.New("session does not own sandbox")

// AuthorizeLuweiSandbox only authorizes the exact persisted session binding.
// The caller must fetch the binding from the database, never from request headers.
func AuthorizeLuweiSandbox(signedSessionID, persistedSessionID string) error {
	if signedSessionID == "" || persistedSessionID == "" || signedSessionID != persistedSessionID {
		return ErrLuweiSessionOwnership
	}
	return nil
}
