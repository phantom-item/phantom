package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
)

type Authenticator interface {
	Verify(hash string) bool
	Reload(passwords []string)
}

type StaticAuth struct {
	mu sync.RWMutex
	// hashes holds the hex-encoded SHA-224 of each configured password.
	// A slice (not a map) is used so Verify can compare against every
	// entry in constant time rather than via a timing-variable map
	// lookup.
	hashes []string
}

func hashPasswords(passwords []string) []string {
	out := make([]string, 0, len(passwords))
	for _, password := range passwords {
		h := sha256.Sum224([]byte(password))
		out = append(out, hex.EncodeToString(h[:]))
	}
	return out
}

func NewStaticAuth(passwords []string) *StaticAuth {
	return &StaticAuth{hashes: hashPasswords(passwords)}
}

// Verify reports whether hash matches any configured password hash.
//
// The comparison runs in time independent of which password matched and
// of how far down the list the match is: every entry is compared with
// crypto/subtle.ConstantTimeCompare and the results are OR-ed together
// without short-circuiting. This avoids leaking, via response timing,
// whether an attacker's guess is "close" to a valid credential.
func (a *StaticAuth) Verify(hash string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	hb := []byte(hash)
	var match int
	for _, known := range a.hashes {
		// ConstantTimeCompare returns 1 only when lengths match and all
		// bytes are equal; length differs only for malformed input, and
		// the hash length is not secret.
		match |= subtle.ConstantTimeCompare(hb, []byte(known))
	}
	return match == 1
}

func (a *StaticAuth) Reload(passwords []string) {
	newHashes := hashPasswords(passwords)

	a.mu.Lock()
	a.hashes = newHashes
	a.mu.Unlock()
}
