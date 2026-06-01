package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

type Authenticator interface {
	Verify(hash string) bool
	Reload(passwords []string)
}

type StaticAuth struct {
	mu     sync.RWMutex
	hashes map[string]struct{}
}

func NewStaticAuth(passwords []string) *StaticAuth {
	hashes := make(map[string]struct{})
	for _, password := range passwords {
		hash := sha256.Sum224([]byte(password))
		hashes[hex.EncodeToString(hash[:])] = struct{}{}
	}

	return &StaticAuth{
		hashes: hashes,
	}
}

func (a *StaticAuth) Verify(hash string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	_, ok := a.hashes[hash]
	return ok
}

func (a *StaticAuth) Reload(passwords []string) {
	newHashes := make(map[string]struct{})
	for _, password := range passwords {
		hash := sha256.Sum224([]byte(password))
		newHashes[hex.EncodeToString(hash[:])] = struct{}{}
	}

	a.mu.Lock()
	a.hashes = newHashes
	a.mu.Unlock()
}
