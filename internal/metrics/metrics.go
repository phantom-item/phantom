package metrics

import (
	"sync"
	"sync/atomic"
)

type UserStats struct {
	Sent     atomic.Uint64
	Received atomic.Uint64
}

type Metrics struct {
	mu    sync.RWMutex
	users map[string]*UserStats
}

func New() *Metrics {
	return &Metrics{
		users: make(map[string]*UserStats),
	}
}

func (m *Metrics) GetOrCreate(hash string) *UserStats {
	m.mu.RLock()
	s, ok := m.users[hash]
	m.mu.RUnlock()
	if ok {
		return s
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok = m.users[hash]; ok {
		return s
	}
	s = &UserStats{}
	m.users[hash] = s
	return s
}

func (m *Metrics) Snapshot() map[string][2]uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][2]uint64, len(m.users))
	for hash, s := range m.users {
		result[hash] = [2]uint64{s.Sent.Load(), s.Received.Load()}
	}
	return result
}
