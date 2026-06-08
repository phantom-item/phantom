// Phantom — encrypted transport framework
// Copyright (C) 2026 The Phantom Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. It is distributed WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU AGPL <https://www.gnu.org/licenses/> for details.

package main

import (
	"errors"
	"io"
	"sync"
	"time"
)

// errPoolUnavailable is returned when the pool has no healthy session and a
// fresh dial also failed.
var errPoolUnavailable = errors.New("session pool: no healthy session available")

// pooledSession is the minimal behaviour the pool needs from an underlying
// transport session (smux over TLS/WS, or a QUIC connection). Both the
// smux-backed and QUIC-backed implementations live in main.go.
type pooledSession interface {
	// OpenStream opens a new multiplexed stream as a duplex byte pipe.
	OpenStream() (io.ReadWriteCloser, error)
	// Healthy reports whether the session is still usable.
	Healthy() bool
	// NumStreams returns the number of currently-open streams, used to
	// decide when on-demand growth is warranted.
	NumStreams() int
	// Close tears the session down.
	Close() error
}

// dialFn establishes one new underlying session. It is always called WITHOUT
// the pool lock held, so a slow TLS/QUIC handshake never blocks other
// goroutines acquiring an already-established session (this is the #5 fix).
type dialFn func() (pooledSession, error)

// sessionPool keeps up to maxSize underlying sessions to the server and hands
// out streams across them.
//
// Growth is on demand, never eager: the pool starts empty and opens its first
// session on the first request. A second (and further, up to maxSize) session
// is opened only when every existing healthy session is already carrying at
// least growthThreshold concurrent streams — so a pool configured with
// maxSize=4 still presents just one connection until real load justifies more,
// avoiding a burst of simultaneous handshakes at startup.
//
// When maxSize == 1 the pool degenerates to exactly the original
// single-session behaviour: one connection, reused, re-dialled on death.
type sessionPool struct {
	mu       sync.Mutex
	sessions []pooledSession
	rr       int // round-robin cursor

	maxSize         int
	growthThreshold int
	dial            dialFn

	// dialing guards against multiple goroutines dialling concurrently when
	// they all observe "needs growth" at once. Only one new dial is in
	// flight at a time; others reuse whatever is currently available.
	dialing bool
}

// newSessionPool builds a pool. maxSize < 1 is clamped to 1. growthThreshold
// is the per-session concurrent-stream count above which the pool will
// consider opening another session (ignored when maxSize == 1).
func newSessionPool(maxSize, growthThreshold int, dial dialFn) *sessionPool {
	if maxSize < 1 {
		maxSize = 1
	}
	if growthThreshold < 1 {
		growthThreshold = 1
	}
	return &sessionPool{
		maxSize:         maxSize,
		growthThreshold: growthThreshold,
		dial:            dial,
	}
}

// pruneLocked drops dead sessions. Caller holds p.mu.
func (p *sessionPool) pruneLocked() {
	live := p.sessions[:0]
	for _, s := range p.sessions {
		if s.Healthy() {
			live = append(live, s)
		} else {
			s.Close()
		}
	}
	p.sessions = live
	if len(p.sessions) == 0 {
		p.rr = 0
	} else if p.rr >= len(p.sessions) {
		p.rr = 0
	}
}

// pickLocked returns the next healthy session round-robin, or nil if the pool
// is empty. Caller holds p.mu.
func (p *sessionPool) pickLocked() pooledSession {
	if len(p.sessions) == 0 {
		return nil
	}
	s := p.sessions[p.rr%len(p.sessions)]
	p.rr++
	return s
}

// minLoadLocked reports the smallest NumStreams across healthy sessions.
// Caller holds p.mu. Returns 0 when there are no sessions.
func (p *sessionPool) minLoadLocked() int {
	if len(p.sessions) == 0 {
		return 0
	}
	min := -1
	for _, s := range p.sessions {
		n := s.NumStreams()
		if min < 0 || n < min {
			min = n
		}
	}
	if min < 0 {
		return 0
	}
	return min
}

// OpenStream acquires a stream from the pool, dialling a new session if needed.
// The dial happens with the lock released.
func (p *sessionPool) OpenStream() (io.ReadWriteCloser, error) {
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		p.pruneLocked()

		needDial := len(p.sessions) == 0 ||
			(len(p.sessions) < p.maxSize &&
				p.minLoadLocked() >= p.growthThreshold &&
				!p.dialing)

		// If we don't need to dial, just use an existing session.
		if !needDial {
			s := p.pickLocked()
			p.mu.Unlock()
			if s == nil {
				// Race: pruned to empty between checks. Retry, which
				// will trigger a dial.
				continue
			}
			stream, err := s.OpenStream()
			if err != nil {
				// Session died under us; loop to prune + retry.
				continue
			}
			return stream, nil
		}

		// We are the goroutine elected to dial. Mark dialing, release the
		// lock, perform the (possibly slow) handshake unlocked.
		p.dialing = true
		p.mu.Unlock()

		sess, err := p.dial()

		p.mu.Lock()
		p.dialing = false
		if err != nil {
			// Dial failed. If we still have a usable session, fall back to
			// it; otherwise surface the error.
			p.pruneLocked()
			s := p.pickLocked()
			p.mu.Unlock()
			if s != nil {
				if stream, oerr := s.OpenStream(); oerr == nil {
					return stream, nil
				}
			}
			return nil, err
		}
		p.sessions = append(p.sessions, sess)
		p.mu.Unlock()

		stream, oerr := sess.OpenStream()
		if oerr != nil {
			continue
		}
		return stream, nil
	}

	// Final attempt: best-effort pick.
	p.mu.Lock()
	p.pruneLocked()
	s := p.pickLocked()
	p.mu.Unlock()
	if s != nil {
		return s.OpenStream()
	}
	return nil, errPoolUnavailable
}

// keepAlive runs in the background, periodically pruning dead sessions and
// ensuring at least one session exists so the first request after an idle gap
// doesn't pay the full reconnect latency. It never grows the pool beyond one
// session on its own — growth past one is strictly load-driven via OpenStream.
func (p *sessionPool) keepAlive(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			p.mu.Lock()
			p.pruneLocked()
			empty := len(p.sessions) == 0
			dialing := p.dialing
			if empty && !dialing {
				p.dialing = true
			}
			p.mu.Unlock()

			if empty && !dialing {
				sess, err := p.dial()
				p.mu.Lock()
				p.dialing = false
				if err == nil {
					p.sessions = append(p.sessions, sess)
				}
				p.mu.Unlock()
			}
		}
	}
}

// Close tears down every session in the pool.
func (p *sessionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		s.Close()
	}
	p.sessions = nil
}
