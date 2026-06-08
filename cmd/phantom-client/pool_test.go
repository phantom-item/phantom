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
	"sync/atomic"
	"testing"
	"time"
)

// ── Fakes ───────────────────────────────────────────────────────────────────

// fakeStream is a trivial io.ReadWriteCloser that reports its closure back to
// the parent session so live-stream accounting can be asserted.
type fakeStream struct {
	parent *fakeSession
	once   sync.Once
}

func (s *fakeStream) Read(p []byte) (int, error)  { return 0, io.EOF }
func (s *fakeStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *fakeStream) Close() error {
	s.once.Do(func() { s.parent.live.Add(-1) })
	return nil
}

// fakeSession is an in-process pooledSession. It needs no network, so the
// pool can be exercised under -race without real TLS/QUIC. healthy is toggled
// to simulate a dropped connection; openErr forces OpenStream failures.
type fakeSession struct {
	id      int
	live    atomic.Int64 // currently-open streams
	opened  atomic.Int64 // cumulative streams opened (for assertions)
	healthy atomic.Bool
	openErr atomic.Bool
	closed  atomic.Bool
}

func newFakeSession(id int) *fakeSession {
	s := &fakeSession{id: id}
	s.healthy.Store(true)
	return s
}

func (s *fakeSession) OpenStream() (io.ReadWriteCloser, error) {
	if s.openErr.Load() || !s.healthy.Load() {
		return nil, errors.New("fake session: open failed")
	}
	s.live.Add(1)
	s.opened.Add(1)
	return &fakeStream{parent: s}, nil
}
func (s *fakeSession) Healthy() bool   { return s.healthy.Load() && !s.closed.Load() }
func (s *fakeSession) NumStreams() int { return int(s.live.Load()) }
func (s *fakeSession) Close() error    { s.closed.Store(true); return nil }

// dialerFactory returns a dialFn that hands out fresh fakeSessions and records
// how many dials happened. An optional delay simulates a slow handshake so the
// "dial happens with the lock released" property can be probed.
func dialerFactory(delay time.Duration) (dialFn, *atomic.Int64, *[]*fakeSession, *sync.Mutex) {
	var dials atomic.Int64
	var mu sync.Mutex
	var created []*fakeSession
	fn := func() (pooledSession, error) {
		n := int(dials.Add(1))
		if delay > 0 {
			time.Sleep(delay)
		}
		s := newFakeSession(n)
		mu.Lock()
		created = append(created, s)
		mu.Unlock()
		return s, nil
	}
	return fn, &dials, &created, &mu
}

// ── Tests ─────────────────────────────────────────────────────────────────

// TestPoolSingleSessionReuse: with maxSize=1 the pool must open exactly one
// session and reuse it for every stream — the original single-session
// behaviour, zero extra connections.
func TestPoolSingleSessionReuse(t *testing.T) {
	dial, dials, _, _ := dialerFactory(0)
	p := newSessionPool(1, 16, dial)
	defer p.Close()

	for i := 0; i < 50; i++ {
		st, err := p.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		st.Close()
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("expected exactly 1 dial for maxSize=1, got %d", got)
	}
}

// TestPoolNoGrowthBelowThreshold: with maxSize>1 but streams always closed
// promptly (load stays under threshold), the pool should still only ever need
// one session.
func TestPoolNoGrowthBelowThreshold(t *testing.T) {
	dial, dials, _, _ := dialerFactory(0)
	p := newSessionPool(4, 8, dial)
	defer p.Close()

	for i := 0; i < 100; i++ {
		st, err := p.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		st.Close() // load returns to 0 between opens
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("expected no growth under threshold, got %d dials", got)
	}
}

// TestPoolGrowsUnderLoad: holding many streams open simultaneously should push
// per-session load over the threshold and trigger growth, but never beyond
// maxSize.
func TestPoolGrowsUnderLoad(t *testing.T) {
	const maxSize, threshold = 3, 5
	dial, dials, _, _ := dialerFactory(0)
	p := newSessionPool(maxSize, threshold, dial)
	defer p.Close()

	var held []io.ReadWriteCloser
	for i := 0; i < threshold*maxSize+10; i++ {
		st, err := p.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		held = append(held, st) // keep open to build up load
	}
	got := dials.Load()
	if got < 2 {
		t.Errorf("expected pool to grow past 1 under sustained load, got %d dials", got)
	}
	if got > maxSize {
		t.Errorf("pool exceeded maxSize: %d dials > %d", got, maxSize)
	}
	for _, st := range held {
		st.Close()
	}
}

// TestPoolPrunesDeadSession: a session that goes unhealthy must be dropped and
// replaced on the next OpenStream rather than handed out.
func TestPoolPrunesDeadSession(t *testing.T) {
	dial, dials, created, mu := dialerFactory(0)
	p := newSessionPool(2, 16, dial)
	defer p.Close()

	// Force the first session to exist.
	st, err := p.OpenStream()
	if err != nil {
		t.Fatalf("initial OpenStream: %v", err)
	}
	st.Close()
	if dials.Load() != 1 {
		t.Fatalf("expected 1 dial, got %d", dials.Load())
	}

	// Kill it.
	mu.Lock()
	(*created)[0].healthy.Store(false)
	mu.Unlock()

	// Next open must prune the dead one and dial a replacement.
	st2, err := p.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream after death: %v", err)
	}
	st2.Close()
	if dials.Load() != 2 {
		t.Errorf("expected a replacement dial, got %d total", dials.Load())
	}
}

// TestPoolConcurrentOpenClose hammers the pool from many goroutines. Run with
// -race to surface data races in pickLocked/pruneLocked/dialing handling.
func TestPoolConcurrentOpenClose(t *testing.T) {
	dial, _, _, _ := dialerFactory(0)
	p := newSessionPool(4, 8, dial)
	defer p.Close()

	const workers, perWorker = 32, 200
	var wg sync.WaitGroup
	wg.Add(workers)
	var failures atomic.Int64
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				st, err := p.OpenStream()
				if err != nil {
					failures.Add(1)
					continue
				}
				// Hold briefly to create overlapping load.
				time.Sleep(time.Microsecond)
				st.Close()
			}
		}()
	}
	wg.Wait()
	if f := failures.Load(); f != 0 {
		t.Errorf("had %d OpenStream failures under concurrency (expected 0 with healthy fakes)", f)
	}
}

// TestPoolSlowDialDoesNotSerialize verifies the #5 fix: a slow handshake must
// not block other goroutines that could use an already-established session.
// Once one session exists, a flood of concurrent opens should be served by it
// quickly even while a second (slow) dial may be in flight.
func TestPoolSlowDialDoesNotSerialize(t *testing.T) {
	dial, _, _, _ := dialerFactory(100 * time.Millisecond)
	p := newSessionPool(4, 1, dial) // threshold=1 makes growth eager
	defer p.Close()

	// Prime one session (pays one slow dial).
	st, err := p.OpenStream()
	if err != nil {
		t.Fatalf("prime: %v", err)
	}
	// keep it open so load>=threshold and growth is considered
	defer st.Close()

	// Now fire many opens concurrently. Even though a second dial may be
	// in flight (slow), the existing session should serve these without
	// every caller paying the 100ms.
	start := time.Now()
	var wg sync.WaitGroup
	const n = 50
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s, err := p.OpenStream()
			if err == nil {
				s.Close()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// If opens were serialized behind dials, this would be many * 100ms.
	// Allow generous headroom for CI but catch gross serialization.
	if elapsed > 2*time.Second {
		t.Errorf("concurrent opens appear serialized behind slow dials: took %v", elapsed)
	}
}

// TestPoolCloseIsIdempotentEnough ensures Close tears down sessions and a
// subsequent OpenStream simply redials rather than panicking.
func TestPoolCloseReleasesSessions(t *testing.T) {
	dial, _, created, mu := dialerFactory(0)
	p := newSessionPool(2, 16, dial)

	st, err := p.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	st.Close()

	p.Close()

	mu.Lock()
	for _, s := range *created {
		if !s.closed.Load() {
			t.Errorf("session %d was not closed by pool.Close()", s.id)
		}
	}
	mu.Unlock()
}
