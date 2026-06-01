package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// fakeConn lets us drive Reads from a buffer through a net.Conn-compatible
// interface so RewindConn can be exercised without a real network socket.
type fakeConn struct {
	net.Conn
	r *bytes.Buffer
}

func newFakeConn(data []byte) *fakeConn {
	return &fakeConn{r: bytes.NewBuffer(data)}
}

func (f *fakeConn) Read(b []byte) (int, error) { return f.r.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}
func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRewindReplaysBufferedBytes(t *testing.T) {
	rc := NewRewindConn(newFakeConn([]byte("ABCDEFGH")))

	// Read 4 bytes
	first := make([]byte, 4)
	if _, err := io.ReadFull(rc, first); err != nil {
		t.Fatalf("initial read: %v", err)
	}
	if string(first) != "ABCD" {
		t.Fatalf("expected ABCD, got %q", first)
	}

	rc.Rewind()

	// After Rewind, we should see the buffered ABCD first, then EFGH.
	out, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read after rewind: %v", err)
	}
	if string(out) != "ABCDEFGH" {
		t.Errorf("expected ABCDEFGH after rewind, got %q", out)
	}
}

func TestRewindBufferIsCapped(t *testing.T) {
	// Send substantially more than MaxRewindBuffer; the cap should
	// silently engage without breaking the Read pipeline.
	payload := bytes.Repeat([]byte{'X'}, MaxRewindBuffer*2)
	rc := NewRewindConn(newFakeConn(payload))

	// Drain the entire stream pre-Rewind. All reads must succeed.
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// Buffer must not have grown past the cap.
	if rc.buf.Len() > MaxRewindBuffer {
		t.Errorf("buffer exceeded cap: %d > %d", rc.buf.Len(), MaxRewindBuffer)
	}
	if !rc.bufFull {
		t.Error("bufFull flag was not set after exceeding cap")
	}
}

func TestRewindIdempotent(t *testing.T) {
	rc := NewRewindConn(newFakeConn([]byte("hello")))
	// Calling Rewind twice should be a no-op the second time.
	rc.Rewind()
	rc.Rewind()
	out, _ := io.ReadAll(rc)
	if string(out) != "hello" {
		t.Errorf("expected hello, got %q", out)
	}
}
