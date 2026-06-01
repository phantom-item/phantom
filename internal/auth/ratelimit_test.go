package auth

import (
	"net"
	"testing"
	"time"
)

// addr returns a net.Addr whose String() yields "host:port", matching
// what extractIP() expects.
type addr struct{ s string }

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return a.s }

func TestRateLimiterBansAfterMaxFailures(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute, time.Minute)
	defer rl.Close()

	a := addr{"1.2.3.4:5000"}
	if rl.IsBanned(a) {
		t.Fatal("fresh IP should not be banned")
	}

	rl.RecordFailure(a)
	rl.RecordFailure(a)
	if rl.IsBanned(a) {
		t.Error("should not be banned before threshold")
	}
	rl.RecordFailure(a)
	if !rl.IsBanned(a) {
		t.Error("should be banned after threshold")
	}
}

func TestRateLimiterPerIPIsolation(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, time.Minute)
	defer rl.Close()

	a := addr{"1.2.3.4:5000"}
	b := addr{"9.9.9.9:5000"}

	rl.RecordFailure(a)
	rl.RecordFailure(a)
	if !rl.IsBanned(a) {
		t.Error("a should be banned")
	}
	if rl.IsBanned(b) {
		t.Error("b should not be banned by a's failures")
	}
}

func TestRateLimiterRecordSuccessClears(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, time.Minute)
	defer rl.Close()

	a := addr{"1.2.3.4:5000"}
	rl.RecordFailure(a)
	rl.RecordSuccess(a)
	rl.RecordFailure(a)
	if rl.IsBanned(a) {
		t.Error("should not be banned — success cleared the counter")
	}
}

func TestRateLimiterMalformedAddrIgnored(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, time.Minute)
	defer rl.Close()

	// Empty-string address — extractIP returns "" and the limiter
	// silently no-ops.
	bad := addr{""}
	rl.RecordFailure(bad)
	if rl.IsBanned(bad) {
		t.Error("malformed addr should never be banned (records dropped)")
	}
}

func TestExtractIPFromTCPAddr(t *testing.T) {
	// Spot-check: extractIP should work with a real net.TCPAddr too,
	// not just our stub addr type.
	ta := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	if got := extractIP(ta); got != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %q", got)
	}
}
