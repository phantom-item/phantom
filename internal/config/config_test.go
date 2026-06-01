package config

import (
	"strings"
	"testing"
)

// ── ClientConfig.VerifyEnabled ──────────────────────────────────────────────

func TestVerifyEnabledDefaultsTrue(t *testing.T) {
	c := &ClientConfig{}
	if !c.VerifyEnabled() {
		t.Error("VerifyEnabled() with nil pointer should default to true")
	}
}

func TestVerifyEnabledExplicitTrue(t *testing.T) {
	yes := true
	c := &ClientConfig{Verify: &yes}
	if !c.VerifyEnabled() {
		t.Error("VerifyEnabled() with explicit true should return true")
	}
}

func TestVerifyEnabledExplicitFalse(t *testing.T) {
	no := false
	c := &ClientConfig{Verify: &no}
	if c.VerifyEnabled() {
		t.Error("VerifyEnabled() with explicit false should return false")
	}
}

// ── requireLoopbackSocks5 ───────────────────────────────────────────────────

func TestRequireLoopbackSocks5Accepts(t *testing.T) {
	good := []string{
		"127.0.0.1:1080",
		"127.5.6.7:1080", // entire 127.0.0.0/8 is loopback
		"[::1]:1080",
		"localhost:1080",
	}
	for _, addr := range good {
		if err := requireLoopbackSocks5(addr); err != nil {
			t.Errorf("expected %q to be accepted, got error: %v", addr, err)
		}
	}
}

func TestRequireLoopbackSocks5RejectsEmptyHost(t *testing.T) {
	err := requireLoopbackSocks5(":1080")
	if err == nil {
		t.Fatal("expected empty-host bind to be rejected")
	}
	if !strings.Contains(err.Error(), "open relay") {
		t.Errorf("error should mention open relay risk, got: %v", err)
	}
}

func TestRequireLoopbackSocks5RejectsBindAll(t *testing.T) {
	bad := []string{
		"0.0.0.0:1080",
		"[::]:1080",
	}
	for _, addr := range bad {
		if err := requireLoopbackSocks5(addr); err == nil {
			t.Errorf("expected %q to be rejected", addr)
		}
	}
}

func TestRequireLoopbackSocks5RejectsLAN(t *testing.T) {
	bad := []string{
		"192.168.1.10:1080",
		"10.0.0.5:1080",
		"172.16.5.10:1080",
		"[2001:db8::1]:1080",
	}
	for _, addr := range bad {
		err := requireLoopbackSocks5(addr)
		if err == nil {
			t.Errorf("expected %q to be rejected", addr)
		}
	}
}

// ── Validate end-to-end ─────────────────────────────────────────────────────

func TestValidateClientRejectsNonLoopbackByDefault(t *testing.T) {
	c := &Config{
		Client: ClientConfig{
			ServerAddr: "example.com:443",
			Password:   "x",
			Socks5Addr: "0.0.0.0:1080",
		},
	}
	if err := c.Validate(); err == nil {
		t.Error("Validate should reject 0.0.0.0 socks5 bind without allow_lan_socks5")
	}
}

func TestValidateClientAllowsLANOptIn(t *testing.T) {
	c := &Config{
		Client: ClientConfig{
			ServerAddr:     "example.com:443",
			Password:       "x",
			Socks5Addr:     "0.0.0.0:1080",
			AllowLANSocks5: true,
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate should accept 0.0.0.0 bind when allow_lan_socks5=true: %v", err)
	}
}

func TestValidateClientLoopbackByDefault(t *testing.T) {
	c := &Config{
		Client: ClientConfig{
			ServerAddr: "example.com:443",
			Password:   "x",
			Socks5Addr: "127.0.0.1:1080",
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate should accept loopback socks5: %v", err)
	}
}
