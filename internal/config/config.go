package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// Thin wrappers — kept as package-locals so the validation helpers
// above can read like spec text without net. prefixes everywhere, and
// so they remain trivially replaceable in tests if needed.
var (
	splitHostPort = net.SplitHostPort
	parseIP       = net.ParseIP
)

type Config struct {
	Server ServerConfig `json:"server"`
	Client ClientConfig `json:"client"`
}

type ServerConfig struct {
	Listen       string   `json:"listen"`
	Passwords    []string `json:"passwords"`
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	FallbackAddr string   `json:"fallback_addr"`
	Transport    string   `json:"transport"` // "tcp", "quic", or "ws"
	WSPath       string   `json:"ws_path"`   // e.g., "/api/v1/stream"

	// TrustProxyHeaders controls whether X-Forwarded-For / X-Real-IP
	// from incoming WebSocket requests are honoured when computing the
	// remote address used by rate limiting.
	//
	// Default false. Only enable when phantom-server runs behind a
	// trusted reverse proxy (Nginx, Caddy, Cloudflare) that strips
	// client-supplied XFF and writes a verified value. Enabling without
	// a fronting proxy lets any client spoof its source IP, which both
	// evades the rate limiter and lets the attacker arrange for innocent
	// IPs to be banned.
	TrustProxyHeaders bool `json:"trust_proxy_headers"`

	// AllowPrivateTargets disables the SSRF guard that, by default,
	// refuses to relay to loopback, link-local, private (RFC 1918 /
	// ULA) and cloud-metadata addresses.
	//
	// Default false (guard active). Any client holding a valid password
	// can otherwise ask the server to dial arbitrary hosts, turning it
	// into a probe into the server's own internal network and the cloud
	// metadata endpoint (169.254.169.254). Enable only when the server
	// is deliberately used to reach a trusted private network.
	AllowPrivateTargets bool `json:"allow_private_targets"`
}

type ClientConfig struct {
	ServerAddr     string `json:"server_addr"`
	Password       string `json:"password"`
	Target         string `json:"target"`
	Socks5Addr     string `json:"socks5_addr"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Transport      string `json:"transport"` // "tcp", "quic", or "ws"
	WSPath         string `json:"ws_path"`   // e.g., "/api/v1/stream"

	// Verify controls TLS certificate validation against the configured
	// SNI. Default true.
	//
	// Set to false only for direct-IP + self-signed deployments (matches
	// the protocol-spec ?allowInsecure=1 URI parameter). For
	// domain + CA-issued certificate deployments, leaving this true gives
	// real MITM protection — without it the uTLS layer alone provides
	// fingerprint mimicry but no peer authentication.
	//
	// Pointer so a missing JSON field defaults to true rather than false.
	Verify *bool `json:"verify,omitempty"`

	// AllowLANSocks5 must be set true to allow socks5_addr to bind on
	// anything other than a loopback / link-local address. Default false.
	//
	// The client's SOCKS5 listener performs no authentication (sends the
	// canonical 0x00 "no-auth" reply). When bound to 0.0.0.0:1080 or a
	// LAN address it becomes an open relay reachable by anyone who can
	// route to the host. This guard catches the most common operator
	// mistake; operators who legitimately want LAN access opt in
	// explicitly.
	AllowLANSocks5 bool `json:"allow_lan_socks5"`
}

func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config

	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	// Server side validation
	if c.Server.Listen != "" {
		if len(c.Server.Passwords) == 0 {
			return fmt.Errorf("server.passwords is required")
		}
		if c.Server.CertFile == "" {
			return fmt.Errorf("server.cert_file is required")
		}
		if c.Server.KeyFile == "" {
			return fmt.Errorf("server.key_file is required")
		}
		// Default transport to tcp if not specified
		if c.Server.Transport == "" {
			c.Server.Transport = "tcp"
		}
		// Set a stealthy default path if transport is websocket
		if c.Server.Transport == "ws" && c.Server.WSPath == "" {
			c.Server.WSPath = "/api/v1/stream"
		}
	}

	// Client side validation
	if c.Client.ServerAddr != "" {
		if c.Client.Password == "" {
			return fmt.Errorf("client.password is required")
		}
		if c.Client.Socks5Addr == "" {
			return fmt.Errorf("client.socks5_addr is required")
		}
		if c.Client.TLSFingerprint == "" {
			c.Client.TLSFingerprint = "HelloChrome_Auto"
		}
		// Default transport to tcp if not specified
		if c.Client.Transport == "" {
			c.Client.Transport = "tcp"
		}
		// Set a stealthy default path if transport is websocket
		if c.Client.Transport == "ws" && c.Client.WSPath == "" {
			c.Client.WSPath = "/api/v1/stream"
		}

		// Verify the SOCKS5 listener is loopback-only unless the
		// operator has explicitly opted into LAN exposure. This
		// catches the most common misconfiguration where socks5_addr
		// would otherwise turn the client into an open relay.
		if !c.Client.AllowLANSocks5 {
			if err := requireLoopbackSocks5(c.Client.Socks5Addr); err != nil {
				return err
			}
		}
	}

	return nil
}

// VerifyEnabled reports whether the client should verify the server's TLS
// certificate. Pointer-based default-true: omitted field -> true; explicit
// false -> false. Centralised here so call sites stay readable.
func (c *ClientConfig) VerifyEnabled() bool {
	if c.Verify == nil {
		return true
	}
	return *c.Verify
}

// requireLoopbackSocks5 enforces that socks5_addr binds to a loopback
// address. host part may be empty (which net.Listen treats as 0.0.0.0
// — explicitly rejected), an IPv4/IPv6 loopback literal, or "localhost".
func requireLoopbackSocks5(addr string) error {
	host, _, err := splitHostPort(addr)
	if err != nil {
		return fmt.Errorf("client.socks5_addr is not a valid host:port: %w", err)
	}
	// Empty host means bind-to-all — reject unless opted-in.
	if host == "" {
		return fmt.Errorf(
			"client.socks5_addr=%q binds to all interfaces; "+
				"this would turn the client into an open relay (the SOCKS5 listener has no auth). "+
				"Either bind to 127.0.0.1 / ::1, or set client.allow_lan_socks5 = true to acknowledge the risk",
			addr,
		)
	}
	if host == "localhost" {
		return nil
	}
	ip := parseIP(host)
	if ip == nil {
		return fmt.Errorf(
			"client.socks5_addr=%q: host must be 127.0.0.1, ::1, localhost, or another loopback address "+
				"(or set client.allow_lan_socks5 = true)",
			addr,
		)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf(
			"client.socks5_addr=%q binds to a non-loopback address; "+
				"this exposes an unauthenticated SOCKS5 proxy to the network. "+
				"Either bind to 127.0.0.1 / ::1, or set client.allow_lan_socks5 = true to acknowledge the risk",
			addr,
		)
	}
	return nil
}
