# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-06-02

### Added
- **TCP + QUIC dual-stack deployment.** `install.sh` now installs two
  independent systemd units, `phantom-server-tcp` (TCP/TLS on 443) and
  `phantom-server-quic` (QUIC on UDP/443), sharing a single config. Previously
  only TCP was served despite QUIC being advertised.
- **QUIC selectable via config.** `transport: "quic"` now enables the QUIC
  transport on both client and server, equivalent to the `--quic` flag, so a
  `phantom://...?type=quic` URI maps onto config without the flag.
- **SSRF guard.** The server refuses by default to relay (TCP or UDP) to
  loopback, link-local, private (RFC 1918 / ULA) and cloud-metadata
  (169.254.169.254) addresses, resolving hostnames first so a domain pointing
  at an internal IP is also blocked. Opt out with `allow_private_targets: true`.
- `--version` flag on both `phantom-server` and `phantom-client`. The version
  string is injected at build time via `-ldflags "-X main.version=..."` and
  wired into the release workflow.
- QUIC client URI shown by the installer alongside the TCP URI.

### Fixed
- `protocol.writeAddress` now returns an error for unknown address types and
  rejects empty domain names, instead of silently emitting a malformed packet.
- SOCKS5 handshake now verifies the client actually offered the no-auth method
  (0x00) and replies with 0xFF ("no acceptable methods") otherwise, per RFC 1928.
- Client UDP relay (`handleUDP`) now closes the tunnel stream on exit so the
  inbound read goroutine cannot linger.
- `install.sh` download now uses `curl -fsSL` and validates the archive and the
  extracted binary, instead of silently saving an HTTP error page.
- The legacy single-mode `phantom-server.service` unit is removed on
  (re)install and uninstall so it cannot double-bind port 443.
- `auth.Verify` now compares the credential hash against every configured
  password hash in constant time (crypto/subtle, no short-circuit) instead of a
  timing-variable map lookup.
- Removed an unused `QUICConnToNet` helper and a no-op `http2 on;` directive
  from the Nginx fallback block.
- `go.mod` toolchain directive aligned to Go 1.25 (1.24 reached EOL), matching CI.

## [1.0.0]
- Initial release: Trojan-compatible encrypted proxy with TCP/TLS and QUIC
  transports, WebSocket option, SOCKS5 front end, UDP relay, multi-user auth,
  rate limiting, hot config reload, and metrics.
