# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-06-08

### Added
- **Configurable client session pool.** New `session_pool_size` (default `1`).
  At `1` the client keeps exactly one session, so the TLS fingerprint appears
  once and there is no multi-connection signature — identical to previous
  behaviour. At `N > 1` the client round-robins new streams across up to `N`
  sessions for higher aggregate throughput and resilience: a single session
  dropping no longer stalls everything.
- **On-demand pool growth.** Sessions are never pre-opened. The pool starts
  empty, opens its first session on the first request, and only opens further
  sessions (up to `session_pool_size`) once the busiest existing session is
  carrying at least `session_growth_threshold` concurrent streams — avoiding
  the signature of `N` simultaneous handshakes at startup.
- **`session_growth_threshold` (default `16`).** The stealth/throughput dial:
  larger packs more streams onto each connection (fewer connections, stealthier);
  smaller opens new sessions sooner (more parallelism). Ignored when
  `session_pool_size == 1`.
- **QUIC keep-alive.** The QUIC dialer and listener now set a keep-alive period
  so an idle tunnel is not silently dropped by NAT/firewall middleboxes between
  requests.

### Fixed
- **Client TLS handshake moved out of the pool lock.** The (possibly slow)
  uTLS/QUIC handshake now runs with the lock released, so re-dialling a dead
  session no longer freezes every other in-flight request behind it.
- **Automatic session recovery.** A background keep-alive loop prunes dead
  sessions and re-establishes one after an idle gap, so the first request after
  a drop does not pay the full reconnect penalty mid-request.
- **`QUICNetConn` now honours the `io.Reader` contract.** Its placeholder
  `Read`/`Write` returned `(0, nil)`, which makes `io.Copy`/`io.ReadFull` spin
  at 100% CPU. They now return an explicit error, turning any accidental
  stream-level misuse into a loud failure instead of a busy-loop.
- **Oversized UDP datagrams no longer tear down the relay.** A datagram whose
  payload exceeds `MaxUDPPayloadLength` is now dropped individually (with a
  warning) instead of returning a fatal error that killed the entire UDP
  session in that direction. Applied on both the client and server relay paths.

### Security
- **Root-caused the SSRF TOCTOU / DNS-rebinding bypass.** The relay previously
  resolved-and-checked the target, then dialled the hostname again, allowing a
  hostile resolver to return a public IP for the check and an internal IP
  (e.g. `169.254.169.254`) for the connection. The target is now resolved
  exactly once, every returned address is verified against the guard, and the
  dial is pinned to the verified IP — the name is never handed to `Dial` a
  second time. Applied to both the TCP and UDP relay paths.
- **Rate-limiter memory bound.** The per-IP failure table now has a hard cap
  (`DefaultMaxEntries`). When full, the least-recently-seen *non-banned* record
  is evicted to make room; active bans are never evicted, so an attacker cannot
  flush a legitimate ban by spraying fresh source IPs. This closes a
  memory-exhaustion vector under a high-cardinality failure flood.

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
