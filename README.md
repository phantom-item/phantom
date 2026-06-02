# Phantom

![Version](https://img.shields.io/badge/version-v1.0.0-blue) ![License](https://img.shields.io/badge/license-AGPL--3.0-orange) ![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8)

A modern encrypted transport framework with its own `phantom://` protocol,
built for performance, security, and clean architecture.

> **Status**: Stable — v1.0.0

---

## One-Line Install

```bash
bash <(curl -sL https://raw.githubusercontent.com/phantom-item/phantom/main/docs/install.sh)
```

> Supports Debian / Ubuntu / CentOS. Must run as root.
>
> The installer will automatically:
> - Install and configure Nginx as fallback backend
> - Obtain a Let's Encrypt TLS certificate (if domain provided)
> - Generate a random password
> - Configure UFW firewall
> - Set up systemd auto-start service
> - Print connection URI and QR code

### Post-install management

Re-running the same one-liner on an already-installed server brings up a menu of management actions:

```
[1] Install Phantom
[2] Uninstall Phantom
[3] Show users (URI + QR code)
[4] Add user
[5] Remove user
[6] Exit
```

`[3]` lists every configured password with its connection URI and a freshly-rendered QR code — useful for re-adding a device or sharing the link without copy-pasting from disk.

`[4]` and `[5]` add or remove individual passwords. Each password is an independent user identity: server-side metrics are tracked per password, so a stolen device can be revoked without affecting anyone else. The server picks up changes via SIGHUP with no connection downtime. `[5]` refuses to remove the last remaining user to avoid locking yourself out.

---

## Features

### Core Transport
- **Native `phantom://` Protocol** — Purpose-built encrypted transport with clean wire format
- **Native QUIC Transport** — Eliminates head-of-line blocking, achieves lower latency
- **WebSocket Transport** — CDN-compatible mode disguising traffic as standard HTTPS WebSocket
- **Stream Multiplexing** — smux over TLS multiplexes multiple streams over one socket

### Stealth & Security
- **uTLS Fingerprint Mimicry** — Disguises TLS Client Hello as Chrome / Firefox / Edge / Random
- **Active Probe Defense** — Invalid connections are transparently forwarded to a real web server
- **Rate Limiting** — Auto-bans IPs after repeated authentication failures
- **Stealthy Default Paths** — WebSocket path defaults to `/api/v1/stream` to blend with normal APIs

### Operations
- **Config Hot Reload** — Add or remove users via `SIGHUP` without restarting
- **Per-User Traffic Metrics** — Lock-free atomic counters per user
- **Graceful Shutdown** — Active sessions complete before server exits

---

## Performance

| Benchmark | Result |
|:---|:---|
| TCP relay throughput | 318 MB/s |
| Concurrent streams | 22 MB/s |
| Round-trip latency | ~46 µs |

> Benchmarked on a mid-range x86-64 machine. Results vary by hardware and network conditions.

---

## Configuration

### Server (`config.json`)

```json
{
  "server": {
    "listen": ":443",
    "passwords": ["your-password"],
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem",
    "fallback_addr": "127.0.0.1:8080",
    "transport": "tcp",
    "ws_path": "/api/v1/stream",
    "trust_proxy_headers": false
  }
}
```

> `trust_proxy_headers` (default `false`) controls whether
> `X-Forwarded-For` / `X-Real-IP` from incoming WebSocket requests
> are honoured. Enable **only** when phantom-server runs behind a
> trusted reverse proxy that strips and rewrites client-supplied
> XFF (Nginx, Caddy, Cloudflare). Enabling it on a directly-exposed
> server lets clients spoof their source IP, bypassing rate limiting.

### Client (`config.json`)

```json
{
  "client": {
    "server_addr": "your-server.com:443",
    "password": "your-password",
    "socks5_addr": "127.0.0.1:1080",
    "transport": "tcp",
    "ws_path": "/api/v1/stream",
    "tls_fingerprint": "HelloChrome_Auto",
    "verify": true,
    "allow_lan_socks5": false
  }
}
```

> `verify` (default `true`) controls TLS certificate verification.
> Set to `false` only for direct-IP + self-signed deployments
> (matches the `?allowInsecure=1` URI parameter). Domain + CA-cert
> deployments should keep it `true` to get real MITM protection.

> `allow_lan_socks5` (default `false`) must be set true to bind
> `socks5_addr` to anything other than a loopback address. The
> SOCKS5 listener has no authentication; binding to `0.0.0.0` or
> a LAN address turns the client into an open proxy for anyone
> who can reach it.

### Transport Modes

| Mode | Description | Use Case |
|:---|:---|:---|
| `tcp` (default) | TLS + smux multiplexing | General use |
| `ws` | WebSocket over TLS | CDN deployment, strict networks |
| `--quic` flag | Native QUIC transport | Low-latency, mobile networks |

### TLS Fingerprints

| Value | Description |
|:---|:---|
| `HelloChrome_Auto` (default) | Latest Chrome fingerprint |
| `HelloFirefox_Auto` | Latest Firefox fingerprint |
| `HelloEdge_Auto` | Latest Edge fingerprint |
| `HelloRandomized` | Randomized fingerprint |

---

## Manual Setup (Advanced)

For developers who prefer manual control over one-line install.

### 1. Download Binary

```bash
tar -xzf phantom-linux-amd64.tar.gz
chmod +x phantom-server phantom-client
```

### 2. Generate TLS Certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=phantom"
```

### 3. Run

```bash
# TCP mode (default)
./phantom-server --config config.json
./phantom-client --config config.json

# QUIC mode
./phantom-server --config config.json --quic
./phantom-client --config config.json --quic

# WebSocket mode (set "transport": "ws" in config.json)
./phantom-server --config config.json
./phantom-client --config config.json
```

### 4. Hot Reload

```bash
kill -HUP $(pgrep phantom-server)
```

---

## Client Compatibility

Phantom uses its own `phantom://` protocol. For immediate compatibility,
Phantom server also accepts standard Trojan clients as a temporary bridge.

| Client | Platform | Native phantom:// | Trojan fallback |
|:---|:---|:---|:---|
| Shadowrocket | iOS | Pending | ✅ |
| NekoBox | Android | Pending | ✅ |
| v2rayN | Windows | Pending | ✅ |
| Clash Meta / Mihomo | All | Pending | ✅ |
| sing-box | All | Pending | ✅ |

> These clients have not yet added native `phantom://` support.
> Trojan compatibility is provided as a temporary bridge in the meantime.
> Client developers are welcome to integrate — see [Protocol Specification](docs/protocol-spec.md).

---

## Documentation

- [Design Document](docs/design.md)
- [Protocol Specification](docs/protocol-spec.md)
- [Philosophy](docs/philosophy.md)

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0) — see [LICENSE](LICENSE).

This is a strong copyleft license. In particular, AGPL §13 extends the
copyleft obligation to network use: if you run a modified version of this
software and let users interact with it over a network, you must make the
modified source available to those users. This is deliberate — it keeps
derivative work in the open rather than allowing it to be folded into a
closed network service.
