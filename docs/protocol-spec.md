# Phantom Protocol Specification

**Version**: 0.1
**Status**: Draft
**Last Updated**: 2026-05-23

---

## URI Format

```
phantom://password@host:port?params
```

### Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `type` | `tcp`, `quic` | Transport layer mode |
| `security` | `tls` | Transport security (always enabled) |
| `sni` | string | TLS SNI (Server Name Indication) hostname |
| `allowInsecure` | `0`, `1` | Skip TLS certificate verification (`1` = skip) |
| `fp` | `chrome`, `firefox`, `random` | TLS Client Hello fingerprint mimicking |

### Examples

**TCP mode with domain name:**
```
phantom://mypassword@example.com:443?type=tcp&security=tls&sni=example.com
```

**QUIC mode with domain name:**
```
phantom://mypassword@example.com:443?type=quic&security=tls&sni=example.com
```

**TCP mode with direct IP (self-signed certificate):**
```
phantom://mypassword@1.2.3.4:443?type=tcp&security=tls&allowInsecure=1
```

---

## Wire Format

### TCP Request Header

```
[56 bytes SHA224(password) hex] CRLF
[CMD 1 byte] [ATYP 1 byte] [DST.ADDR] [DST.PORT 2 bytes] CRLF
[Payload...]
```

### CMD Values

| Value | Description |
|-------|-------------|
| `0x01` | `CONNECT` — TCP tunnel relay |
| `0x03` | `UDP ASSOCIATE` — UDP packet tunneling |

### ATYP Values

| Value | Description |
|-------|-------------|
| `0x01` | IPv4 address (4 bytes raw) |
| `0x03` | Domain name (1 byte length prefix + N bytes string) |
| `0x04` | IPv6 address (16 bytes raw) |

### UDP Packet Format

```
[ATYP 1 byte] [DST.ADDR] [DST.PORT 2 bytes]
[Length 2 bytes] CRLF [Payload...]
```

> **Security Note**: The `Length` field is a 16-bit unsigned integer (Big-Endian).
> The protocol's hard upper bound is therefore 65535, but a reference
> implementation should reject packets above a conservative limit
> (Phantom uses 9000 bytes, slightly above standard jumbo frame size)
> to prevent per-packet memory amplification.

---

## Anti-Probe Behavior

An invalid password hash or malformed handshake header triggers an immediate backend
redirection. The incoming connection **MUST NOT** be abruptly reset. Instead, all
subsequent raw bytes are replayed transparently to a preconfigured fallback backend
(e.g., a legitimate web server) to mitigate active-probing detection.

---

## Ecosystem Integration Drafts

> These are draft configuration examples intended to assist third-party tool maintainers
> in implementing Phantom protocol support. They are not yet officially supported.

### sing-box

```json
{
 "type": "phantom",
 "server": "example.com",
 "server_port": 443,
 "password": "yourpassword",
 "tls": {
   "enabled": true,
   "server_name": "example.com"
 },
 "transport": {
   "type": "tcp"
 }
}
```

### Xray

```json
{
 "protocol": "phantom",
 "settings": {
   "servers": [
     {
       "address": "example.com",
       "port": 443,
       "password": "yourpassword"
     }
   ]
 },
 "streamSettings": {
   "network": "tcp",
   "security": "tls"
 }
}
```
