# Phantom Design Document

## Status

Experimental. Not recommended for production use without thorough review.

## Overview

Phantom is a modern encrypted transport framework with its own `phantom://` protocol,
built for performance, security, and clean architecture. It provides Trojan protocol
compatibility as a temporary bridge for existing clients, while establishing its own
independent protocol identity.

## Architecture

<pre><code>Client Side:
[ Application ] -> SOCKS5 -> [ phantom-client ]
                                      |
                            (TLS / QUIC Transport)
                                      v
[ phantom-server ] &lt;- [ Auth ] -> [ TCP/UDP Relay ] -> [ Target ]
        |                (Invalid Auth)
        v
[ Fallback Addr ] (e.g., Nginx)</code></pre>

### Session Lifecycle & Multiplexing

- **TCP Mode**: The client multiplexes multiple logical streams over a single underlying TLS connection using smux (MuxSession). This eliminates TCP 3-way handshake overhead for individual connections.
- **QUIC Mode**: The client leverages native QUIC streams directly over a single QUIC connection, benefiting from built-in 0-RTT handshakes and head-of-line blocking elimination.

## Layers

### Protocol Layer (<code>internal/protocol</code>)

- Parses and writes Trojan wire format.
- Handles TCP CONNECT and UDP ASSOCIATE commands.
- Completely decoupled from auth and transport layers to allow independent testing.

### Auth Layer (<code>internal/auth</code>)

- Password hashing via SHA224.
- Multi-user support via hash map.
- Thread-safe runtime configuration hot reload via <code>sync.RWMutex</code>.

### Transport Layer (<code>internal/transport</code>)

- **RewindConn**: Buffers the initial read operations during parsing. If the request proves to be an unauthorized active probe, the buffer is rewound, and the raw payload is replayed seamlessly to the fallback address.
- **MuxSession**: smux-based stream multiplexing over a secure TCP connection.
- **QUICListener / DialQUIC**: Native QUIC transport mapping QUIC streams to proxy sub-connections.
- **SessionPool**: Manages active connections on the client side with automatic connection state checking and seamless reconnection.

### SOCKS5 Layer (<code>internal/socks5</code>)

- Handles client-side SOCKS5 CONNECT and UDP ASSOCIATE requests.
- Parses and encapsulates standard SOCKS5 UDP framing into Trojan UDP packets.

### Metrics Layer (<code>internal/metrics</code>)

- Real-time, per-user traffic accounting tracking sent and received bytes.
- Utilizes lock-free <code>sync/atomic</code> counters to guarantee zero contention under high-throughput concurrency.
- Dumps comprehensive accounting metrics to logs upon receiving SIGHUP and during graceful shutdown.

## Transport Modes

| Mode | Command | Notes |
| :--- | :--- | :--- |
| TCP + smux | ./phantom-server | Default mode. Highly stable, bypasses restrictive UDP firewalls. |
| QUIC + streams | ./phantom-server --quic | Optimized for lossy networks. Zero head-of-line blocking, lower latency. |

## Anti-Probe Design

- **Zero-Footprint Fallback**: When an invalid password or non-Trojan payload is detected, phantom-server immediately rewinds the connection and pipes the raw data directly to <code>FallbackAddr</code> (e.g., a local Nginx server).
- **Behavioral Consistency**: The probe connection is fully handed over to the fallback server without closing or resetting prematurely. To any external scanner, the server behaves identically to a normal HTTPS server.
- **Dynamic Config Reload**: Upon receiving a SIGHUP signal, the server re-reads <code>config.json</code> to apply user credential changes dynamically via <code>Auth.Reload()</code> without breaking active sessions or dropping the listening socket.

## Non-Goals

- Region-specific censorship evasion logic or active obfuscation layers.
- Built-in traffic routing rules, ACLs, or domain-based switching.
- Commercial panel integrations, user billing APIs, or multi-node cluster management.
- Video streaming unlock optimizations or residential IP proxy routing.
