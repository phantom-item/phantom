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
	"context"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phantom-item/phantom/internal/config"
	"github.com/phantom-item/phantom/internal/logger"
	"github.com/phantom-item/phantom/internal/protocol"
	"github.com/phantom-item/phantom/internal/socks5"
	"github.com/phantom-item/phantom/internal/transport"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"
)

var log = logger.New()

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	useQUIC := flag.Bool("quic", false, "use QUIC transport")
	configPath := flag.String("config", "config.json", "path to configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		os.Stdout.WriteString("phantom-client " + version + "\n")
		return
	}

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	// QUIC is enabled by either the --quic flag or transport="quic" in
	// config, so a phantom://...?type=quic URI translated into config
	// selects QUIC without needing the flag. The flag remains as a
	// convenient override.
	quicEnabled := *useQUIC || cfg.Client.Transport == "quic"

	if quicEnabled && cfg.Client.Transport == "ws" {
		log.Error("QUIC and transport=ws are mutually exclusive")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", cfg.Client.Socks5Addr)
	if err != nil {
		log.Error("listen socks5", "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	log.Info("socks5 listening", "addr", cfg.Client.Socks5Addr)

	if quicEnabled {
		runQUIC(cfg, ln)
	} else {
		runTCP(cfg, ln)
	}
}

// dialUTLS establishes a TLS connection mimicking a browser fingerprint based on configuration.
// When verify is false, certificate verification is skipped (matches the
// protocol-spec ?allowInsecure=1 use case for IP + self-signed deployments).
// When true, the server certificate is verified against the SNI host as
// usual — operators using a domain + CA cert should leave this enabled.
func dialUTLS(serverAddr string, fingerprint string, verify bool) (net.Conn, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	tcpConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	uConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: !verify,
		NextProtos:         []string{"phantom"},
	}

	var clientHelloID utls.ClientHelloID
	switch fingerprint {
	case "HelloFirefox_Auto":
		clientHelloID = utls.HelloFirefox_Auto
	case "HelloEdge_Auto":
		clientHelloID = utls.HelloEdge_Auto
	case "HelloRandomized":
		clientHelloID = utls.HelloRandomized
	default:
		clientHelloID = utls.HelloChrome_Auto
	}

	uConn := utls.UClient(tcpConn, uConfig, clientHelloID)
	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return uConn, nil
}

func runTCP(cfg *config.Config, ln net.Listener) {
	pool := newSessionPool(
		cfg.Client.SessionPoolSize,
		cfg.Client.SessionGrowthThreshold,
		func() (pooledSession, error) { return dialSmuxSession(cfg) },
	)
	defer pool.Close()

	stop := make(chan struct{})
	defer close(stop)
	go pool.keepAlive(15*time.Second, stop)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept", "err", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			stream, err := pool.OpenStream()
			if err != nil {
				log.Error("open stream", "err", err)
				return
			}
			handleClientConn(c, stream, cfg)
		}(conn)
	}
}

// smuxSession adapts *smux.Session to the pooledSession interface.
type smuxSession struct {
	sess *smux.Session
	// underlying transport conn, closed alongside the session.
	conn    net.Conn
	streams atomic.Int64
}

func (s *smuxSession) OpenStream() (io.ReadWriteCloser, error) {
	st, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	s.streams.Add(1)
	return &countedSmuxStream{Stream: st, parent: s}, nil
}
func (s *smuxSession) Healthy() bool   { return s.sess != nil && !s.sess.IsClosed() }
func (s *smuxSession) NumStreams() int { return int(s.streams.Load()) }
func (s *smuxSession) Close() error {
	if s.sess != nil {
		s.sess.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

// countedSmuxStream decrements the parent's live-stream counter once on Close.
type countedSmuxStream struct {
	*smux.Stream
	parent *smuxSession
	once   sync.Once
}

func (c *countedSmuxStream) Close() error {
	c.once.Do(func() { c.parent.streams.Add(-1) })
	return c.Stream.Close()
}

// dialSmuxSession performs the full uTLS (+ optional WebSocket) + smux
// handshake. It is invoked by the pool with no lock held.
func dialSmuxSession(cfg *config.Config) (pooledSession, error) {
	// 1. Establish the underlying uTLS connection (obfuscates JA3/JA4).
	conn, err := dialUTLS(cfg.Client.ServerAddr, cfg.Client.TLSFingerprint, cfg.Client.VerifyEnabled())
	if err != nil {
		return nil, err
	}

	// 2. If WebSocket transport is enabled, layer it on top.
	if cfg.Client.Transport == "ws" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		wsConn, werr := transport.DialWS(ctx, conn, cfg.Client.ServerAddr, cfg.Client.WSPath)
		cancel()
		if werr != nil {
			conn.Close()
			return nil, werr
		}
		conn = wsConn
	}

	// 3. Bind the smux multiplexer onto the secure tunnel.
	sess, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &smuxSession{sess: sess, conn: conn}, nil
}

func runQUIC(cfg *config.Config, ln net.Listener) {
	pool := newSessionPool(
		cfg.Client.SessionPoolSize,
		cfg.Client.SessionGrowthThreshold,
		func() (pooledSession, error) { return dialQUICSession(cfg) },
	)
	defer pool.Close()

	stop := make(chan struct{})
	defer close(stop)
	go pool.keepAlive(15*time.Second, stop)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept", "err", err)
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			stream, err := pool.OpenStream()
			if err != nil {
				log.Error("open quic stream", "err", err)
				return
			}
			handleClientConn(c, stream, cfg)
		}(conn)
	}
}

// quicSession adapts a *quic.Conn to the pooledSession interface, tracking the
// number of live streams it has opened so the pool can make growth decisions.
type quicSession struct {
	conn    *quic.Conn
	streams atomic.Int64
}

func (s *quicSession) OpenStream() (io.ReadWriteCloser, error) {
	st, err := s.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	s.streams.Add(1)
	return &countedStream{Stream: st, parent: s}, nil
}
func (s *quicSession) Healthy() bool   { return s.conn != nil && s.conn.Context().Err() == nil }
func (s *quicSession) NumStreams() int { return int(s.streams.Load()) }
func (s *quicSession) Close() error {
	if s.conn != nil {
		return s.conn.CloseWithError(0, "")
	}
	return nil
}

// countedStream decrements its parent session's stream counter exactly once,
// on first Close, so NumStreams() reflects live streams.
type countedStream struct {
	*quic.Stream
	parent *quicSession
	once   sync.Once
}

func (c *countedStream) Close() error {
	c.once.Do(func() { c.parent.streams.Add(-1) })
	return c.Stream.Close()
}

func dialQUICSession(cfg *config.Config) (pooledSession, error) {
	qc, err := newQUICSession(cfg)
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: qc}, nil
}

func newQUICSession(cfg *config.Config) (*quic.Conn, error) {
	tlsCfg := &tls.Config{
		// Honour the per-client verify toggle. Same trade-off as dialUTLS:
		// for IP + self-signed deployments verify must be false; for
		// domain + CA cert deployments it should stay true.
		InsecureSkipVerify: !cfg.Client.VerifyEnabled(),
		NextProtos:         []string{"phantom"},
		MinVersion:         tls.VersionTLS13,
	}
	// When verifying, derive ServerName from server_addr so the cert's
	// SNI / Subject Alt Name is matched against the host the user typed.
	if cfg.Client.VerifyEnabled() {
		if host, _, err := net.SplitHostPort(cfg.Client.ServerAddr); err == nil {
			tlsCfg.ServerName = host
		} else {
			tlsCfg.ServerName = cfg.Client.ServerAddr
		}
	}
	qc, err := transport.DialQUIC(cfg.Client.ServerAddr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return qc, nil
}

// handleClientConn services one accepted SOCKS5 connection over a stream that
// the pool has already opened. It owns the stream's lifecycle. The transport
// (TCP/smux, WS, QUIC) is irrelevant here — the stream is just a duplex pipe.
func handleClientConn(conn net.Conn, stream io.ReadWriteCloser, cfg *config.Config) {
	defer stream.Close()

	req, err := socks5.Handshake(conn)
	if err != nil {
		log.Error("socks5 handshake", "err", err)
		return
	}

	cmdHost := req.Host
	cmdPort := req.Port
	cmd := byte(protocol.CmdConnect)
	if req.IsUDP {
		cmdHost = "0.0.0.0"
		cmdPort = 0
		cmd = protocol.CmdUDP
	}

	addr, err := protocol.ResolveAddress(cmdHost, cmdPort)
	if err != nil {
		log.Error("resolve target address", "err", err)
		return
	}

	header := &protocol.Header{
		PasswordHash: protocol.HashPassword(cfg.Client.Password),
		Request: protocol.Request{
			Command: cmd,
			Address: addr,
		},
	}

	if err := protocol.WriteHeader(stream, header); err != nil {
		log.Error("write header", "err", err)
		return
	}

	if req.IsUDP {
		log.Info("udp associate", "client", conn.RemoteAddr())
		handleUDP(conn, stream)
		return
	}

	log.Info("relay", "host", req.Host, "port", req.Port)
	relay(conn, stream)
}

func handleUDP(tcpConn net.Conn, stream io.ReadWriter) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Error("resolve local udp addr", "err", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Error("listen local udp", "err", err)
		return
	}
	defer udpConn.Close()

	// Closing the tunnel stream on exit guarantees the inbound
	// ReadUDPPacket goroutine below unblocks promptly rather than
	// lingering on a blocked read until the parent's deferred
	// stream.Close() eventually fires.
	if sc, ok := stream.(io.Closer); ok {
		defer sc.Close()
	}

	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	if err := socks5.SendReply(tcpConn, socks5.RepSuccess, "127.0.0.1", uint16(localPort)); err != nil {
		log.Error("send socks5 udp reply", "err", err)
		return
	}

	done := make(chan struct{}, 2)
	var clientUDPAddr *net.UDPAddr
	var mu sync.Mutex

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			clientUDPAddr = addr
			mu.Unlock()

			socksReq, err := socks5.ParseUDPHeader(buf[:n])
			if err != nil {
				continue
			}
			// The peer's ReadUDPPacket rejects payloads above
			// MaxUDPPayloadLength and treats that as a fatal stream
			// error. Drop the single oversized datagram here rather
			// than framing it and killing the entire UDP session.
			if len(socksReq.Payload) > protocol.MaxUDPPayloadLength {
				log.Warn("dropping oversized udp datagram", "size", len(socksReq.Payload), "max", protocol.MaxUDPPayloadLength)
				continue
			}
			if err := protocol.WriteUDPPacket(stream, socksReq.Host, socksReq.Port, socksReq.Payload); err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			pkt, err := protocol.ReadUDPPacket(stream)
			if err != nil {
				return
			}
			mu.Lock()
			cAddr := clientUDPAddr
			mu.Unlock()
			if cAddr == nil {
				continue
			}
			socksPacket, err := socks5.NewUDPResponseHeader(pkt.Address.Host, pkt.Address.Port, pkt.Payload)
			if err != nil {
				continue
			}
			_, _ = udpConn.WriteToUDP(socksPacket, cAddr)
		}
	}()

	go func() {
		discardBuf := make([]byte, 1024)
		for {
			_, err := tcpConn.Read(discardBuf)
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()

	<-done
}

func relay(a, b io.ReadWriter) {
	// Wait for BOTH directions to complete so neither is truncated when
	// the caller's deferred Close fires. On finishing one direction,
	// half-close the peer's write side (when supported) so it observes
	// EOF and the second copy can drain.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
}
