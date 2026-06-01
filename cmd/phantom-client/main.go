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
	"fmt"
	"io"
	"net"
	"os"
	"sync"
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

func main() {
	useQUIC := flag.Bool("quic", false, "use QUIC transport")
	configPath := flag.String("config", "config.json", "path to configuration file")
	flag.Parse()

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	// Sanity check: --quic and transport=ws are mutually exclusive
	if *useQUIC && cfg.Client.Transport == "ws" {
		log.Error("--quic flag cannot be combined with transport=ws in config")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", cfg.Client.Socks5Addr)
	if err != nil {
		log.Error("listen socks5", "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	log.Info("socks5 listening", "addr", cfg.Client.Socks5Addr)

	if *useQUIC {
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
	// Pass the transport configuration down to the reusable session pool
	pool := newTCPPool(cfg)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept", "err", err)
			continue
		}

		go func(c net.Conn) {
			session, err := pool.GetSession()
			if err != nil {
				log.Error("get session", "err", err)
				c.Close()
				return
			}
			handleTCPConn(c, session, cfg)
		}(conn)
	}
}

// tcpPool manages a reusable smux session over a uTLS (+ optional WebSocket) connection.
type tcpPool struct {
	mu      sync.Mutex
	config  *config.Config
	session *smux.Session
}

func newTCPPool(cfg *config.Config) *tcpPool {
	return &tcpPool{config: cfg}
}

func (p *tcpPool) GetSession() (*smux.Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.session != nil && !p.session.IsClosed() {
		return p.session, nil
	}

	// 1. Establish the underlying uTLS connection first (obfuscates JA3/JA4 fingerprint)
	conn, err := dialUTLS(p.config.Client.ServerAddr, p.config.Client.TLSFingerprint, p.config.Client.VerifyEnabled())
	if err != nil {
		return nil, err
	}

	// 2. If WebSocket transport is enabled, layer it on top of the uTLS connection
	if p.config.Client.Transport == "ws" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		wsConn, err := transport.DialWS(ctx, conn, p.config.Client.ServerAddr, p.config.Client.WSPath)
		cancel()
		if err != nil {
			return nil, err
		}
		conn = wsConn // Seamlessly swap the connection descriptor
	}

	// 3. Bind the smux multiplexer onto the established secure tunnel
	sess, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {
		conn.Close()
		return nil, err
	}

	p.session = sess
	return sess, nil
}

func runQUIC(cfg *config.Config, ln net.Listener) {
	var mu sync.Mutex
	var qconn quic.Conn
	var err error

	qconn, err = newQUICSession(cfg)
	if err != nil {
		log.Error("create quic session", "err", err)
		os.Exit(1)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("accept", "err", err)
			continue
		}

		mu.Lock()
		if qconn.Context().Err() != nil {
			qconn, err = newQUICSession(cfg)
			if err != nil {
				mu.Unlock()
				log.Error("recreate quic session", "err", err)
				conn.Close()
				continue
			}
		}
		currentQconn := qconn
		mu.Unlock()

		go handleQUICConn(conn, currentQconn, cfg)
	}
}

func newQUICSession(cfg *config.Config) (quic.Conn, error) {
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
		return quic.Conn{}, err
	}
	return qc, nil
}

func handleTCPConn(conn net.Conn, session *smux.Session, cfg *config.Config) {
	defer conn.Close()

	req, err := socks5.Handshake(conn)
	if err != nil {
		log.Error("socks5 handshake", "err", err)
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		log.Error("open stream", "err", err)
		return
	}
	defer stream.Close()

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
		log.Info("udp associate tcp-mux", "client", conn.RemoteAddr())
		handleUDP(conn, stream)
		return
	}

	log.Info("relay tcp", "host", req.Host, "port", req.Port)
	relay(conn, stream)
}

func handleQUICConn(conn net.Conn, qconn quic.Conn, cfg *config.Config) {
	defer conn.Close()

	req, err := socks5.Handshake(conn)
	if err != nil {
		log.Error("socks5 handshake", "err", err)
		return
	}

	stream, err := qconn.OpenStream()
	if err != nil {
		log.Error("open quic stream", "err", err)
		return
	}
	defer stream.Close()

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
		log.Info("udp associate quic", "client", conn.RemoteAddr())
		handleUDP(conn, stream)
		return
	}

	log.Info("relay quic", "host", req.Host, "port", req.Port)
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

	_, localPortStr, _ := net.SplitHostPort(udpConn.LocalAddr().String())
	var lp int
	fmt.Sscanf(localPortStr, "%d", &lp)

	if err := socks5.SendReply(tcpConn, socks5.RepSuccess, "127.0.0.1", uint16(lp)); err != nil {
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
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
}

var _ = context.Background
