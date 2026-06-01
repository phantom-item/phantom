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
	"bufio"
	"crypto/tls"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/phantom-item/phantom/internal/auth"
	"github.com/phantom-item/phantom/internal/config"
	"github.com/phantom-item/phantom/internal/logger"
	"github.com/phantom-item/phantom/internal/metrics"
	"github.com/phantom-item/phantom/internal/protocol"
	"github.com/phantom-item/phantom/internal/transport"
)

var log *slog.Logger

func main() {
	useQUIC := flag.Bool("quic", false, "use QUIC transport")
	configPath := flag.String("config", "config.json", "path to configuration file")
	flag.Parse()

	log = logger.New()

	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	// Sanity check: --quic and transport=ws are mutually exclusive
	if *useQUIC && cfg.Server.Transport == "ws" {
		log.Error("--quic flag cannot be combined with transport=ws in config")
		os.Exit(1)
	}

	cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		log.Error("load cert", "err", err)
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"phantom", "http/1.1"},
	}

	var ln net.Listener
	if *useQUIC {
		ql, err := transport.ListenQUIC(cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen quic", "err", err)
			os.Exit(1)
		}
		ln = ql
		log.Info("listening on QUIC", "addr", cfg.Server.Listen)
	} else {
		ln, err = tls.Listen("tcp", cfg.Server.Listen, tlsCfg)
		if err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
		log.Info("listening on TCP", "addr", cfg.Server.Listen)
	}

	authenticator := auth.NewStaticAuth(cfg.Server.Passwords)

	limiter := auth.NewRateLimiter(20, 5*time.Minute, 5*time.Minute)
	defer limiter.Close()

	m := metrics.New()

	var wg sync.WaitGroup

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for {
			s := <-sig
			switch s {
			case syscall.SIGHUP:
				log.Info("received SIGHUP, reloading configuration")
				newCfg, err := config.LoadFromFile(*configPath)
				if err != nil {
					log.Error("reload config failed", "err", err)
					continue
				}
				if newCfg.Server.Listen != cfg.Server.Listen {
					log.Warn("listen address change requires restart", "current", cfg.Server.Listen, "ignored", newCfg.Server.Listen)
				}
				if newCfg.Server.FallbackAddr != cfg.Server.FallbackAddr {
					cfg.Server.FallbackAddr = newCfg.Server.FallbackAddr
				}
				authenticator.Reload(newCfg.Server.Passwords)
				for hash, stats := range m.Snapshot() {
					log.Info("user stats", "hash", hash[:8], "sent", stats[0], "recv", stats[1])
				}
				log.Info("config reloaded")

			default:
				for hash, stats := range m.Snapshot() {
					log.Info("user stats", "hash", hash[:8], "sent", stats[0], "recv", stats[1])
				}
				log.Info("shutting down")
				ln.Close()
				return
			}
		}
	}()

	if cfg.Server.Transport == "ws" {
		log.Info("starting WebSocket mode", "path", cfg.Server.WSPath)

		var fallbackProxy *httputil.ReverseProxy
		if cfg.Server.FallbackAddr != "" {
			fallbackAddr := cfg.Server.FallbackAddr
			// Tolerate user input with or without scheme prefix
			if !strings.HasPrefix(fallbackAddr, "http://") && !strings.HasPrefix(fallbackAddr, "https://") {
				fallbackAddr = "http://" + fallbackAddr
			}
			fallbackURL, err := url.Parse(fallbackAddr)
			if err != nil {
				log.Error("parse fallback addr", "err", err)
				os.Exit(1)
			}
			fallbackProxy = httputil.NewSingleHostReverseProxy(fallbackURL)
		}

		mux := http.NewServeMux()

		mux.HandleFunc(cfg.Server.WSPath, func(w http.ResponseWriter, r *http.Request) {
			wsConn, err := transport.AcceptWS(w, r, cfg.Server.TrustProxyHeaders)
			if err != nil {
				log.Error("websocket accept failed", "err", err)
				return
			}

			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleSession(c, authenticator, limiter, cfg.Server.FallbackAddr, m)
			}(wsConn)
		})

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if fallbackProxy != nil {
				fallbackProxy.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		})

		server := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		_ = server.Serve(ln)
	} else {
		for {
			conn, err := ln.Accept()
			if err != nil {
				break
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleSession(c, authenticator, limiter, cfg.Server.FallbackAddr, m)
			}(conn)
		}
	}

	wg.Wait()
	log.Info("shutdown complete")
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func handleSession(conn net.Conn, authenticator auth.Authenticator, limiter *auth.RateLimiter, fallbackAddr string, m *metrics.Metrics) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()

	if limiter.IsBanned(remoteAddr) {
		log.Warn("banned IP attempted connection, falling back", "addr", remoteAddr)
		doFallback(conn, remoteAddr, fallbackAddr)
		return
	}

	if qconn, ok := conn.(*transport.QUICNetConn); ok {
		streams, _ := transport.AcceptQUICStreams(qconn.Conn)
		for stream := range streams {
			go handleConn(stream, authenticator, limiter, fallbackAddr, m)
		}
		return
	}

	rconn := transport.NewRewindConn(conn)
	rconn.SetDeadline(time.Now().Add(10 * time.Second))

	header, err := protocol.ParseHeader(rconn)
	if err == nil {
		rconn.SetDeadline(time.Time{})
		if !authenticator.Verify(header.PasswordHash) {
			limiter.RecordFailure(remoteAddr)
			rconn.Rewind()
			doFallback(rconn, remoteAddr, fallbackAddr)
			return
		}
		limiter.RecordSuccess(remoteAddr)
		dispatchConn(rconn, header, m)
		return
	}

	rconn.Rewind()
	rconn.SetDeadline(time.Time{})

	bufReader := bufio.NewReader(rconn)
	firstByte, peekErr := bufReader.Peek(1)
	if peekErr != nil || len(firstByte) == 0 {
		return
	}

	bufConn := &bufferedConn{Conn: rconn, reader: bufReader}

	if firstByte[0] != 0x01 {
		doFallback(bufConn, remoteAddr, fallbackAddr)
		return
	}

	session, err := transport.AcceptMuxSession(bufConn)
	if err != nil {
		doFallback(bufConn, remoteAddr, fallbackAddr)
		return
	}
	defer session.Close()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			break
		}
		go handleConn(stream, authenticator, limiter, fallbackAddr, m)
	}
}

func handleConn(conn net.Conn, authenticator auth.Authenticator, limiter *auth.RateLimiter, fallbackAddr string, m *metrics.Metrics) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()

	if limiter.IsBanned(remoteAddr) {
		doFallback(conn, remoteAddr, fallbackAddr)
		return
	}

	rconn := transport.NewRewindConn(conn)
	rconn.SetDeadline(time.Now().Add(10 * time.Second))

	header, err := protocol.ParseHeader(rconn)
	validAuth := err == nil && authenticator.Verify(header.PasswordHash)

	if !validAuth {
		if err == nil {
			limiter.RecordFailure(remoteAddr)
		}
		rconn.Rewind()
		rconn.SetDeadline(time.Time{})
		doFallback(rconn, remoteAddr, fallbackAddr)
		return
	}

	limiter.RecordSuccess(remoteAddr)

	rconn.SetDeadline(time.Time{})
	dispatchConn(rconn, header, m)
}

func dispatchConn(conn net.Conn, header *protocol.Header, m *metrics.Metrics) {
	stats := m.GetOrCreate(header.PasswordHash)

	if header.Request.Command == protocol.CmdUDP {
		log.Info("udp relay", "target", header.Request.Address.String())
		handleUDPRelay(conn)
		return
	}

	target := header.Request.Address.String()
	log.Info("relay", "target", target, "user", header.PasswordHash[:8])

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	remote, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Error("dial target", "err", err, "target", target)
		return
	}
	defer remote.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Minute))
	remote.SetDeadline(time.Now().Add(5 * time.Minute))

	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(remote, conn)
		stats.Sent.Add(uint64(n))
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(conn, remote)
		stats.Received.Add(uint64(n))
		done <- struct{}{}
	}()
	<-done
}

func doFallback(conn net.Conn, remoteAddr net.Addr, fallbackAddr string) {
	if fallbackAddr == "" {
		return
	}

	remote, err := net.Dial("tcp", fallbackAddr)
	if err != nil {
		log.Error("fallback dial", "err", err)
		return
	}
	defer remote.Close()

	log.Info("fallback connection", "from", remoteAddr)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, remote)
		done <- struct{}{}
	}()
	<-done
}

func handleUDPRelay(stream io.ReadWriter) {
	// sessions: target-string -> outbound UDP socket.
	//
	// Concurrency invariant: this map is touched ONLY by the main read
	// loop below. The per-target goroutines spawned at line ~410 do
	// NOT access sessions — they hold a captured *net.UDPConn pointer
	// in their closure. As long as that invariant holds the map needs
	// no mutex. If a future change adds a second writer (e.g. eviction
	// based on idle timeout), add sync.Mutex and protect every access.
	sessions := make(map[string]*net.UDPConn)
	defer func() {
		for _, conn := range sessions {
			conn.Close()
		}
	}()

	if c, ok := stream.(net.Conn); ok {
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
	}

	for {
		pkt, err := protocol.ReadUDPPacket(stream)
		if err != nil {
			return
		}

		if c, ok := stream.(net.Conn); ok {
			c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		}

		target := pkt.Address.String()
		udpConn, exists := sessions[target]

		if !exists {
			udpAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				log.Error("resolve udp target", "err", err)
				continue
			}
			udpConn, err = net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				log.Error("dial udp target", "err", err)
				continue
			}
			sessions[target] = udpConn

			go func(uConn *net.UDPConn, host string, port uint16) {
				buf := make([]byte, 65535)
				for {
					uConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := uConn.Read(buf)
					if err != nil {
						return
					}
					if err := protocol.WriteUDPPacket(stream, host, port, buf[:n]); err != nil {
						return
					}
				}
			}(udpConn, pkt.Address.Host, pkt.Address.Port)
		}

		_, err = udpConn.Write(pkt.Payload)
		if err != nil {
			log.Error("write to udp target", "err", err)
			udpConn.Close()
			delete(sessions, target)
		}
	}
}
