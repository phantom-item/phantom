package benchmark

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/phantom-item/phantom/internal/transport"
)

func BenchmarkTCPRelay(b *testing.B) {
	cert, _ := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	server, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		session, err := transport.AcceptMuxSession(conn)
		if err != nil {
			return
		}
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(stream, stream)
		}
	}()

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), clientTLS)
	if err != nil {
		b.Fatal(err)
	}
	session, err := transport.NewMuxSession(conn)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 32*1024) // 32KB

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream, err := session.OpenStream()
		if err != nil {
			b.Fatal(err)
		}

		start := time.Now()
		stream.Write(payload)
		buf := make([]byte, len(payload))
		io.ReadFull(stream, buf)
		_ = time.Since(start)

		stream.Close()
	}
}

func BenchmarkQUICRelay(b *testing.B) {
	b.Skip("QUIC loopback benchmark skipped")
}

func BenchmarkConcurrentStreams(b *testing.B) {
	cert, _ := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	server, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		session, err := transport.AcceptMuxSession(conn)
		if err != nil {
			return
		}
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(stream, stream)
		}
	}()

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), clientTLS)
	if err != nil {
		b.Fatal(err)
	}
	session, err := transport.NewMuxSession(conn)
	if err != nil {
		b.Fatal(err)
	}

	payload := make([]byte, 1024) // 1KB

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stream, err := session.OpenStream()
			if err != nil {
				b.Error(err)
				return
			}
			stream.Write(payload)
			buf := make([]byte, len(payload))
			io.ReadFull(stream, buf)
			stream.Close()
		}
	})
}

func BenchmarkLatency(b *testing.B) {
	cert, _ := tls.LoadX509KeyPair("../../server.crt", "../../server.key")
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	server, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		session, err := transport.AcceptMuxSession(conn)
		if err != nil {
			return
		}
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go func(s net.Conn) {
				buf := make([]byte, 1)
				s.Read(buf)
				s.Write(buf)
				s.Close()
			}(stream)
		}
	}()

	clientTLS := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", server.Addr().String(), clientTLS)
	if err != nil {
		b.Fatal(err)
	}
	session, err := transport.NewMuxSession(conn)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream, err := session.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		stream.Write([]byte{1})
		buf := make([]byte, 1)
		io.ReadFull(stream, buf)
		stream.Close()
	}
}
