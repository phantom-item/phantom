package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICListener implements net.Listener around a *quic.Listener.
//
// quic-go's Conn, Stream and Listener types embed locks and an internal
// noCopy marker, so they must never be copied by value. Everything here
// holds pointers (*quic.Conn, *quic.Stream, *quic.Listener) accordingly.
type QUICListener struct {
	ln *quic.Listener
}

// Accept accepts an incoming QUIC connection and wraps it into a net.Conn
// compatible *QUICNetConn.
func (l *QUICListener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	return &QUICNetConn{Conn: conn}, nil
}

// Addr returns the listener's network address.
func (l *QUICListener) Addr() net.Addr {
	return l.ln.Addr()
}

// Close closes the underlying QUIC listener.
func (l *QUICListener) Close() error {
	return l.ln.Close()
}

// QUICNetConn wraps a *quic.Conn to implement the net.Conn interface so a
// QUIC session can flow through the same routing as TCP connections.
type QUICNetConn struct {
	Conn *quic.Conn
}

// Read is a placeholder to satisfy net.Conn. Real data transfer uses
// OpenStream/AcceptStream on the embedded connection.
func (c *QUICNetConn) Read(b []byte) (int, error) { return 0, nil }

// Write is a placeholder to satisfy net.Conn. Real data transfer uses
// OpenStream/AcceptStream on the embedded connection.
func (c *QUICNetConn) Write(b []byte) (int, error) { return 0, nil }

// Close closes the underlying QUIC connection session.
func (c *QUICNetConn) Close() error {
	return c.Conn.CloseWithError(0, "")
}

// LocalAddr returns the local network address.
func (c *QUICNetConn) LocalAddr() net.Addr { return c.Conn.LocalAddr() }

// RemoteAddr returns the remote network address.
func (c *QUICNetConn) RemoteAddr() net.Addr { return c.Conn.RemoteAddr() }

func (c *QUICNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *QUICNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *QUICNetConn) SetWriteDeadline(t time.Time) error { return nil }

// QUICStreamConn wraps a *quic.Stream as net.Conn for unified routing into
// handleConn. Stream deadlines are real (unlike the session-level conn).
type QUICStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (c *QUICStreamConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *QUICStreamConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *QUICStreamConn) Close() error                { return c.stream.Close() }

func (c *QUICStreamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *QUICStreamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *QUICStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *QUICStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *QUICStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// DialQUIC establishes a client-side QUIC connection and returns the
// *quic.Conn session.
func DialQUIC(addr string, tlsCfg *tls.Config) (*quic.Conn, error) {
	conn, err := quic.DialAddr(context.Background(), addr, tlsCfg, &quic.Config{})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenQUIC starts a server-side QUIC listener.
func ListenQUIC(addr string, tlsCfg *tls.Config) (*QUICListener, error) {
	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{})
	if err != nil {
		return nil, err
	}
	return &QUICListener{ln: ln}, nil
}

// AcceptQUICStreams loops, wraps incoming multiplexed streams into net.Conn,
// and pushes them to the returned channel. The channel closes when the
// connection is torn down.
func AcceptQUICStreams(conn *quic.Conn) chan net.Conn {
	streams := make(chan net.Conn, 100)
	go func() {
		defer close(streams)
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			streams <- &QUICStreamConn{stream: stream, conn: conn}
		}
	}()
	return streams
}
