package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICListener implements the net.Listener interface wrapped around a quic.Listener struct value.
type QUICListener struct {
	quic.Listener
}

// Accept accepts an incoming QUIC connection and wraps it into a net.Conn compatible QUICNetConn.
func (l *QUICListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	// conn is a pointer (*quic.Conn), dereference it to fit the struct field
	return &QUICNetConn{Conn: *conn}, nil
}

// Addr returns the listener's network address.
func (l *QUICListener) Addr() net.Addr {
	return l.Listener.Addr()
}

// QUICNetConn wraps a quic.Conn struct to implement the net.Conn interface.
type QUICNetConn struct {
	quic.Conn
}

// Read is a dummy implementation to satisfy net.Conn. Real data transfer should utilize OpenStream/AcceptStream.
func (c *QUICNetConn) Read(b []byte) (int, error) {
	return 0, nil
}

// Write is a dummy implementation to satisfy net.Conn. Real data transfer should utilize OpenStream/AcceptStream.
func (c *QUICNetConn) Write(b []byte) (int, error) {
	return 0, nil
}

// Close closes the underlying QUIC connection session.
func (c *QUICNetConn) Close() error {
	return c.Conn.CloseWithError(0, "")
}

// LocalAddr returns the local network address.
func (c *QUICNetConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *QUICNetConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *QUICNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *QUICNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *QUICNetConn) SetWriteDeadline(t time.Time) error { return nil }

// QUICStreamConn wraps quic.Stream struct value as net.Conn for unified routing down into handleConn.
type QUICStreamConn struct {
	quic.Stream
	conn quic.Conn
}

func (c *QUICStreamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *QUICStreamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *QUICStreamConn) SetDeadline(t time.Time) error      { return c.Stream.SetDeadline(t) }
func (c *QUICStreamConn) SetReadDeadline(t time.Time) error  { return c.Stream.SetReadDeadline(t) }
func (c *QUICStreamConn) SetWriteDeadline(t time.Time) error { return c.Stream.SetWriteDeadline(t) }

// DialQUIC establishes a client-side QUIC connection session and returns a quic.Conn struct value.
func DialQUIC(addr string, tlsCfg *tls.Config) (quic.Conn, error) {
	conn, err := quic.DialAddr(context.Background(), addr, tlsCfg, &quic.Config{})
	if err != nil {
		return quic.Conn{}, err
	}
	// conn is a pointer (*quic.Conn), dereference it to return the struct value
	return *conn, nil
}

// ListenQUIC starts a server-side QUIC listener wrapped inside the QUICListener struct.
func ListenQUIC(addr string, tlsCfg *tls.Config) (*QUICListener, error) {
	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{})
	if err != nil {
		return nil, err
	}
	// Dereference the pointer *ln since the embedded field is a struct value
	return &QUICListener{Listener: *ln}, nil
}

// QUICConnToNet wraps a raw quic.Conn struct value into a *QUICNetConn for server-side type assertions.
func QUICConnToNet(conn quic.Conn) *QUICNetConn {
	return &QUICNetConn{Conn: conn}
}

// AcceptQUICStreams loops, wraps incoming multiplexed streams into net.Conn, and pushes them to the channel.
func AcceptQUICStreams(conn quic.Conn) (chan net.Conn, error) {
	streams := make(chan net.Conn, 100)
	go func() {
		defer close(streams)
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			// stream is a pointer (*quic.Stream), dereference it into the QUICStreamConn wrapper struct
			streams <- &QUICStreamConn{Stream: *stream, conn: conn}
		}
	}()
	return streams, nil
}
