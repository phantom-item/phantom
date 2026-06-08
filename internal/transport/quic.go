package transport

import (
	"context"
	"crypto/tls"
	"errors"
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

// errNoStreamIO is returned by QUICNetConn.Read/Write. A QUICNetConn
// represents the session, not a byte stream — all real I/O happens on streams
// obtained via OpenStream/AcceptStream. Returning (0, nil) from Read would
// violate the io.Reader contract: io.Copy and io.ReadFull treat a (0, nil)
// read as "try again" and spin at 100% CPU forever. Returning a non-nil error
// makes any accidental stream-level use fail loudly instead.
var errNoStreamIO = errors.New("quic: QUICNetConn is a session, not a byte stream; use OpenStream/AcceptStream")

// Read always errors: a session carries no bytes of its own. See errNoStreamIO.
func (c *QUICNetConn) Read(b []byte) (int, error) { return 0, errNoStreamIO }

// Write always errors: a session carries no bytes of its own. See errNoStreamIO.
func (c *QUICNetConn) Write(b []byte) (int, error) { return 0, errNoStreamIO }

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

// quicConfig is shared by the dialer and listener so both ends agree on
// keep-alive and stream limits. Without KeepAlivePeriod an idle tunnel is
// silently dropped by NAT/firewall middleboxes after ~30s, which on the
// client surfaces as the session being torn down between requests. The
// raised MaxIncomingStreams keeps a busy multiplexed client from stalling
// once it exceeds quic-go's conservative default stream budget.
func quicConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:    15 * time.Second,
		MaxIncomingStreams: 1024,
	}
}

// DialQUIC establishes a client-side QUIC connection and returns the
// *quic.Conn session.
func DialQUIC(addr string, tlsCfg *tls.Config) (*quic.Conn, error) {
	conn, err := quic.DialAddr(context.Background(), addr, tlsCfg, quicConfig())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenQUIC starts a server-side QUIC listener.
func ListenQUIC(addr string, tlsCfg *tls.Config) (*QUICListener, error) {
	ln, err := quic.ListenAddr(addr, tlsCfg, quicConfig())
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
