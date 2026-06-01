package transport

import (
	"net"

	"github.com/xtaci/smux"
)

// NewMuxSession initializes a client-side smux multiplexing session over a connection.
func NewMuxSession(conn net.Conn) (*smux.Session, error) {
	return smux.Client(conn, smux.DefaultConfig())
}

// AcceptMuxSession initializes a server-side smux multiplexing session over a connection.
func AcceptMuxSession(conn net.Conn) (*smux.Session, error) {
	return smux.Server(conn, smux.DefaultConfig())
}
