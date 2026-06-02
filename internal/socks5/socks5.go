package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	version5 = 0x05

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	RepSuccess = 0x00
)

type Request struct {
	Host  string
	Port  uint16
	IsUDP bool
}

type UDPPacket struct {
	Host    string
	Port    uint16
	Payload []byte
}

func Handshake(conn net.Conn) (*Request, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}

	if header[0] != version5 {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	// Confirm the client offered the "no authentication" method (0x00)
	// before we select it. If it did not, reply with 0xFF ("no
	// acceptable methods") per RFC 1928 and abort, rather than
	// unconditionally claiming 0x00 was negotiated.
	if !bytes.Contains(methods, []byte{methodNoAuth}) {
		_, _ = conn.Write([]byte{version5, methodNoAcceptable})
		return nil, fmt.Errorf("client offered no acceptable SOCKS5 auth methods")
	}

	if _, err := conn.Write([]byte{version5, methodNoAuth}); err != nil {
		return nil, err
	}

	var reqHeader [4]byte
	if _, err := io.ReadFull(conn, reqHeader[:]); err != nil {
		return nil, err
	}

	if reqHeader[0] != version5 {
		return nil, fmt.Errorf("unsupported request version: %d", reqHeader[0])
	}

	cmd := reqHeader[1]
	if cmd != cmdConnect && cmd != cmdUDPAssociate {
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := reqHeader[3]
	var host string

	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		host = net.IP(ip).String()

	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return nil, err
		}
		host = net.IP(ip).String()

	case atypDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return nil, err
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)

	default:
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	isUDP := cmd == cmdUDPAssociate

	// Only send immediate generic reply for TCP Connect.
	// For UDP Associate, the reply must be delayed until the UDP listener port is ready.
	if !isUDP {
		if _, err := conn.Write([]byte{
			version5, 0x00, 0x00, atypIPv4,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}); err != nil {
			return nil, err
		}
	}

	return &Request{
		Host:  host,
		Port:  port,
		IsUDP: isUDP,
	}, nil
}

func SendReply(conn net.Conn, rep byte, host string, port uint16) error {
	buf := []byte{version5, rep, 0x00, atypIPv4}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		ip = []byte{0, 0, 0, 0}
	}
	buf = append(buf, ip...)
	buf = append(buf, byte(port>>8), byte(port))
	_, err := conn.Write(buf)
	return err
}

func ParseUDPHeader(data []byte) (*UDPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("udp header too short")
	}

	atyp := data[3]
	var host string
	offset := 4

	switch atyp {
	case atypIPv4:
		if len(data) < offset+4+2 {
			return nil, fmt.Errorf("too short for ipv4")
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case atypIPv6:
		if len(data) < offset+16+2 {
			return nil, fmt.Errorf("too short for ipv6")
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	case atypDomain:
		if len(data) < offset+1 {
			return nil, fmt.Errorf("too short for domain length")
		}
		dlen := int(data[offset])
		offset++
		if len(data) < offset+dlen+2 {
			return nil, fmt.Errorf("too short for domain")
		}
		host = string(data[offset : offset+dlen])
		offset += dlen
	default:
		return nil, fmt.Errorf("unknown atyp: %d", atyp)
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	return &UDPPacket{
		Host:    host,
		Port:    port,
		Payload: data[offset:],
	}, nil
}

func NewUDPResponseHeader(host string, port uint16, payload []byte) ([]byte, error) {
	buf := make([]byte, 0, 4+len(host)+2+len(payload))
	buf = append(buf, 0x00, 0x00, 0x00) // RSV (2 bytes) + FRAG (1 byte)

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, atypIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, atypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long: %d bytes", len(host))
		}
		buf = append(buf, atypDomain)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}

	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, payload...)
	return buf, nil
}
