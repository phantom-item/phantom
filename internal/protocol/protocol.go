package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

const (
	CmdConnect = 0x01
	CmdUDP     = 0x03

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

type Address struct {
	Type byte
	Host string
	Port uint16
}

func (a *Address) String() string {
	return fmt.Sprintf("%s:%d", a.Host, a.Port)
}

type Request struct {
	Command byte
	Address Address
}

type Header struct {
	PasswordHash string
	Request      Request
}

type UDPPacket struct {
	Address Address
	Payload []byte
}

// HashPassword computes the SHA-224 hash of the password and returns its hex string representation.
func HashPassword(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ResolveAddress exposes the address resolution logic to determine IPv4, IPv6, or Domain type.
func ResolveAddress(host string, port uint16) (Address, error) {
	return resolveAddress(host, port)
}

// ParseHeader parses the incoming Trojan handshake header from the client (Server side).
func ParseHeader(r io.Reader) (*Header, error) {
	hash := make([]byte, 56)
	_, err := io.ReadFull(r, hash)
	if err != nil {
		return nil, err
	}

	err = readCRLF(r)
	if err != nil {
		return nil, err
	}

	var cmd [1]byte
	_, err = io.ReadFull(r, cmd[:])
	if err != nil {
		return nil, err
	}

	addr, err := readAddress(r)
	if err != nil {
		return nil, err
	}

	err = readCRLF(r)
	if err != nil {
		return nil, err
	}

	return &Header{
		PasswordHash: string(hash),
		Request: Request{
			Command: cmd[0],
			Address: addr,
		},
	}, nil
}

// WriteHeader writes the Trojan handshake header to the server (Client side).
func WriteHeader(w io.Writer, h *Header) error {
	if _, err := w.Write([]byte(h.PasswordHash)); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}
	if _, err := w.Write([]byte{h.Request.Command}); err != nil {
		return err
	}
	if err := writeAddress(w, h.Request.Address); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}
	return nil
}

// MaxUDPPayloadLength caps individual UDP packet payloads to bound the
// per-packet allocation in ReadUDPPacket. A 16-bit length field can encode
// up to 65535, but a maximally-sized payload is implausible for legitimate
// traffic (Ethernet jumbo frames stop around 9000 bytes; over QUIC/TCP
// transport the encapsulated packet is rarely above 1500). The previous
// "length > 65535" check was a no-op because the length field is uint16.
//
// This bound is conservative enough to never reject real traffic while
// preventing an attacker from amplifying a small Trojan-format stream
// into 64 KB-per-packet allocations.
const MaxUDPPayloadLength = 9000

// ReadUDPPacket parses the Trojan UDP encapsulation with security boundary checks against OOM attacks.
func ReadUDPPacket(r io.Reader) (*UDPPacket, error) {
	addr, err := readAddress(r)
	if err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	_, err = io.ReadFull(r, lenBuf[:])
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	// Reject implausibly large payloads. The length field is uint16
	// (already <= 65535), so the meaningful guard is the protocol-level
	// MaxUDPPayloadLength limit defined above.
	if length > MaxUDPPayloadLength {
		return nil, fmt.Errorf("udp packet length too large: %d (max %d)", length, MaxUDPPayloadLength)
	}

	payload := make([]byte, length)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		return nil, err
	}

	err = readCRLF(r)
	if err != nil {
		return nil, err
	}

	return &UDPPacket{
		Address: addr,
		Payload: payload,
	}, nil
}

// WriteUDPPacket encapsulates and writes data into the Trojan UDP format.
func WriteUDPPacket(w io.Writer, host string, port uint16, payload []byte) error {
	addr, err := resolveAddress(host, port)
	if err != nil {
		return err
	}

	if err := writeAddress(w, addr); err != nil {
		return err
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}

	if _, err := w.Write(payload); err != nil {
		return err
	}

	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}
	return nil
}

func readCRLF(r io.Reader) error {
	buf := make([]byte, 2)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	if buf[0] != '\r' || buf[1] != '\n' {
		return fmt.Errorf("invalid CRLF")
	}
	return nil
}

func readAddress(r io.Reader) (Address, error) {
	var atyp [1]byte
	_, err := io.ReadFull(r, atyp[:])
	if err != nil {
		return Address{}, err
	}

	addr := Address{
		Type: atyp[0],
	}

	switch atyp[0] {
	case AtypIPv4:
		ip := make([]byte, 4)
		_, err = io.ReadFull(r, ip)
		if err != nil {
			return Address{}, err
		}
		addr.Host = net.IP(ip).String()

	case AtypIPv6:
		ip := make([]byte, 16)
		_, err = io.ReadFull(r, ip)
		if err != nil {
			return Address{}, err
		}
		addr.Host = net.IP(ip).String()

	case AtypDomain:
		var length [1]byte
		_, err = io.ReadFull(r, length[:])
		if err != nil {
			return Address{}, err
		}
		if length[0] == 0 {
			return Address{}, fmt.Errorf("empty domain name")
		}
		domain := make([]byte, length[0])
		_, err = io.ReadFull(r, domain)
		if err != nil {
			return Address{}, err
		}
		addr.Host = string(domain)

	default:
		return Address{}, fmt.Errorf("unsupported address type: %d", atyp[0])
	}

	var portBuf [2]byte
	_, err = io.ReadFull(r, portBuf[:])
	if err != nil {
		return Address{}, err
	}
	addr.Port = binary.BigEndian.Uint16(portBuf[:])

	return addr, nil
}

func writeAddress(w io.Writer, addr Address) error {
	if _, err := w.Write([]byte{addr.Type}); err != nil {
		return err
	}

	switch addr.Type {
	case AtypIPv4:
		ip := net.ParseIP(addr.Host).To4()
		if ip == nil {
			return fmt.Errorf("invalid ipv4 address")
		}
		if _, err := w.Write(ip); err != nil {
			return err
		}
	case AtypIPv6:
		ip := net.ParseIP(addr.Host).To16()
		if ip == nil {
			return fmt.Errorf("invalid ipv6 address")
		}
		if _, err := w.Write(ip); err != nil {
			return err
		}
	case AtypDomain:
		if len(addr.Host) == 0 {
			return fmt.Errorf("empty domain name")
		}
		if len(addr.Host) > 255 {
			return fmt.Errorf("domain name too long")
		}
		if _, err := w.Write([]byte{byte(len(addr.Host))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(addr.Host)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported address type: %d", addr.Type)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], addr.Port)
	if _, err := w.Write(portBuf[:]); err != nil {
		return err
	}
	return nil
}

func resolveAddress(host string, port uint16) (Address, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return Address{Type: AtypIPv4, Host: host, Port: port}, nil
		}
		return Address{Type: AtypIPv6, Host: host, Port: port}, nil
	}
	return Address{Type: AtypDomain, Host: host, Port: port}, nil
}
