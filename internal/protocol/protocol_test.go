package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// buildHeader returns a minimal valid Trojan-format header for testing.
func buildHeader(cmd byte, atyp byte, addr []byte, port uint16) []byte {
	hash := bytes.Repeat([]byte("a"), 56)
	buf := &bytes.Buffer{}
	buf.Write(hash)
	buf.Write([]byte("\r\n"))
	buf.WriteByte(cmd)
	buf.WriteByte(atyp)
	if atyp == AtypDomain {
		buf.WriteByte(byte(len(addr)))
	}
	buf.Write(addr)
	binary.Write(buf, binary.BigEndian, port)
	buf.Write([]byte("\r\n"))
	return buf.Bytes()
}

func TestParseHeader(t *testing.T) {
	hash := bytes.Repeat([]byte("a"), 56)

	buf := &bytes.Buffer{}
	buf.Write(hash)
	buf.Write([]byte("\r\n"))
	buf.WriteByte(CmdConnect)
	buf.WriteByte(AtypDomain)
	buf.WriteByte(7)
	buf.WriteString("example")
	buf.WriteByte(0x01)
	buf.WriteByte(0xBB)
	buf.Write([]byte("\r\n"))

	header, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if header.PasswordHash != string(hash) {
		t.Errorf("unexpected hash")
	}
	if header.Request.Command != CmdConnect {
		t.Errorf("unexpected command")
	}
	if header.Request.Address.Host != "example" {
		t.Errorf("unexpected host: %s", header.Request.Address.Host)
	}
	if header.Request.Address.Port != 443 {
		t.Errorf("unexpected port: %d", header.Request.Address.Port)
	}
}

func TestParseHeaderIPv4(t *testing.T) {
	hdr := buildHeader(CmdConnect, AtypIPv4, []byte{192, 0, 2, 1}, 8080)
	h, err := ParseHeader(bytes.NewReader(hdr))
	if err != nil {
		t.Fatalf("ParseHeader IPv4 failed: %v", err)
	}
	if h.Request.Address.Host != "192.0.2.1" {
		t.Errorf("unexpected IPv4: %q", h.Request.Address.Host)
	}
	if h.Request.Address.Port != 8080 {
		t.Errorf("unexpected port: %d", h.Request.Address.Port)
	}
}

func TestParseHeaderIPv6(t *testing.T) {
	addr := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01,
	}
	hdr := buildHeader(CmdConnect, AtypIPv6, addr, 443)
	h, err := ParseHeader(bytes.NewReader(hdr))
	if err != nil {
		t.Fatalf("ParseHeader IPv6 failed: %v", err)
	}
	if h.Request.Address.Host != "2001:db8::1" {
		t.Errorf("unexpected IPv6: %q", h.Request.Address.Host)
	}
}

func TestParseHeaderUDPCommand(t *testing.T) {
	hdr := buildHeader(CmdUDP, AtypIPv4, []byte{198, 51, 100, 7}, 53)
	h, err := ParseHeader(bytes.NewReader(hdr))
	if err != nil {
		t.Fatalf("ParseHeader UDP failed: %v", err)
	}
	if h.Request.Command != CmdUDP {
		t.Errorf("expected CmdUDP, got %#x", h.Request.Command)
	}
}

func TestParseHeaderRejectsTruncated(t *testing.T) {
	full := buildHeader(CmdConnect, AtypIPv4, []byte{1, 2, 3, 4}, 80)
	// Lop off various amounts to verify each missing byte produces an error.
	for _, cut := range []int{1, 5, 56, 58, 59, len(full) - 1} {
		if cut >= len(full) {
			continue
		}
		if _, err := ParseHeader(bytes.NewReader(full[:cut])); err == nil {
			t.Errorf("truncated header (len=%d) parsed successfully — expected error", cut)
		}
	}
}

func TestParseHeaderRejectsBadCRLF(t *testing.T) {
	// Replace the first CRLF (after the 56-byte hash) with garbage.
	hdr := buildHeader(CmdConnect, AtypIPv4, []byte{1, 2, 3, 4}, 80)
	hdr[56] = 'X'
	hdr[57] = 'Y'
	if _, err := ParseHeader(bytes.NewReader(hdr)); err == nil {
		t.Error("ParseHeader accepted bad CRLF")
	}
}

func TestParseHeaderRejectsZeroLengthDomain(t *testing.T) {
	// Manually craft a header with atyp=domain but length=0.
	buf := &bytes.Buffer{}
	buf.Write(bytes.Repeat([]byte("a"), 56))
	buf.Write([]byte("\r\n"))
	buf.WriteByte(CmdConnect)
	buf.WriteByte(AtypDomain)
	buf.WriteByte(0) // length 0
	buf.Write([]byte{0x00, 0x50})
	buf.Write([]byte("\r\n"))

	if _, err := ParseHeader(buf); err == nil {
		t.Error("ParseHeader accepted empty domain")
	}
}

func TestParseHeaderRejectsUnknownAtyp(t *testing.T) {
	buf := &bytes.Buffer{}
	buf.Write(bytes.Repeat([]byte("a"), 56))
	buf.Write([]byte("\r\n"))
	buf.WriteByte(CmdConnect)
	buf.WriteByte(0x99) // unknown atyp
	buf.Write([]byte{1, 2, 3, 4, 0x00, 0x50})
	buf.Write([]byte("\r\n"))

	if _, err := ParseHeader(buf); err == nil {
		t.Error("ParseHeader accepted unknown atyp")
	}
}

// ── UDP packet round-trip tests ─────────────────────────────────────────────

func TestUDPPacketRoundTrip(t *testing.T) {
	payload := []byte("hello world")

	buf := &bytes.Buffer{}
	if err := WriteUDPPacket(buf, "192.0.2.1", 53, payload); err != nil {
		t.Fatalf("WriteUDPPacket failed: %v", err)
	}

	pkt, err := ReadUDPPacket(buf)
	if err != nil {
		t.Fatalf("ReadUDPPacket failed: %v", err)
	}
	if pkt.Address.Host != "192.0.2.1" {
		t.Errorf("unexpected host: %q", pkt.Address.Host)
	}
	if pkt.Address.Port != 53 {
		t.Errorf("unexpected port: %d", pkt.Address.Port)
	}
	if !bytes.Equal(pkt.Payload, payload) {
		t.Errorf("payload mismatch: %q vs %q", pkt.Payload, payload)
	}
}

func TestUDPPacketRejectsOversize(t *testing.T) {
	// Manually construct a packet header that claims a payload larger
	// than MaxUDPPayloadLength.  ReadUDPPacket should refuse without
	// attempting the giant allocation.
	buf := &bytes.Buffer{}
	buf.WriteByte(AtypIPv4)
	buf.Write([]byte{1, 2, 3, 4})
	binary.Write(buf, binary.BigEndian, uint16(53))
	binary.Write(buf, binary.BigEndian, uint16(MaxUDPPayloadLength+1))
	// CRLF + payload bytes deliberately not written — the length check
	// must trigger before any read of them.

	if _, err := ReadUDPPacket(buf); err == nil {
		t.Error("ReadUDPPacket accepted oversized length")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestUDPPacketAcceptsMaxLength(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, MaxUDPPayloadLength)
	buf := &bytes.Buffer{}
	if err := WriteUDPPacket(buf, "192.0.2.1", 53, payload); err != nil {
		t.Fatalf("WriteUDPPacket failed: %v", err)
	}
	pkt, err := ReadUDPPacket(buf)
	if err != nil {
		t.Fatalf("ReadUDPPacket at max length failed: %v", err)
	}
	if len(pkt.Payload) != MaxUDPPayloadLength {
		t.Errorf("expected payload size %d, got %d", MaxUDPPayloadLength, len(pkt.Payload))
	}
}

// ── HashPassword ────────────────────────────────────────────────────────────

func TestHashPasswordStable(t *testing.T) {
	const pw = "correct horse battery staple"
	a := HashPassword(pw)
	b := HashPassword(pw)
	if a != b {
		t.Errorf("HashPassword non-deterministic: %q vs %q", a, b)
	}
	if len(a) != 56 {
		t.Errorf("expected 56-char hex, got %d", len(a))
	}
	if HashPassword("different") == a {
		t.Error("different passwords produced identical hash")
	}
}
