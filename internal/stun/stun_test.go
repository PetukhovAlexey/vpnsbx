package stun

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseXorMapped(t *testing.T) {
	req, id := Request()
	want := netip.MustParseAddrPort("203.0.113.7:54321")
	b := append([]byte(nil), req...)
	binary.BigEndian.PutUint16(b[0:], 0x0101)
	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:], 0x0020)
	binary.BigEndian.PutUint16(attr[2:], 8)
	attr[5] = 0x01
	binary.BigEndian.PutUint16(attr[6:], want.Port()^cookie>>16)
	ip := want.Addr().As4()
	binary.BigEndian.PutUint32(attr[8:], binary.BigEndian.Uint32(ip[:])^cookie)
	binary.BigEndian.PutUint16(b[2:], uint16(len(attr)))
	b = append(b, attr...)
	got, err := Parse(b, id)
	if err != nil || got != want {
		t.Fatalf("got %v, %v", got, err)
	}
	id[0] ^= 1
	if _, err := Parse(b, id); err == nil {
		t.Fatal("чужой transaction ID должен отвергаться")
	}
}
