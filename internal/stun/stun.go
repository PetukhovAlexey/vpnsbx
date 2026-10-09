// Package stun — минимальный STUN Binding (RFC 5389): узнать внешний адрес,
// с которого сервер видит UDP-пакеты.
package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

const cookie = 0x2112A442

var servers = []struct {
	host, fallback string
	port           uint16
}{
	{"stun.l.google.com", "74.125.250.129", 19302},
	{"stun.cloudflare.com", "162.159.207.0", 3478},
}

// Servers — IPv4-адреса публичных STUN-серверов. Имена разрешаются
// системным DNS; если не вышло — известные адреса.
func Servers(ctx context.Context) []netip.AddrPort {
	var r []netip.AddrPort
	for _, s := range servers {
		a := netip.MustParseAddr(s.fallback)
		if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", s.host); err == nil && len(ips) > 0 {
			a = ips[0].Unmap()
		}
		r = append(r, netip.AddrPortFrom(a, s.port))
	}
	return r
}

// Request — запрос Binding и его transaction ID.
func Request() (req []byte, id [12]byte) {
	rand.Read(id[:])
	req = make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001)
	binary.BigEndian.PutUint32(req[4:], cookie)
	copy(req[8:], id[:])
	return req, id
}

// Parse достаёт из ответа внешний адрес.
func Parse(b []byte, id [12]byte) (netip.AddrPort, error) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 ||
		binary.BigEndian.Uint32(b[4:]) != cookie || [12]byte(b[8:20]) != id {
		return netip.AddrPort{}, errors.New("чужой или неверный ответ STUN")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if 20+n > len(b) {
		return netip.AddrPort{}, errors.New("обрезанный ответ STUN")
	}
	var mapped netip.AddrPort
	for a := b[20 : 20+n]; len(a) >= 4; {
		t, l := binary.BigEndian.Uint16(a), int(binary.BigEndian.Uint16(a[2:]))
		if 4+l > len(a) {
			break
		}
		v := a[4 : 4+l]
		if l >= 8 && v[1] == 0x01 { // IPv4
			port := binary.BigEndian.Uint16(v[2:])
			ip := [4]byte(v[4:8])
			switch t {
			case 0x0020: // XOR-MAPPED-ADDRESS
				port ^= cookie >> 16
				binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])^cookie)
				return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
			case 0x0001: // MAPPED-ADDRESS
				mapped = netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			}
		}
		a = a[4+(l+3)&^3:]
	}
	if mapped.IsValid() {
		return mapped, nil
	}
	return netip.AddrPort{}, errors.New("в ответе STUN нет адреса")
}
