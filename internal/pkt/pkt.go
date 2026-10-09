// Package pkt — разбор и сборка IP-пакетов: контрольные суммы, MSS,
// синтетические ответы (RST, ICMP unreachable).
package pkt

import (
	"encoding/binary"
	"net/netip"
)

const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58

	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPAck = 0x10
)

// Info — разобранные поля IP-пакета (без копирования данных).
type Info struct {
	V6        bool
	Proto     byte
	Src, Dst  netip.Addr
	SrcPort   uint16
	DstPort   uint16
	HdrLen    int  // длина IP-заголовка (для IPv6 — 40, расширения не поддерживаются)
	TotalLen  int  // длина всего IP-пакета
	Fragment  bool // фрагмент (IPv4: MF или ненулевое смещение)
	FirstFrag bool // первый фрагмент или нефрагментированный пакет
	DF        bool
	TCPFlags  byte
	ID        uint16 // IPv4 identification
	ICMPType  byte
}

// Parse разбирает IPv4/IPv6-пакет. ok=false, если пакет не IP или обрезан.
func Parse(p []byte) (in Info, ok bool) {
	if len(p) < 20 {
		return in, false
	}
	switch p[0] >> 4 {
	case 4:
		ihl := int(p[0]&0x0f) * 4
		tot := int(binary.BigEndian.Uint16(p[2:4]))
		if ihl < 20 || tot < ihl || tot > len(p) {
			return in, false
		}
		ff := binary.BigEndian.Uint16(p[6:8])
		in.HdrLen, in.TotalLen = ihl, tot
		in.Proto = p[9]
		in.Src = netip.AddrFrom4([4]byte(p[12:16]))
		in.Dst = netip.AddrFrom4([4]byte(p[16:20]))
		in.ID = binary.BigEndian.Uint16(p[4:6])
		in.DF = ff&0x4000 != 0
		off := ff & 0x1fff
		in.Fragment = ff&0x2000 != 0 || off != 0
		in.FirstFrag = off == 0
	case 6:
		if len(p) < 40 {
			return in, false
		}
		tot := 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if tot > len(p) {
			return in, false
		}
		in.V6 = true
		in.HdrLen, in.TotalLen = 40, tot
		in.Proto = p[6]
		in.Src = netip.AddrFrom16([16]byte(p[8:24]))
		in.Dst = netip.AddrFrom16([16]byte(p[24:40]))
		in.FirstFrag = true
		in.DF = true
		if in.Proto == 44 { // фрагмент IPv6
			in.Fragment = true
			in.FirstFrag = false
		}
	default:
		return in, false
	}
	if !in.FirstFrag {
		return in, true
	}
	l4 := p[in.HdrLen:in.TotalLen]
	switch in.Proto {
	case ProtoTCP:
		if len(l4) < 20 {
			return in, false
		}
		in.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		in.DstPort = binary.BigEndian.Uint16(l4[2:4])
		in.TCPFlags = l4[13]
	case ProtoUDP:
		if len(l4) < 8 {
			return in, false
		}
		in.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		in.DstPort = binary.BigEndian.Uint16(l4[2:4])
	case ProtoICMP, ProtoICMPv6:
		if len(l4) < 8 {
			return in, false
		}
		in.ICMPType = l4[0]
		in.SrcPort = binary.BigEndian.Uint16(l4[4:6]) // identifier для echo
	}
	return in, true
}

func sum(b []byte, s uint32) uint32 {
	n := len(b) &^ 1
	for i := 0; i < n; i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)&1 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	return ^uint16(s)
}

func pseudo(p []byte, in *Info, l4len int) uint32 {
	var s uint32
	if in.V6 {
		s = sum(p[8:40], 0)
	} else {
		s = sum(p[12:20], 0)
	}
	return s + uint32(in.Proto) + uint32(l4len)
}

// SetSrc/SetDst меняют адрес в заголовке (без пересчёта сумм — вызовите Fix).
func SetSrc(p []byte, a netip.Addr) {
	if p[0]>>4 == 4 {
		b := a.As4()
		copy(p[12:16], b[:])
	} else {
		b := a.As16()
		copy(p[8:24], b[:])
	}
}

func SetDst(p []byte, a netip.Addr) {
	if p[0]>>4 == 4 {
		b := a.As4()
		copy(p[16:20], b[:])
	} else {
		b := a.As16()
		copy(p[24:40], b[:])
	}
}

// Fix пересчитывает контрольные суммы IP и транспортного уровня.
// Входящие из стека Windows пакеты могут иметь незаполненные суммы
// (checksum offload), поэтому считаем полностью, а не инкрементально.
// Для фрагментов (кроме первого) транспортная сумма не трогается.
func Fix(p []byte) {
	in, ok := Parse(p)
	if !ok {
		return
	}
	if !in.V6 {
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:12], fold(sum(p[:in.HdrLen], 0)))
	}
	if in.Fragment {
		// Сумма первого фрагмента охватывает всю дейтаграмму — пересчитать нельзя,
		// для фрагментов используйте Rewrite (инкрементальная правка).
		return
	}
	l4 := p[in.HdrLen:in.TotalLen]
	switch in.Proto {
	case ProtoTCP:
		l4[16], l4[17] = 0, 0
		binary.BigEndian.PutUint16(l4[16:18], fold(sum(l4, pseudo(p, &in, len(l4)))))
	case ProtoUDP:
		l4[6], l4[7] = 0, 0
		c := fold(sum(l4, pseudo(p, &in, len(l4))))
		if c == 0 {
			c = 0xffff
		}
		binary.BigEndian.PutUint16(l4[6:8], c)
	case ProtoICMP:
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:4], fold(sum(l4, 0)))
	case ProtoICMPv6:
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:4], fold(sum(l4, pseudo(p, &in, len(l4)))))
	}
}

// Rewrite меняет адреса источника/назначения (невалидный Addr — не менять)
// и приводит суммы в порядок: для целых пакетов — полный пересчёт, для
// фрагментов — инкрементальная правка по RFC 1624 (offload у фрагментов не бывает).
func Rewrite(p []byte, in *Info, src, dst netip.Addr) {
	if !in.Fragment {
		if src.IsValid() {
			SetSrc(p, src)
		}
		if dst.IsValid() {
			SetDst(p, dst)
		}
		Fix(p)
		return
	}
	var oldA, newA []byte
	if src.IsValid() {
		oldA, newA = append(oldA, in.Src.AsSlice()...), append(newA, src.AsSlice()...)
		SetSrc(p, src)
	}
	if dst.IsValid() {
		oldA, newA = append(oldA, in.Dst.AsSlice()...), append(newA, dst.AsSlice()...)
		SetDst(p, dst)
	}
	if !in.V6 {
		p[10], p[11] = 0, 0
		binary.BigEndian.PutUint16(p[10:12], fold(sum(p[:in.HdrLen], 0)))
	}
	if !in.FirstFrag {
		return
	}
	l4 := p[in.HdrLen:in.TotalLen]
	var at int
	switch in.Proto {
	case ProtoTCP:
		at = 16
	case ProtoUDP:
		at = 6
		if binary.BigEndian.Uint16(l4[6:8]) == 0 {
			return // сумма UDP не используется
		}
	default:
		return
	}
	if len(l4) < at+2 {
		return
	}
	// HC' = ~(~HC + ~m + m')
	s := uint32(^binary.BigEndian.Uint16(l4[at : at+2]))
	for i := 0; i+1 < len(oldA); i += 2 {
		s += uint32(^(uint16(oldA[i])<<8 | uint16(oldA[i+1])))
		s += uint32(uint16(newA[i])<<8 | uint16(newA[i+1]))
	}
	binary.BigEndian.PutUint16(l4[at:at+2], fold(s))
}

// ClampMSS уменьшает MSS в SYN-пакете до mss. Суммы не пересчитывает.
func ClampMSS(p []byte, in *Info, mss uint16) bool {
	if in.Proto != ProtoTCP || in.TCPFlags&TCPSyn == 0 || in.Fragment {
		return false
	}
	t := p[in.HdrLen:in.TotalLen]
	off := int(t[12]>>4) * 4
	if off < 20 || off > len(t) {
		return false
	}
	opts := t[20:off]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case 0:
			return false
		case 1:
			i++
			continue
		}
		if i+1 >= len(opts) || opts[i+1] < 2 || i+int(opts[i+1]) > len(opts) {
			return false
		}
		if opts[i] == 2 && opts[i+1] == 4 {
			if binary.BigEndian.Uint16(opts[i+2:i+4]) > mss {
				binary.BigEndian.PutUint16(opts[i+2:i+4], mss)
				return true
			}
			return false
		}
		i += int(opts[i+1])
	}
	return false
}

func ipHeader(v6 bool, proto byte, src, dst netip.Addr, payload int) []byte {
	if v6 {
		h := make([]byte, 40, 40+payload)
		h[0] = 0x60
		binary.BigEndian.PutUint16(h[4:6], uint16(payload))
		h[6] = proto
		h[7] = 64
		s, d := src.As16(), dst.As16()
		copy(h[8:24], s[:])
		copy(h[24:40], d[:])
		return h
	}
	h := make([]byte, 20, 20+payload)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payload))
	h[6] = 0x40 // DF
	h[8] = 64
	h[9] = proto
	s, d := src.As4(), dst.As4()
	copy(h[12:16], s[:])
	copy(h[16:20], d[:])
	return h
}

// TCPReset строит RST в ответ на исходящий TCP-пакет p (направление: от удалённой стороны к локальной).
func TCPReset(p []byte, in *Info) []byte {
	t := p[in.HdrLen:in.TotalLen]
	off := int(t[12]>>4) * 4
	plen := len(t) - off
	seq := binary.BigEndian.Uint32(t[4:8])
	ack := binary.BigEndian.Uint32(t[8:12])
	r := make([]byte, 20)
	binary.BigEndian.PutUint16(r[0:2], in.DstPort)
	binary.BigEndian.PutUint16(r[2:4], in.SrcPort)
	r[12] = 5 << 4
	if in.TCPFlags&TCPAck != 0 {
		binary.BigEndian.PutUint32(r[4:8], ack)
		r[13] = TCPRst
	} else {
		adv := uint32(plen)
		if in.TCPFlags&TCPSyn != 0 {
			adv++
		}
		if in.TCPFlags&TCPFin != 0 {
			adv++
		}
		binary.BigEndian.PutUint32(r[8:12], seq+adv)
		r[13] = TCPRst | TCPAck
	}
	out := append(ipHeader(in.V6, ProtoTCP, in.Dst, in.Src, len(r)), r...)
	Fix(out)
	return out
}

// Unreachable строит ICMP/ICMPv6 «назначение недоступно» в ответ на пакет p.
// from — адрес отправителя ошибки. Для «нужна фрагментация» передайте mtu>0.
func Unreachable(p []byte, in *Info, from netip.Addr, code byte, mtu uint16) []byte {
	quote := p[:in.TotalLen]
	var hdr [8]byte
	var proto byte
	if in.V6 {
		proto = ProtoICMPv6
		if len(quote) > 1232 {
			quote = quote[:1232]
		}
		if mtu > 0 {
			hdr[0] = 2 // Packet Too Big
			binary.BigEndian.PutUint32(hdr[4:8], uint32(mtu))
		} else {
			hdr[0], hdr[1] = 1, code
		}
	} else {
		proto = ProtoICMP
		if len(quote) > in.HdrLen+8 {
			quote = quote[:in.HdrLen+8]
		}
		hdr[0], hdr[1] = 3, code
		if mtu > 0 {
			hdr[1] = 4
			binary.BigEndian.PutUint16(hdr[6:8], mtu)
		}
	}
	body := append(hdr[:], quote...)
	out := append(ipHeader(in.V6, proto, from, in.Src, len(body)), body...)
	Fix(out)
	return out
}

// Fragment4 режет IPv4-пакет без DF на фрагменты не длиннее mtu.
// Пакет может сам быть фрагментом — смещения и MF учитываются.
func Fragment4(p []byte, in *Info, mtu int) [][]byte {
	hl := in.HdrLen
	step := (mtu - hl) &^ 7
	if in.V6 || step <= 0 {
		return nil
	}
	ff := binary.BigEndian.Uint16(p[6:8])
	base := int(ff&0x1fff) * 8
	lastMF := ff&0x2000 != 0
	data := p[hl:in.TotalLen]
	var out [][]byte
	for off := 0; off < len(data); off += step {
		end := min(off+step, len(data))
		f := make([]byte, hl+end-off)
		copy(f, p[:hl])
		copy(f[hl:], data[off:end])
		binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
		v := uint16((base + off) / 8)
		if end < len(data) || lastMF {
			v |= 0x2000
		}
		binary.BigEndian.PutUint16(f[6:8], v)
		f[10], f[11] = 0, 0
		binary.BigEndian.PutUint16(f[10:12], fold(sum(f[:hl], 0)))
		out = append(out, f)
	}
	return out
}

// UDP4 строит IPv4/UDP-пакет с готовыми суммами.
func UDP4(src, dst netip.AddrPort, payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	out := append(ipHeader(false, ProtoUDP, src.Addr(), dst.Addr(), len(u)), u...)
	Fix(out)
	return out
}

// EchoRequest строит ICMP echo (IPv4) — для проверки живости туннеля.
func EchoRequest(src, dst netip.Addr, id, seq uint16) []byte {
	b := make([]byte, 8+16)
	b[0] = 8
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], "vpnsbx-healthchk")
	out := append(ipHeader(false, ProtoICMP, src, dst, len(b)), b...)
	Fix(out)
	return out
}
