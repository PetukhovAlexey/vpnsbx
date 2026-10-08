// Package proc — кому принадлежит соединение и подпадает ли процесс под правило.
package proc

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

type tcpKey struct {
	local, remote netip.AddrPort
}

// Owners — снимок таблиц TCP/UDP с PID владельцев.
type Owners struct {
	mu      sync.Mutex
	tcp     map[tcpKey]uint32
	udp     map[netip.AddrPort]uint32 // локальный адрес:порт (адрес может быть 0.0.0.0 / ::)
	updated time.Time
	buf     []byte
}

func NewOwners() *Owners {
	return &Owners{}
}

// Lookup ищет PID процесса, отправившего пакет src→dst. Снимок старше
// 100 мс перечитывается (порт UDP мог перейти к другому процессу), при
// промахе — тоже, но не чаще раза в миллисекунду.
func (o *Owners) Lookup(proto byte, src, dst netip.AddrPort) (uint32, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if time.Since(o.updated) > 100*time.Millisecond {
		o.refresh()
	}
	if pid, ok := o.find(proto, src, dst); ok {
		return pid, true
	}
	if time.Since(o.updated) < time.Millisecond {
		return 0, false
	}
	o.refresh()
	return o.find(proto, src, dst)
}

func (o *Owners) find(proto byte, src, dst netip.AddrPort) (uint32, bool) {
	switch proto {
	case 6:
		pid, ok := o.tcp[tcpKey{src, dst}]
		return pid, ok
	case 17:
		if pid, ok := o.udp[src]; ok {
			return pid, true
		}
		cands := []netip.Addr{netip.IPv6Unspecified()}
		if src.Addr().Is4() {
			// dual-stack сокет ([::]) тоже может слать IPv4
			cands = []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified(),
				netip.AddrFrom16(src.Addr().As16())}
		}
		for _, a := range cands {
			if pid, ok := o.udp[netip.AddrPortFrom(a, src.Port())]; ok {
				return pid, true
			}
		}
		return 0, false
	}
	return 0, false
}

func (o *Owners) refresh() {
	o.tcp = make(map[tcpKey]uint32, len(o.tcp))
	o.udp = make(map[netip.AddrPort]uint32, len(o.udp))
	o.load(procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPidAll, func(r []byte) {
		// MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid
		l := netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), binary.BigEndian.Uint16(r[8:10]))
		rm := netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), binary.BigEndian.Uint16(r[16:18]))
		o.tcp[tcpKey{l, rm}] = binary.LittleEndian.Uint32(r[20:24])
	}, 24)
	o.load(procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPidAll, func(r []byte) {
		// MIB_TCP6ROW_OWNER_PID: laddr[16], lscope, lport, raddr[16], rscope, rport, state, pid
		l := netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])), binary.BigEndian.Uint16(r[20:22]))
		rm := netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])), binary.BigEndian.Uint16(r[44:46]))
		o.tcp[tcpKey{l, rm}] = binary.LittleEndian.Uint32(r[52:56])
	}, 56)
	o.load(procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPid, func(r []byte) {
		// MIB_UDPROW_OWNER_PID: laddr, lport, pid
		l := netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[0:4])), binary.BigEndian.Uint16(r[4:6]))
		o.udp[l] = binary.LittleEndian.Uint32(r[8:12])
	}, 12)
	o.load(procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPid, func(r []byte) {
		// MIB_UDP6ROW_OWNER_PID: laddr[16], lscope, lport, pid
		l := netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])), binary.BigEndian.Uint16(r[20:22]))
		o.udp[l] = binary.LittleEndian.Uint32(r[24:28])
	}, 28)
	o.updated = time.Now()
}

func (o *Owners) load(proc *windows.LazyProc, af, class uintptr, row func([]byte), size int) {
	for try := 0; try < 4; try++ {
		if len(o.buf) < 4096 {
			o.buf = make([]byte, 64*1024)
		}
		n := uint32(len(o.buf))
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&o.buf[0])), uintptr(unsafe.Pointer(&n)), 0, af, class, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			o.buf = make([]byte, int(n)+16*1024)
			continue
		}
		if r != 0 {
			return
		}
		cnt := int(binary.LittleEndian.Uint32(o.buf[0:4]))
		for i := 0; i < cnt; i++ {
			off := 4 + i*size
			if off+size > int(n) {
				break
			}
			row(o.buf[off : off+size])
		}
		return
	}
}
