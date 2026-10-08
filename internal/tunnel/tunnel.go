// Package tunnel — AmneziaWG-туннель внутри процесса: без адаптера и wintun.
// Пакеты приложений подаются через Send, ответы приходят в колбэк OnPacket.
package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"

	"vpnsbx/internal/pkt"
	"vpnsbx/internal/profile"
)

// chanTun реализует tun.Device поверх каналов.
type chanTun struct {
	mtu     int
	in      chan []byte
	events  chan tun.Event
	closed  chan struct{}
	once    sync.Once
	onWrite func([]byte)
}

func (t *chanTun) File() *os.File           { return nil }
func (t *chanTun) MTU() (int, error)        { return t.mtu, nil }
func (t *chanTun) Name() (string, error)    { return "vpnsbx", nil }
func (t *chanTun) Events() <-chan tun.Event { return t.events }
func (t *chanTun) BatchSize() int           { return 16 }

func (t *chanTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var p []byte
	select {
	case p = <-t.in:
	case <-t.closed:
		return 0, os.ErrClosed
	}
	n := 0
	for {
		sizes[n] = copy(bufs[n][offset:], p)
		n++
		if n == len(bufs) {
			return n, nil
		}
		select {
		case p = <-t.in:
		default:
			return n, nil
		}
	}
}

func (t *chanTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		t.onWrite(b[offset:])
	}
	return len(bufs), nil
}

func (t *chanTun) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// Tunnel — поднятый туннель.
type Tunnel struct {
	Addr4     netip.Addr // адрес туннеля IPv4 (источник для NAT)
	Addr6     netip.Addr // адрес IPv6, если есть
	Prefixes  []netip.Prefix
	DNS       []netip.Addr
	MTU       int
	Endpoints []netip.AddrPort

	dev      *device.Device
	tun      *chanTun
	onPacket func([]byte)

	lastRx    atomic.Int64 // unix nano последнего пакета из туннеля
	probeDst  netip.Addr
	probeID   uint16
	probeSeq  uint16
	stop      chan struct{}
	DownAfter time.Duration

	cut atomic.Bool // имитация обрыва (для испытаний)
}

// SetCut включает/выключает имитацию обрыва: пакеты в обе стороны теряются.
func (t *Tunnel) SetCut(v bool) { t.cut.Store(v) }

// Start поднимает туннель. onPacket получает расшифрованные IP-пакеты;
// буфер действителен только во время вызова.
func Start(a *profile.AWG, onPacket func([]byte), logger *log.Logger) (*Tunnel, error) {
	eps, err := a.ResolveEndpoints(profile.SystemResolver)
	if err != nil {
		return nil, err
	}
	t := &Tunnel{
		Prefixes:  a.Addresses,
		DNS:       a.DNS,
		MTU:       a.MTU,
		Endpoints: eps,
		onPacket:  onPacket,
		stop:      make(chan struct{}),
		DownAfter: 10 * time.Second,
		probeID:   uint16(os.Getpid()),
	}
	for _, p := range a.Addresses {
		if p.Addr().Is4() && !t.Addr4.IsValid() {
			t.Addr4 = p.Addr()
		}
		if p.Addr().Is6() && !t.Addr6.IsValid() {
			t.Addr6 = p.Addr()
		}
	}
	if !t.Addr4.IsValid() {
		return nil, errors.New("в профиле нет IPv4-адреса туннеля")
	}
	t.probeDst = netip.MustParseAddr("1.1.1.1")
	for _, d := range a.DNS {
		if d.Is4() {
			t.probeDst = d
			break
		}
	}

	t.tun = &chanTun{
		mtu:     a.MTU,
		in:      make(chan []byte, 1024),
		events:  make(chan tun.Event, 1),
		closed:  make(chan struct{}),
		onWrite: t.receive,
	}
	t.tun.events <- tun.EventUp

	lg := device.NewLogger(device.LogLevelError, "awg: ")
	if logger != nil {
		lg.Errorf = func(f string, args ...any) { logger.Printf("awg: "+f, args...) }
	}
	t.dev = device.NewDevice(t.tun, conn.NewDefaultBind(), lg)
	if err := t.dev.IpcSet(a.UAPI(eps)); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		t.dev.Close()
		return nil, err
	}
	go t.prober()
	return t, nil
}

func (t *Tunnel) receive(p []byte) {
	if t.cut.Load() {
		return
	}
	t.lastRx.Store(time.Now().UnixNano())
	if in, ok := pkt.Parse(p); ok && !in.V6 && in.Proto == pkt.ProtoICMP &&
		in.ICMPType == 0 && in.SrcPort == t.probeID && in.Dst == t.Addr4 {
		return // ответ на нашу проверку
	}
	t.onPacket(p)
}

// prober раз в 2 с шлёт ping через туннель, чтобы отличать «тишину» от обрыва.
func (t *Tunnel) prober() {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		t.probeSeq++
		t.Send(pkt.EchoRequest(t.Addr4, t.probeDst, t.probeID, t.probeSeq))
		select {
		case <-tk.C:
		case <-t.stop:
			return
		}
	}
}

// Send ставит IP-пакет в очередь на шифрование. Пакет копируется.
// false — очередь переполнена или туннель закрыт.
func (t *Tunnel) Send(p []byte) bool {
	if t.cut.Load() {
		return true
	}
	c := append([]byte(nil), p...)
	select {
	case t.tun.in <- c:
		return true
	default:
		return false
	}
}

// Healthy — от сервера были пакеты за последние DownAfter.
func (t *Tunnel) Healthy() bool {
	last := t.lastRx.Load()
	return last != 0 && time.Since(time.Unix(0, last)) < t.DownAfter
}

// LastRx — время последнего пакета из туннеля (нулевое, если не было).
func (t *Tunnel) LastRx() time.Time {
	if v := t.lastRx.Load(); v != 0 {
		return time.Unix(0, v)
	}
	return time.Time{}
}

func (t *Tunnel) Close() {
	select {
	case <-t.stop:
		return
	default:
	}
	close(t.stop)
	t.dev.Close()
}
