// Package engine — перехват исходящих пакетов драйвером NDISRD: трафик
// процессов из правила уходит в AWG-туннель внутри процесса, остальное
// проходит как есть. При обрыве туннеля процессы из правила не получают
// никакой сети (включая LAN).
package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	A "github.com/wiresock/ndisapi-go"
	"golang.org/x/sys/windows"

	"vpnsbx/internal/pkt"
	"vpnsbx/internal/proc"
	"vpnsbx/internal/profile"
	"vpnsbx/internal/tunnel"
)

type Config struct {
	AWG     *profile.AWG
	Rules   *proc.Rules
	Adapter string // имя адаптера; пусто — адаптер маршрута по умолчанию
	Log     *log.Logger
	Verbose bool

	// Испытания: имитировать обрыв туннеля в окне [CutFrom, CutTo) от старта.
	CutFrom, CutTo time.Duration
}

// kind — куда направлять поток процесса из правила.
type kind uint8

const (
	kTunnel kind = iota // в туннель с SNAT
	kDNS                // в туннель с SNAT и DNAT на DNS туннеля
	kLAN                // напрямую, пока туннель жив
	kBlock              // всегда блокировать
)

func (k kind) String() string {
	return [...]string{"туннель", "DNS→туннель", "LAN", "блок"}[k]
}

type flowKey struct {
	proto    byte
	src, dst netip.AddrPort
}

type natKey struct {
	proto  byte
	port   uint16         // исходный порт отправителя (не меняется)
	remote netip.AddrPort // адресат в туннеле (после DNAT)
}

type flow struct {
	rule   bool
	kind   kind
	pid    uint32
	key    flowKey
	remote netip.AddrPort // адресат в туннеле
	ad     A.Handle       // адаптер, через который ушёл первый пакет
	hostM  [6]byte        // MAC адаптера
	gwM    [6]byte        // MAC шлюза (получатель исходного кадра)
	last   atomic.Int64
	syn    atomic.Bool // соединение начато при нас (видели SYN)
}

func (f *flow) markSyn(flags byte) {
	if flags&pkt.TCPSyn != 0 {
		f.syn.Store(true)
	}
}

func (f *flow) seenSyn() bool { return f.syn.Load() }

type fragKey struct {
	src, dst netip.Addr
	id       uint16
	proto    byte
}

type fragEnt struct {
	f    *flow
	seen time.Time
}

type Engine struct {
	cfg  Config
	log  *log.Logger
	api  *A.NdisApi
	ads  []adapter
	nets []netip.Prefix // подсети адаптеров хоста (LAN)

	tun     *tunnel.Tunnel
	owners  *proc.Owners
	tracker *proc.Tracker
	dnsDst  netip.Addr

	mu       sync.Mutex
	flows    map[flowKey]*flow
	nat      map[natKey]*flow
	fragsOut map[fragKey]fragEnt
	fragsIn  map[fragKey]fragEnt

	inject  chan frame // готовые Ethernet-кадры для стека
	healthy atomic.Bool

	Stats struct {
		Out, ToTunnel, FromTunnel, Blocked, Unknown, Dropped atomic.Uint64
	}
}

var lanV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

var lanV6 = []netip.Prefix{
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff00::/8"),
}

func New(cfg Config) (*Engine, error) {
	if cfg.Log == nil {
		cfg.Log = log.Default()
	}
	e := &Engine{
		cfg:      cfg,
		log:      cfg.Log,
		flows:    map[flowKey]*flow{},
		nat:      map[natKey]*flow{},
		fragsOut: map[fragKey]fragEnt{},
		fragsIn:  map[fragKey]fragEnt{},
		inject:   make(chan frame, 4096),
		owners:   proc.NewOwners(),
	}
	api, err := A.NewNdisApi()
	if err != nil {
		return nil, fmt.Errorf("драйвер NDISRD: %w", err)
	}
	if !api.IsDriverLoaded() {
		api.Close()
		return nil, errors.New("драйвер NDISRD не загружен")
	}
	e.api = api
	if err := e.pickAdapters(); err != nil {
		api.Close()
		return nil, err
	}
	return e, nil
}

type adapter struct {
	h    A.Handle
	name string
}

type frame struct {
	ad A.Handle
	b  []byte
}

// pickAdapters выбирает адаптеры для фильтрации: все Ethernet (0) и IP (19,
// VPN-адаптеры — драйвер подставляет для них Ethernet-заголовок с нулевыми
// MAC, обработка та же). Иначе программа из правила при обрыве туннеля
// дотянулась бы до LAN через неотфильтрованный адаптер.
func (e *Engine) pickAdapters() error {
	list, err := e.api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return err
	}
	for i := 0; i < int(list.AdapterCount); i++ {
		name := e.api.ConvertWindows2000AdapterName(string(list.AdapterNameList[i][:]))
		if e.cfg.Adapter != "" && name != e.cfg.Adapter {
			continue
		}
		if m := list.AdapterMediumList[i]; m != 0 && m != 19 {
			e.log.Printf("адаптер %q: среда %d не поддерживается, пропущен", name, m)
			continue
		}
		e.ads = append(e.ads, adapter{list.AdapterHandle[i], name})
	}
	if len(e.ads) == 0 {
		return errors.New("нет адаптеров для фильтрации")
	}
	// подсети всех адаптеров хоста считаем LAN
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(n.String()); err == nil && !p.Addr().IsLoopback() {
					e.nets = append(e.nets, p.Masked())
				}
			}
		}
	}
	return nil
}

func (e *Engine) AdapterNames() []string {
	var out []string
	for _, a := range e.ads {
		out = append(out, a.name)
	}
	return out
}

// Run поднимает туннель и фильтрует до отмены ctx.
func (e *Engine) Run(ctx context.Context) error {
	defer e.api.Close()
	t, err := tunnel.Start(e.cfg.AWG, e.fromTunnel, e.log)
	if err != nil {
		return err
	}
	e.tun = t
	defer t.Close()
	for _, d := range t.DNS {
		if d.Is4() {
			e.dnsDst = d
			break
		}
	}
	e.tracker = proc.NewTracker(e.cfg.Rules)
	defer e.tracker.Close()

	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	defer func() {
		for _, a := range e.ads {
			e.api.SetAdapterMode(&A.AdapterMode{AdapterHandle: a.h, Flags: 0})
			e.api.SetPacketEvent(a.h, 0)
		}
	}()
	for _, a := range e.ads {
		if err := e.api.SetPacketEvent(a.h, ev); err != nil {
			return fmt.Errorf("SetPacketEvent %q: %w", a.name, err)
		}
		if err := e.api.SetAdapterMode(&A.AdapterMode{AdapterHandle: a.h, Flags: A.MSTCP_FLAG_SENT_TUNNEL}); err != nil {
			return fmt.Errorf("SetAdapterMode %q: %w", a.name, err)
		}
	}
	e.log.Printf("фильтр включён на адаптерах: %d шт.", len(e.ads))

	done := make(chan struct{})
	defer close(done)
	go e.injector(done)
	go e.housekeeping(done)
	if e.cfg.CutTo > e.cfg.CutFrom {
		go func() {
			start := time.Now()
			for _, s := range []struct {
				at  time.Duration
				cut bool
			}{{e.cfg.CutFrom, true}, {e.cfg.CutTo, false}} {
				select {
				case <-time.After(time.Until(start.Add(s.at))):
				case <-done:
					return
				}
				t.SetCut(s.cut)
				e.log.Printf("ИСПЫТАНИЕ: имитация обрыва = %v", s.cut)
			}
		}()
	}

	bufs := make([]A.IntermediateBuffer, 256)
	ptrs := make([]*A.IntermediateBuffer, len(bufs))
	for i := range bufs {
		ptrs[i] = &bufs[i]
	}
	pass := make([]*A.IntermediateBuffer, 0, len(bufs))
	for ctx.Err() == nil {
		windows.WaitForSingleObject(ev, 100)
		windows.ResetEvent(ev)
		for {
			var n uint32
			if !e.api.ReadPacketsUnsorted(ptrs, uint32(len(ptrs)), &n) || n == 0 {
				break
			}
			pass = pass[:0]
			for i := 0; i < int(n); i++ {
				b := ptrs[i]
				if b.DeviceFlags != A.PACKET_FLAG_ON_SEND || e.outgoing(b) {
					pass = append(pass, b)
				}
			}
			if len(pass) > 0 {
				var sent uint32
				e.api.SendPacketsToAdaptersUnsorted(pass, uint32(len(pass)), &sent)
			}
		}
	}
	return nil
}

// outgoing решает судьбу исходящего кадра. true — пропустить в сеть.
func (e *Engine) outgoing(b *A.IntermediateBuffer) bool {
	e.Stats.Out.Add(1)
	fr := b.Buffer[:b.Length]
	if len(fr) < 14+20 {
		return true
	}
	et := binary.BigEndian.Uint16(fr[12:14])
	if et != 0x0800 && et != 0x86DD {
		return true // ARP и прочее
	}
	ip := fr[14:]
	in, ok := pkt.Parse(ip)
	if !ok {
		return true
	}
	ip = ip[:in.TotalLen]

	var f *flow
	if in.Fragment && !in.FirstFrag {
		e.mu.Lock()
		fe, ok := e.fragsOut[fragKey{in.Src, in.Dst, in.ID, in.Proto}]
		e.mu.Unlock()
		if !ok {
			return true
		}
		f = fe.f
	} else {
		if in.Proto != pkt.ProtoTCP && in.Proto != pkt.ProtoUDP {
			return true // ICMP и прочее не атрибутируются
		}
		f = e.lookupFlow(&in, fr, b.HAdapterQLinkUnion.GetAdapter())
		if in.Fragment {
			e.mu.Lock()
			e.fragsOut[fragKey{in.Src, in.Dst, in.ID, in.Proto}] = fragEnt{f, time.Now()}
			e.mu.Unlock()
		}
	}
	if !f.rule {
		return true
	}
	f.last.Store(time.Now().UnixNano())

	if !e.healthy.Load() || f.kind == kBlock {
		e.block(ip, &in, f)
		return false
	}
	switch f.kind {
	case kLAN:
		return true
	case kTunnel, kDNS:
		e.toTunnel(ip, &in, f)
	}
	return false
}

func (e *Engine) lookupFlow(in *pkt.Info, fr []byte, ad A.Handle) *flow {
	k := flowKey{in.Proto, netip.AddrPortFrom(in.Src, in.SrcPort), netip.AddrPortFrom(in.Dst, in.DstPort)}
	e.mu.Lock()
	f := e.flows[k]
	e.mu.Unlock()
	if f != nil {
		return f
	}
	f = &flow{key: k, remote: k.dst}
	pid, ok := e.owners.Lookup(in.Proto, k.src, k.dst)
	if !ok {
		e.Stats.Unknown.Add(1)
		if e.cfg.Verbose {
			e.log.Printf("владелец не найден: %s %s→%s", protoName(in.Proto), k.src, k.dst)
		}
	} else {
		f.pid = pid
		f.rule, _ = e.tracker.Matched(pid)
	}
	if f.rule {
		f.kind = e.classify(in)
		f.ad = ad
		copy(f.gwM[:], fr[0:6])
		copy(f.hostM[:], fr[6:12])
		if f.kind == kDNS && e.dnsDst.IsValid() {
			f.remote = netip.AddrPortFrom(e.dnsDst, in.DstPort)
		}
		e.log.Printf("pid %d %s: %s %s → %s",
			pid, e.tracker.Path(pid), protoName(in.Proto), k.dst, f.kind)
	}
	f.last.Store(time.Now().UnixNano())
	e.mu.Lock()
	if old := e.flows[k]; old != nil {
		f = old
	} else {
		e.flows[k] = f
		if f.rule && (f.kind == kTunnel || f.kind == kDNS) {
			e.nat[natKey{in.Proto, in.SrcPort, f.remote}] = f
		}
	}
	e.mu.Unlock()
	return f
}

func (e *Engine) classify(in *pkt.Info) kind {
	d := in.Dst
	if in.V6 {
		if in.DstPort == 53 {
			return kBlock // DNS по IPv6 мимо туннеля не пускаем
		}
		for _, p := range lanV6 {
			if p.Contains(d) {
				return kLAN
			}
		}
		if e.tun.Addr6.IsValid() {
			return kTunnel
		}
		return kBlock
	}
	for _, x := range e.tun.DNS {
		if x == d {
			return kTunnel
		}
	}
	if in.DstPort == 53 {
		if e.dnsDst.IsValid() {
			return kDNS
		}
		return kTunnel
	}
	for _, p := range e.tun.Prefixes {
		if p.Masked().Contains(d) {
			return kTunnel
		}
	}
	for _, p := range lanV4 {
		if p.Contains(d) {
			return kLAN
		}
	}
	for _, p := range e.nets {
		if p.Contains(d) {
			return kLAN
		}
	}
	return kTunnel
}

func (e *Engine) toTunnel(ip []byte, in *pkt.Info, f *flow) {
	src := e.tun.Addr4
	if in.V6 {
		src = e.tun.Addr6
	}
	var dst netip.Addr
	if f.kind == kDNS {
		dst = f.remote.Addr()
	}
	// Соединение, начатое до нас (не SYN), через туннель не продолжить.
	if in.Proto == pkt.ProtoTCP && in.FirstFrag && in.TCPFlags&pkt.TCPSyn == 0 && in.TCPFlags&pkt.TCPRst == 0 && !f.seenSyn() {
		e.block(ip, in, f)
		return
	}
	mtu := e.tun.MTU
	if in.Proto == pkt.ProtoTCP && in.FirstFrag {
		f.markSyn(in.TCPFlags)
		mss := mtu - 40
		if in.V6 {
			mss = mtu - 60
		}
		pkt.ClampMSS(ip, in, uint16(mss))
	}
	pkt.Rewrite(ip, in, src, dst)
	if len(ip) <= mtu {
		e.send(ip)
		return
	}
	if !in.V6 && !in.DF {
		for _, fr := range pkt.Fragment4(ip, in, mtu) {
			e.send(fr)
		}
		return
	}
	// большой пакет с DF: сообщаем стеку MTU туннеля (по исходному пакету)
	pkt.Rewrite(ip, in, f.key.src.Addr(), f.key.dst.Addr())
	e.toStack(f, pkt.Unreachable(ip, in, f.key.dst.Addr(), 4, uint16(mtu)))
}

func (e *Engine) send(p []byte) {
	if e.tun.Send(p) {
		e.Stats.ToTunnel.Add(1)
	} else {
		e.Stats.Dropped.Add(1)
	}
}

// block — «сети нет»: TCP получает RST, UDP — ICMP «порт недоступен».
func (e *Engine) block(ip []byte, in *pkt.Info, f *flow) {
	e.Stats.Blocked.Add(1)
	if !in.FirstFrag {
		return
	}
	switch in.Proto {
	case pkt.ProtoTCP:
		if in.TCPFlags&pkt.TCPRst == 0 {
			e.toStack(f, pkt.TCPReset(ip, in))
		}
	case pkt.ProtoUDP:
		code := byte(3)
		if in.V6 {
			code = 4
		}
		e.toStack(f, pkt.Unreachable(ip, in, in.Dst, code, 0))
	}
}

// toStack заворачивает IP-пакет в Ethernet и отдаёт стеку Windows.
func (e *Engine) toStack(f *flow, ip []byte) {
	if len(ip)+14 > A.MAX_ETHER_FRAME {
		e.Stats.Dropped.Add(1)
		return
	}
	fr := make([]byte, 14+len(ip))
	copy(fr[0:6], f.hostM[:])
	copy(fr[6:12], f.gwM[:])
	et := uint16(0x0800)
	if ip[0]>>4 == 6 {
		et = 0x86DD
	}
	binary.BigEndian.PutUint16(fr[12:14], et)
	copy(fr[14:], ip)
	select {
	case e.inject <- frame{f.ad, fr}:
	default:
		e.Stats.Dropped.Add(1)
	}
}

func (e *Engine) injector(done chan struct{}) {
	bufs := make([]A.IntermediateBuffer, 64)
	ptrs := make([]*A.IntermediateBuffer, 0, len(bufs))
	for {
		var fr frame
		select {
		case fr = <-e.inject:
		case <-done:
			return
		}
		ptrs = ptrs[:0]
		for {
			b := &bufs[len(ptrs)]
			b.HAdapterQLinkUnion.SetAdapter(fr.ad)
			b.DeviceFlags = A.PACKET_FLAG_ON_RECEIVE
			b.Flags, b.M8021q, b.FilterID = 0, 0, 0
			b.Length = uint32(copy(b.Buffer[:], fr.b))
			ptrs = append(ptrs, b)
			if len(ptrs) == len(bufs) {
				break
			}
			select {
			case fr = <-e.inject:
				continue
			default:
			}
			break
		}
		var sent uint32
		e.api.SendPacketsToMstcpUnsorted(ptrs, uint32(len(ptrs)), &sent)
	}
}

// fromTunnel — пакет от сервера: обратный NAT и в стек.
func (e *Engine) fromTunnel(p []byte) {
	e.Stats.FromTunnel.Add(1)
	in, ok := pkt.Parse(p)
	if !ok || (in.Dst != e.tun.Addr4 && in.Dst != e.tun.Addr6) {
		return
	}
	ip := append([]byte(nil), p[:in.TotalLen]...)
	var f *flow
	switch {
	case in.Fragment && !in.FirstFrag:
		e.mu.Lock()
		fe, ok := e.fragsIn[fragKey{in.Src, in.Dst, in.ID, in.Proto}]
		e.mu.Unlock()
		if !ok {
			return
		}
		f = fe.f
	case in.Proto == pkt.ProtoTCP || in.Proto == pkt.ProtoUDP:
		e.mu.Lock()
		f = e.nat[natKey{in.Proto, in.DstPort, netip.AddrPortFrom(in.Src, in.SrcPort)}]
		if f != nil && in.Fragment {
			e.fragsIn[fragKey{in.Src, in.Dst, in.ID, in.Proto}] = fragEnt{f, time.Now()}
		}
		e.mu.Unlock()
	case in.Proto == pkt.ProtoICMP || in.Proto == pkt.ProtoICMPv6:
		e.icmpError(ip, &in)
		return
	}
	if f == nil || !e.healthy.Load() {
		return
	}
	var src netip.Addr
	if f.kind == kDNS {
		src = f.key.dst.Addr()
	}
	if in.Proto == pkt.ProtoTCP && in.FirstFrag {
		mss := e.tun.MTU - 40
		if in.V6 {
			mss = e.tun.MTU - 60
		}
		pkt.ClampMSS(ip, &in, uint16(mss))
	}
	pkt.Rewrite(ip, &in, src, f.key.src.Addr())
	e.toStack(f, ip)
}

// icmpError транслирует ICMP-ошибку из туннеля, вложенный пакет которой
// принадлежит нашему потоку.
func (e *Engine) icmpError(ip []byte, in *pkt.Info) {
	l4 := ip[in.HdrLen:]
	if len(l4) < 8 {
		return
	}
	t := l4[0]
	if in.V6 {
		if t > 4 {
			return
		}
	} else if t != 3 && t != 11 && t != 12 {
		return
	}
	inner := l4[8:]
	ii, ok := parsePartial(inner)
	if !ok {
		return
	}
	e.mu.Lock()
	f := e.nat[natKey{ii.Proto, ii.SrcPort, netip.AddrPortFrom(ii.Dst, ii.DstPort)}]
	e.mu.Unlock()
	if f == nil {
		return
	}
	// вложенный: src → исходный локальный адрес, dst → исходный адресат
	pkt.SetSrc(inner, f.key.src.Addr())
	pkt.SetDst(inner, f.key.dst.Addr())
	if !ii.V6 {
		hl := int(inner[0]&0x0f) * 4
		inner[10], inner[11] = 0, 0
		binary.BigEndian.PutUint16(inner[10:12], ipChecksum(inner[:hl]))
	}
	var from netip.Addr
	if f.kind == kDNS {
		from = f.key.dst.Addr()
	}
	pkt.Rewrite(ip, in, from, f.key.src.Addr())
	e.toStack(f, ip)
}

// parsePartial разбирает обрезанный вложенный пакет ICMP-ошибки.
func parsePartial(p []byte) (pkt.Info, bool) {
	var in pkt.Info
	if len(p) < 20 {
		return in, false
	}
	var l4 []byte
	switch p[0] >> 4 {
	case 4:
		hl := int(p[0]&0x0f) * 4
		if len(p) < hl+4 {
			return in, false
		}
		in.Proto = p[9]
		in.Src = netip.AddrFrom4([4]byte(p[12:16]))
		in.Dst = netip.AddrFrom4([4]byte(p[16:20]))
		l4 = p[hl:]
	case 6:
		if len(p) < 44 {
			return in, false
		}
		in.V6 = true
		in.Proto = p[6]
		in.Src = netip.AddrFrom16([16]byte(p[8:24]))
		in.Dst = netip.AddrFrom16([16]byte(p[24:40]))
		l4 = p[40:]
	default:
		return in, false
	}
	in.SrcPort = binary.BigEndian.Uint16(l4[0:2])
	in.DstPort = binary.BigEndian.Uint16(l4[2:4])
	return in, true
}

func ipChecksum(h []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(h); i += 2 {
		s += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

// housekeeping: состояние туннеля и чистка таблиц.
func (e *Engine) housekeeping(done chan struct{}) {
	tk := time.NewTicker(500 * time.Millisecond)
	defer tk.Stop()
	var sweep int
	for {
		select {
		case <-tk.C:
		case <-done:
			return
		}
		h := e.tun.Healthy()
		if e.healthy.Swap(h) != h {
			if h {
				e.log.Printf("туннель: связь есть")
			} else {
				e.log.Printf("туннель: связи нет — программам из правила сеть закрыта")
			}
		}
		if sweep++; sweep%20 != 0 {
			continue
		}
		now := time.Now()
		e.mu.Lock()
		for k, f := range e.flows {
			idle := now.Sub(time.Unix(0, f.last.Load()))
			ttl := 2 * time.Minute
			if k.proto == pkt.ProtoUDP {
				ttl = time.Minute
			}
			if f.rule && k.proto == pkt.ProtoTCP {
				ttl = 5 * time.Minute
			}
			if idle > ttl {
				delete(e.flows, k)
				if n := e.nat[natKey{k.proto, k.src.Port(), f.remote}]; n == f {
					delete(e.nat, natKey{k.proto, k.src.Port(), f.remote})
				}
			}
		}
		for k, v := range e.fragsOut {
			if now.Sub(v.seen) > 30*time.Second {
				delete(e.fragsOut, k)
			}
		}
		for k, v := range e.fragsIn {
			if now.Sub(v.seen) > 30*time.Second {
				delete(e.fragsIn, k)
			}
		}
		e.mu.Unlock()
	}
}

func (e *Engine) Healthy() bool { return e.healthy.Load() }

func protoName(p byte) string {
	switch p {
	case pkt.ProtoTCP:
		return "tcp"
	case pkt.ProtoUDP:
		return "udp"
	}
	return fmt.Sprint(p)
}
