// Package engine — перехват исходящих пакетов драйвером NDISRD: трафик
// процессов из правил уходит в AWG-туннели внутри процесса (у каждого
// профиля свой), остальное проходит как есть. Если туннель правила не
// работает, процессы правила не получают никакой сети (включая LAN).
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
	Adapter string // имя адаптера; пусто — все подходящие
	Log     *log.Logger
	Verbose bool

	// Испытания: имитировать обрыв всех туннелей в окне [CutFrom, CutTo) от старта.
	CutFrom, CutTo time.Duration
}

// ProfileSpec — профиль AWG по ID. Text сравнивается при Apply: изменился —
// туннель перезапускается.
type ProfileSpec struct {
	ID, Name, Text string
}

// RuleSpec — правило и ID профиля, через который идёт его трафик.
// Профиля нет или туннель не поднят — сети у процессов правила нет.
type RuleSpec struct {
	proc.Rule
	Profile string
}

// Setup — профили и правила; меняется на ходу через Apply.
type Setup struct {
	Profiles []ProfileSpec
	Rules    []RuleSpec
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
	rule   string    // ID правила ("" — не под правилом)
	ts     *tunState // туннель правила (nil — профиля нет)
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

// tunState — туннель одного профиля. Адреса известны из профиля сразу,
// сам туннель поднимается в фоне (и переподнимается при ошибке).
type tunState struct {
	id, name, text string
	addr4, addr6   netip.Addr
	prefixes       []netip.Prefix
	dns            []netip.Addr
	dnsDst         netip.Addr // DNS туннеля для DNAT (IPv4)
	mtu            int

	tun     atomic.Pointer[tunnel.Tunnel]
	healthy atomic.Bool
	err     atomic.Pointer[string]
	nat     map[natKey]*flow // под Engine.mu
	stop    chan struct{}
	once    sync.Once
}

func (ts *tunState) setErr(err error) {
	if err == nil {
		ts.err.Store(nil)
		return
	}
	s := err.Error()
	ts.err.Store(&s)
}

func (ts *tunState) close() {
	ts.once.Do(func() {
		close(ts.stop)
		ts.healthy.Store(false)
	})
}

type Engine struct {
	cfg  Config
	log  *log.Logger
	api  *A.NdisApi
	ads  []adapter
	nets []netip.Prefix // подсети адаптеров хоста (LAN)

	owners  *proc.Owners
	tracker *proc.Tracker

	mu       sync.Mutex
	closed   bool
	gen      uint64               // растёт при каждом Apply
	tunnels  map[string]*tunState // ID профиля → туннель
	ruleTun  map[string]*tunState // ID правила → туннель (nil — профиля нет)
	flows    map[flowKey]*flow
	fragsOut map[fragKey]fragEnt
	fragsIn  map[fragKey]fragEnt

	inject chan frame // готовые Ethernet-кадры для стека

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
		tunnels:  map[string]*tunState{},
		ruleTun:  map[string]*tunState{},
		flows:    map[flowKey]*flow{},
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
	e.tracker = proc.NewTracker(nil)
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

// Apply заменяет профили и правила на ходу. Туннели удалённых и изменённых
// профилей закрываются, новые поднимаются в фоне. Потоки, у которых сменилось
// правило или туннель, забываются: следующий пакет классифицируется заново.
func (e *Engine) Apply(s Setup) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	want := map[string]ProfileSpec{}
	for _, p := range s.Profiles {
		want[p.ID] = p
	}
	for id, ts := range e.tunnels {
		if w, ok := want[id]; !ok || w.Text != ts.text {
			ts.close()
			delete(e.tunnels, id)
			e.log.Printf("туннель %q закрыт", ts.name)
		} else {
			ts.name = w.Name
		}
	}
	for _, p := range s.Profiles {
		if e.tunnels[p.ID] == nil {
			e.tunnels[p.ID] = e.startTunnel(p)
		}
	}

	var rules []proc.Rule
	e.ruleTun = map[string]*tunState{}
	for _, r := range s.Rules {
		rules = append(rules, r.Rule)
		e.ruleTun[r.ID] = e.tunnels[r.Profile]
	}
	e.gen++
	e.tracker.SetRules(proc.NewRules(rules))

	dropped := 0
	for k, f := range e.flows {
		var rule string
		if f.pid != 0 {
			rule, _ = e.tracker.Matched(f.pid)
		}
		if rule == f.rule && (rule == "" || e.ruleTun[rule] == f.ts) {
			continue
		}
		delete(e.flows, k)
		if f.ts != nil {
			nk := natKey{k.proto, k.src.Port(), f.remote}
			if f.ts.nat[nk] == f {
				delete(f.ts.nat, nk)
			}
		}
		dropped++
	}
	e.log.Printf("применено: профилей %d, правил %d, потоков сброшено %d", len(s.Profiles), len(s.Rules), dropped)
}

func (e *Engine) startTunnel(p ProfileSpec) *tunState {
	ts := &tunState{id: p.ID, name: p.Name, text: p.Text, nat: map[natKey]*flow{}, stop: make(chan struct{})}
	a, err := profile.ParseAWG(p.Text)
	if err != nil {
		ts.setErr(err)
		e.log.Printf("профиль %q: %v", p.Name, err)
		return ts
	}
	ts.prefixes, ts.dns, ts.mtu = a.Addresses, a.DNS, a.MTU
	for _, x := range a.Addresses {
		if x.Addr().Is4() && !ts.addr4.IsValid() {
			ts.addr4 = x.Addr()
		}
		if x.Addr().Is6() && !ts.addr6.IsValid() {
			ts.addr6 = x.Addr()
		}
	}
	for _, d := range a.DNS {
		if d.Is4() {
			ts.dnsDst = d
			break
		}
	}
	go func() {
		for {
			t, err := tunnel.Start(a, func(b []byte) { e.fromTunnel(ts, b) }, e.log)
			if err == nil {
				ts.setErr(nil)
				ts.tun.Store(t)
				e.log.Printf("туннель %q поднят", ts.name)
				<-ts.stop
				t.Close()
				return
			}
			ts.setErr(err)
			e.log.Printf("туннель %q: %v; повтор через 5 с", ts.name, err)
			select {
			case <-time.After(5 * time.Second):
			case <-ts.stop:
				return
			}
		}
	}()
	return ts
}

// shutdown закрывает туннели, трекер и драйвер. Apply после него ничего не делает.
func (e *Engine) shutdown() {
	e.mu.Lock()
	e.closed = true
	for _, ts := range e.tunnels {
		ts.close()
	}
	e.mu.Unlock()
	e.tracker.Close()
	e.api.Close()
}

// Run фильтрует до отмены ctx. Профили и правила задаются Apply (до или
// во время работы). После выхода движок непригоден.
func (e *Engine) Run(ctx context.Context) error {
	defer e.shutdown()
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
		go e.testCut(done)
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

func (e *Engine) testCut(done chan struct{}) {
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
		e.mu.Lock()
		for _, ts := range e.tunnels {
			if t := ts.tun.Load(); t != nil {
				t.SetCut(s.cut)
			}
		}
		e.mu.Unlock()
		e.log.Printf("ИСПЫТАНИЕ: имитация обрыва = %v", s.cut)
	}
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
	if f.rule == "" {
		return true
	}
	f.last.Store(time.Now().UnixNano())

	if f.ts == nil || !f.ts.healthy.Load() || f.kind == kBlock {
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
	gen := e.gen
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
	if f.rule != "" {
		e.mu.Lock()
		f.ts = e.ruleTun[f.rule]
		e.mu.Unlock()
		f.kind = classify(in, f.ts, e.nets)
		f.ad = ad
		copy(f.gwM[:], fr[0:6])
		copy(f.hostM[:], fr[6:12])
		if f.kind == kDNS {
			f.remote = netip.AddrPortFrom(f.ts.dnsDst, in.DstPort)
		}
		name := "—"
		if f.ts != nil {
			name = f.ts.name
		}
		e.log.Printf("pid %d %s [%s]: %s %s → %s",
			pid, e.tracker.Path(pid), name, protoName(in.Proto), k.dst, f.kind)
	}
	f.last.Store(time.Now().UnixNano())
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gen != gen {
		return f // правила сменились, пока искали: поток не запоминаем
	}
	if old := e.flows[k]; old != nil {
		return old
	}
	e.flows[k] = f
	if f.ts != nil && (f.kind == kTunnel || f.kind == kDNS) {
		f.ts.nat[natKey{in.Proto, in.SrcPort, f.remote}] = f
	}
	return f
}

func classify(in *pkt.Info, ts *tunState, nets []netip.Prefix) kind {
	if ts == nil {
		return kBlock
	}
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
		if ts.addr6.IsValid() {
			return kTunnel
		}
		return kBlock
	}
	if !ts.addr4.IsValid() {
		return kBlock
	}
	for _, x := range ts.dns {
		if x == d {
			return kTunnel
		}
	}
	if in.DstPort == 53 {
		if ts.dnsDst.IsValid() {
			return kDNS
		}
		return kTunnel
	}
	for _, p := range ts.prefixes {
		if p.Masked().Contains(d) {
			return kTunnel
		}
	}
	for _, p := range lanV4 {
		if p.Contains(d) {
			return kLAN
		}
	}
	for _, p := range nets {
		if p.Contains(d) {
			return kLAN
		}
	}
	return kTunnel
}

func (e *Engine) toTunnel(ip []byte, in *pkt.Info, f *flow) {
	ts := f.ts
	src := ts.addr4
	if in.V6 {
		src = ts.addr6
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
	mtu := ts.mtu
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
		e.send(ts, ip)
		return
	}
	if !in.V6 && !in.DF {
		for _, fr := range pkt.Fragment4(ip, in, mtu) {
			e.send(ts, fr)
		}
		return
	}
	// большой пакет с DF: сообщаем стеку MTU туннеля (по исходному пакету)
	pkt.Rewrite(ip, in, f.key.src.Addr(), f.key.dst.Addr())
	e.toStack(f, pkt.Unreachable(ip, in, f.key.dst.Addr(), 4, uint16(mtu)))
}

func (e *Engine) send(ts *tunState, p []byte) {
	if t := ts.tun.Load(); t != nil && t.Send(p) {
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
func (e *Engine) fromTunnel(ts *tunState, p []byte) {
	e.Stats.FromTunnel.Add(1)
	in, ok := pkt.Parse(p)
	if !ok || (in.Dst != ts.addr4 && in.Dst != ts.addr6) {
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
		f = ts.nat[natKey{in.Proto, in.DstPort, netip.AddrPortFrom(in.Src, in.SrcPort)}]
		if f != nil && in.Fragment {
			e.fragsIn[fragKey{in.Src, in.Dst, in.ID, in.Proto}] = fragEnt{f, time.Now()}
		}
		e.mu.Unlock()
	case in.Proto == pkt.ProtoICMP || in.Proto == pkt.ProtoICMPv6:
		e.icmpError(ts, ip, &in)
		return
	}
	if f == nil || f.ts != ts || !ts.healthy.Load() {
		return
	}
	var src netip.Addr
	if f.kind == kDNS {
		src = f.key.dst.Addr()
	}
	if in.Proto == pkt.ProtoTCP && in.FirstFrag {
		mss := ts.mtu - 40
		if in.V6 {
			mss = ts.mtu - 60
		}
		pkt.ClampMSS(ip, &in, uint16(mss))
	}
	pkt.Rewrite(ip, &in, src, f.key.src.Addr())
	e.toStack(f, ip)
}

// icmpError транслирует ICMP-ошибку из туннеля, вложенный пакет которой
// принадлежит нашему потоку.
func (e *Engine) icmpError(ts *tunState, ip []byte, in *pkt.Info) {
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
	f := ts.nat[natKey{ii.Proto, ii.SrcPort, netip.AddrPortFrom(ii.Dst, ii.DstPort)}]
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

// housekeeping: состояние туннелей и чистка таблиц.
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
		e.mu.Lock()
		list := make([]*tunState, 0, len(e.tunnels))
		for _, ts := range e.tunnels {
			list = append(list, ts)
		}
		e.mu.Unlock()
		for _, ts := range list {
			t := ts.tun.Load()
			h := t != nil && t.Healthy()
			if ts.healthy.Swap(h) != h {
				if h {
					e.log.Printf("туннель %q: связь есть", ts.name)
				} else {
					e.log.Printf("туннель %q: связи нет — программам его правил сеть закрыта", ts.name)
				}
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
			if f.rule != "" && k.proto == pkt.ProtoTCP {
				ttl = 5 * time.Minute
			}
			if idle > ttl {
				delete(e.flows, k)
				if f.ts != nil {
					nk := natKey{k.proto, k.src.Port(), f.remote}
					if f.ts.nat[nk] == f {
						delete(f.ts.nat, nk)
					}
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

// TunnelStatus — состояние туннеля профиля.
type TunnelStatus struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Started bool      `json:"started"` // туннель поднят (ключи, сокет)
	Up      bool      `json:"up"`      // от сервера есть ответы
	Err     string    `json:"err,omitempty"`
	LastRx  time.Time `json:"lastRx"`
}

func (e *Engine) Tunnels() []TunnelStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []TunnelStatus
	for _, ts := range e.tunnels {
		s := TunnelStatus{ID: ts.id, Name: ts.name, Up: ts.healthy.Load()}
		if t := ts.tun.Load(); t != nil {
			s.Started, s.LastRx = true, t.LastRx()
		}
		if p := ts.err.Load(); p != nil {
			s.Err = *p
		}
		out = append(out, s)
	}
	return out
}

// Sandboxed — живые процессы под правилами.
func (e *Engine) Sandboxed() []proc.Proc { return e.tracker.Sandboxed() }

// RuleOf — ID правила процесса ("" — не в песочнице).
func (e *Engine) RuleOf(pid uint32) string {
	r, _ := e.tracker.Matched(pid)
	return r
}

func protoName(p byte) string {
	switch p {
	case pkt.ProtoTCP:
		return "tcp"
	case pkt.ProtoUDP:
		return "udp"
	}
	return fmt.Sprint(p)
}
