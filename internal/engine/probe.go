package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"vpnsbx/internal/pkt"
	"vpnsbx/internal/stun"
)

// Внешний IP узнаётся по STUN: сервер возвращает адрес, с которого пришёл
// UDP-пакет. Через туннель это адрес выхода VPN, напрямую — настоящий
// адрес хоста. Не DNS: провайдеры VPN нередко перехватывают порт 53.

type probeKey struct {
	port   uint16
	remote netip.AddrPort
}

// ExternalIP — внешний адрес, который видят серверы, когда программа ходит
// через туннель профиля.
func (e *Engine) ExternalIP(ctx context.Context, profileID string) (netip.Addr, error) {
	e.mu.Lock()
	ts := e.tunnels[profileID]
	e.mu.Unlock()
	if ts == nil {
		return netip.Addr{}, errors.New("туннеля профиля нет")
	}
	if p := ts.err.Load(); p != nil {
		return netip.Addr{}, errors.New(*p)
	}
	if ts.tun.Load() == nil || !ts.addr4.IsValid() {
		return netip.Addr{}, errors.New("туннель ещё не поднят")
	}
	srv := stun.Servers(ctx)
	req, id := stun.Request()
	ch := make(chan []byte, 1)
	var port uint16
	e.mu.Lock()
	for free := false; !free; {
		port, free = uint16(20000+rand.IntN(40000)), true
		for _, s := range srv {
			if ts.nat[natKey{pkt.ProtoUDP, port, s}] != nil || e.probes[probeKey{port, s}] != nil {
				free = false
			}
		}
	}
	for _, s := range srv {
		e.probes[probeKey{port, s}] = ch
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		for _, s := range srv {
			delete(e.probes, probeKey{port, s})
		}
		e.mu.Unlock()
	}()
	tk := time.NewTicker(time.Second) // UDP: повторять, пока не ответят
	defer tk.Stop()
	for i := 0; ; i++ {
		e.send(ts, pkt.UDP4(netip.AddrPortFrom(ts.addr4, port), srv[i%len(srv)], req))
		for {
			select {
			case b := <-ch:
				if a, err := stun.Parse(b, id); err == nil {
					return a.Addr(), nil
				}
				continue
			case <-tk.C:
			case <-ctx.Done():
				return netip.Addr{}, errors.New("сервер проверки не ответил через туннель")
			}
			break
		}
	}
}

// DirectIP — настоящий внешний адрес хоста (запрос из службы идёт мимо фильтра).
func DirectIP(ctx context.Context) (netip.Addr, error) {
	srv := stun.Servers(ctx)
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	req, id := stun.Request()
	buf := make([]byte, 1500)
	for i := 0; ; i++ {
		if _, err := c.WriteToUDPAddrPort(req, srv[i%len(srv)]); err != nil {
			return netip.Addr{}, err
		}
		dl := time.Now().Add(time.Second)
		if t, ok := ctx.Deadline(); ok && t.Before(dl) {
			dl = t
		}
		c.SetReadDeadline(dl)
		for {
			n, _, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if a, err := stun.Parse(buf[:n], id); err == nil {
				return a.Addr(), nil
			}
		}
		if ctx.Err() != nil {
			return netip.Addr{}, errors.New("сервер проверки не ответил")
		}
	}
}

// probeReply — ответ на проверку внешнего IP (под e.mu). true — пакет наш.
func (e *Engine) probeReply(in *pkt.Info, p []byte) bool {
	if in.Proto != pkt.ProtoUDP || in.Fragment || len(e.probes) == 0 {
		return false
	}
	ch := e.probes[probeKey{in.DstPort, netip.AddrPortFrom(in.Src, in.SrcPort)}]
	if ch == nil {
		return false
	}
	if l := int(binary.BigEndian.Uint16(p[in.HdrLen+4:])); l >= 8 && in.HdrLen+l <= len(p) {
		select {
		case ch <- append([]byte(nil), p[in.HdrLen+8:in.HdrLen+l]...):
		default:
		}
	}
	return true
}
