package profile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultMTU — MTU туннеля, если в профиле не задан (как у клиента Amnezia).
const DefaultMTU = 1376

// AWG — разобранный профиль AmneziaWG/WireGuard.
type AWG struct {
	Addresses []netip.Prefix
	DNS       []netip.Addr
	MTU       int
	Peers     []AWGPeer

	device [][2]string // строки UAPI уровня устройства (уже в формате UAPI)
}

type AWGPeer struct {
	Endpoint   string // host:port как в профиле; адрес резолвится в UAPI()
	AllowedIPs []netip.Prefix

	lines [][2]string // строки UAPI пира, кроме public_key/endpoint/allowed_ip
	pub   string      // hex
}

// Ключи wg-quick, которые к устройству не относятся.
var ignoredInterfaceKeys = map[string]bool{
	"table": true, "preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true, "fwmark": true,
}

func b64ToHex(v string, size int) (string, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", err
	}
	if len(b) != size {
		return "", fmt.Errorf("ожидалось %d байт, получено %d", size, len(b))
	}
	return hex.EncodeToString(b), nil
}

func parseFlag(v string) (string, error) {
	switch strings.ToLower(v) {
	case "on", "yes", "true", "1":
		return "true", nil
	case "off", "no", "false", "0":
		return "false", nil
	}
	return "", fmt.Errorf("не флаг: %q", v)
}

// snake: RekeyAfterTime -> rekey_after_time
func snake(k string) string {
	var b strings.Builder
	for i, r := range k {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ParseAWG разбирает текст .conf. Ошибки не содержат значений ключей.
func ParseAWG(text string) (*AWG, error) {
	a := &AWG{MTU: DefaultMTU}
	var iface bool
	for _, s := range ParseINI(text) {
		switch strings.ToLower(s.Name) {
		case "interface":
			if iface {
				return nil, fmt.Errorf("несколько секций [Interface]")
			}
			iface = true
			if err := a.parseInterface(s.Keys); err != nil {
				return nil, err
			}
		case "peer":
			p, err := parsePeer(s.Keys)
			if err != nil {
				return nil, err
			}
			a.Peers = append(a.Peers, *p)
		default:
			return nil, fmt.Errorf("неизвестная секция [%s]", s.Name)
		}
	}
	if !iface {
		return nil, fmt.Errorf("нет секции [Interface]")
	}
	if len(a.Peers) == 0 {
		return nil, fmt.Errorf("нет секции [Peer]")
	}
	if len(a.Addresses) == 0 {
		return nil, fmt.Errorf("в [Interface] нет Address")
	}
	return a, nil
}

func (a *AWG) parseInterface(keys []KV) error {
	for _, kv := range keys {
		k, v := kv.Key, kv.Value
		lk := strings.ToLower(k)
		if v == "" || ignoredInterfaceKeys[lk] {
			continue
		}
		switch lk {
		case "privatekey":
			h, err := b64ToHex(v, 32)
			if err != nil {
				return fmt.Errorf("PrivateKey: %w", err)
			}
			a.device = append(a.device, [2]string{"private_key", h})
		case "address":
			for _, s := range splitList(v) {
				p, err := netip.ParsePrefix(s)
				if err != nil {
					ad, err2 := netip.ParseAddr(s)
					if err2 != nil {
						return fmt.Errorf("Address: неверный адрес")
					}
					p = netip.PrefixFrom(ad, ad.BitLen())
				}
				a.Addresses = append(a.Addresses, p)
			}
		case "dns":
			for _, s := range splitList(v) {
				ad, err := netip.ParseAddr(s)
				if err != nil {
					continue // поисковые домены wg-quick
				}
				a.DNS = append(a.DNS, ad)
			}
		case "mtu":
			n, err := strconv.Atoi(v)
			if err != nil || n < 576 || n > 65535 {
				return fmt.Errorf("MTU: неверное значение")
			}
			a.MTU = n
		case "listenport":
			a.device = append(a.device, [2]string{"listen_port", v})
		case "headerprotectionkey":
			h, err := b64ToHex(v, 32)
			if err != nil {
				return fmt.Errorf("HeaderProtectionKey: %w", err)
			}
			a.device = append(a.device, [2]string{"header_protection_key", h})
		case "randomtrailers", "disablecookies":
			f, err := parseFlag(v)
			if err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
			a.device = append(a.device, [2]string{snake(k), f})
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
			"i1", "i2", "i3", "i4", "i5":
			a.device = append(a.device, [2]string{lk, v})
		default:
			// RekeyAfterTime, KeepaliveTimeout, ContentPaddingAddition и т.п.
			// Неизвестный ключ отвергнет сам IpcSet.
			a.device = append(a.device, [2]string{snake(k), v})
		}
	}
	return nil
}

func parsePeer(keys []KV) (*AWGPeer, error) {
	p := &AWGPeer{}
	for _, kv := range keys {
		k, v := kv.Key, kv.Value
		if v == "" {
			continue
		}
		switch strings.ToLower(k) {
		case "publickey":
			h, err := b64ToHex(v, 32)
			if err != nil {
				return nil, fmt.Errorf("PublicKey: %w", err)
			}
			p.pub = h
		case "presharedkey":
			h, err := b64ToHex(v, 32)
			if err != nil {
				return nil, fmt.Errorf("PresharedKey: %w", err)
			}
			p.lines = append(p.lines, [2]string{"preshared_key", h})
		case "endpoint":
			if _, _, err := net.SplitHostPort(v); err != nil {
				return nil, fmt.Errorf("Endpoint: неверный формат")
			}
			p.Endpoint = v
		case "allowedips":
			for _, s := range splitList(v) {
				pr, err := netip.ParsePrefix(s)
				if err != nil {
					return nil, fmt.Errorf("AllowedIPs: неверная подсеть")
				}
				p.AllowedIPs = append(p.AllowedIPs, pr.Masked())
			}
		case "persistentkeepalive":
			if strings.EqualFold(v, "off") {
				continue
			}
			p.lines = append(p.lines, [2]string{"persistent_keepalive_interval", v})
		default:
			p.lines = append(p.lines, [2]string{snake(k), v})
		}
	}
	if p.pub == "" {
		return nil, fmt.Errorf("в [Peer] нет PublicKey")
	}
	if p.Endpoint == "" {
		return nil, fmt.Errorf("в [Peer] нет Endpoint")
	}
	return p, nil
}

// Resolver превращает хост из Endpoint в IP.
type Resolver func(host string) (netip.Addr, error)

// SystemResolver — системный DNS, предпочитает IPv4.
func SystemResolver(host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return netip.AddrFrom4([4]byte(v4)), nil
		}
	}
	if len(ips) > 0 {
		a, _ := netip.AddrFromSlice(ips[0])
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("%s: нет адресов", host)
}

// ResolveEndpoints возвращает IP:порт серверов (их трафик всегда идёт напрямую).
func (a *AWG) ResolveEndpoints(resolve Resolver) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, p := range a.Peers {
		h, ps, _ := net.SplitHostPort(p.Endpoint)
		ip, err := resolve(h)
		if err != nil {
			return nil, fmt.Errorf("Endpoint %s: %w", h, err)
		}
		port, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("Endpoint: неверный порт")
		}
		out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
	}
	return out, nil
}

// UAPI собирает конфигурацию для device.IpcSet. Результат содержит секреты.
func (a *AWG) UAPI(endpoints []netip.AddrPort) string {
	var b strings.Builder
	w := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	for _, kv := range a.device {
		w(kv[0], kv[1])
	}
	w("replace_peers", "true")
	for i, p := range a.Peers {
		w("public_key", p.pub)
		w("endpoint", endpoints[i].String())
		for _, kv := range p.lines {
			w(kv[0], kv[1])
		}
		w("replace_allowed_ips", "true")
		for _, pr := range p.AllowedIPs {
			w("allowed_ip", pr.String())
		}
	}
	return b.String()
}
