package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"vpnsbx/internal/profile"
)

const ipURL = "https://api.ipify.org"

func fetchIP(c *http.Client) (string, error) {
	resp, err := c.Get(ipURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	return strings.TrimSpace(string(b)), err
}

// tunnelTest поднимает туннель в userspace-стеке (gVisor) без драйверов и
// адаптеров и сравнивает внешний IP через туннель и напрямую.
func tunnelTest(path string, verbose bool) error {
	p, err := profile.Load(path)
	if err != nil {
		return err
	}
	if p.Kind != profile.KindAWG {
		return fmt.Errorf("%s: поддерживается только AWG/WireGuard", p.Name)
	}
	a, err := profile.ParseAWG(p.Text)
	if err != nil {
		return fmt.Errorf("%s: %w", p.Name, err)
	}
	eps, err := a.ResolveEndpoints(profile.SystemResolver)
	if err != nil {
		return err
	}

	var addrs []netip.Addr
	for _, pr := range a.Addresses {
		addrs = append(addrs, pr.Addr())
	}
	dns := a.DNS
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	fmt.Printf("профиль %s (%s): MTU %d, пиров %d, DNS из профиля: %d шт.\n", p.Name, p.Source, a.MTU, len(a.Peers), len(a.DNS))

	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, a.MTU)
	if err != nil {
		return err
	}
	lvl := device.LogLevelError
	if verbose {
		lvl = device.LogLevelVerbose
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(lvl, "awg: "))
	defer dev.Close()
	if err := dev.IpcSet(a.UAPI(eps)); err != nil {
		return fmt.Errorf("IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return err
	}

	direct, derr := fetchIP(&http.Client{Timeout: 10 * time.Second})
	if derr != nil {
		direct = "ошибка: " + derr.Error()
	}

	t0 := time.Now()
	vc := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: tnet.DialContext},
	}
	via, err := fetchIP(vc)
	if err != nil {
		return fmt.Errorf("через туннель: %w", err)
	}
	fmt.Printf("внешний IP напрямую:      %s\n", maskIP(direct))
	fmt.Printf("внешний IP через туннель: %s  (%.1f с)\n", maskIP(via), time.Since(t0).Seconds())
	if via == direct {
		fmt.Println("ВНИМАНИЕ: совпадают — возможно, хост сам уже сидит на этом VPN")
	}
	for _, ep := range eps {
		if ep.Addr().String() == via {
			fmt.Println("выход в интернет = адрес сервера из Endpoint")
		}
	}
	if hs := handshakeAge(dev); hs >= 0 {
		fmt.Printf("последнее рукопожатие: %d с назад\n", hs)
	}

	// DNS через туннель (резолвер netstack, серверы из профиля)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ips, err := tnet.LookupContextHost(ctx, "example.com"); err != nil {
		fmt.Println("DNS через туннель: ошибка:", err)
	} else {
		fmt.Println("DNS через туннель: example.com ->", strings.Join(ips, ", "))
	}
	return nil
}

// maskIP скрывает хвост адреса: 203.0.113.7 -> 203.0.x.x
func maskIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.x.x", b[0], b[1])
	}
	p, _ := a.Prefix(32)
	return p.Addr().String() + ":x"
}

func handshakeAge(dev *device.Device) int64 {
	s, err := dev.IpcGet()
	if err != nil {
		return -1
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "last_handshake_time_sec="); ok {
			var sec int64
			fmt.Sscan(v, &sec)
			if sec > 0 {
				return time.Now().Unix() - sec
			}
		}
	}
	return -1
}
