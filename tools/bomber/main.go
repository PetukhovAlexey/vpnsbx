// bomber — проверка утечки при загрузке. Ставится в автозагрузку под
// правило песочницы и с первой секунды долбит сеть: каждую секунду узнаёт
// свой внешний IP по TCP (HTTPS api.ipify.org) и по UDP (STUN) и пишет результат в bomber.log рядом с exe.
// Первые 5 минут — раз в секунду, дальше — раз в минуту.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"vpnsbx/internal/stun"
)

const burst = 5 * time.Minute

var (
	logf  *os.File
	start = time.Now()
)

func main() {
	exe, _ := os.Executable()
	f, err := os.OpenFile(filepath.Join(filepath.Dir(exe), "bomber.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		os.Exit(1)
	}
	logf = f
	up := uptime()
	logln("==== старт pid %d, система работает %s, служба vpnsbx: %s", os.Getpid(), up.Round(time.Second), svcState())

	seen := map[string]int{}
	for i := 0; ; i++ {
		t0 := time.Now()
		var wg sync.WaitGroup
		var web, udp string
		wg.Add(2)
		go func() { defer wg.Done(); web = res(httpsIP()) }()
		go func() { defer wg.Done(); udp = res(stunIP()) }()
		wg.Wait()
		if seen != nil {
			seen["tcp "+web]++
			seen["udp "+udp]++
		}
		inBurst := time.Since(start) < burst
		line := fmt.Sprintf("tcp=%s udp=%s", web, udp)
		if inBurst || i%5 == 0 {
			line += " служба=" + svcState()
		}
		logln("%s", line)
		if !inBurst && seen != nil {
			summary(seen)
			seen = nil
		}
		next := time.Second
		if !inBurst {
			next = time.Minute
		}
		time.Sleep(next - min(time.Since(t0), next))
	}
}

func logln(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	fmt.Fprintf(logf, "%s +%6.1fs %s\r\n", time.Now().Format("2006-01-02 15:04:05.000"), time.Since(start).Seconds(), s)
}

func summary(seen map[string]int) {
	var ks []string
	for k := range seen {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	logln("==== итог первых %s:", burst)
	for _, k := range ks {
		logln("     %4d × %s", seen[k], k)
	}
}

func res(ip netip.Addr, err error) string {
	if err != nil {
		s := err.Error()
		switch {
		case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
			return "НЕТ_СВЯЗИ(таймаут)"
		case strings.Contains(s, "no such host"):
			return "НЕТ_СВЯЗИ(dns)"
		}
		if len(s) > 80 {
			s = s[:80]
		}
		return "НЕТ_СВЯЗИ(" + strings.ReplaceAll(s, " ", "_") + ")"
	}
	return ip.String()
}

// Каждый раз новое соединение: проверяется каждый новый поток, а не один
// закешированный.
var client = &http.Client{
	Timeout:   4 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil},
}

func httpsIP() (netip.Addr, error) {
	r, err := client.Get("https://api.ipify.org")
	if err != nil {
		return netip.Addr{}, err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(strings.TrimSpace(string(b)))
}

// stunIP — внешний адрес по UDP (STUN, как WebRTC и игры). Не DNS: в
// песочнице порт 53 уходит на DNS профиля, myip.opendns.com там не ответит.
func stunIP() (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	srv := stun.Servers(ctx)
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	req, id := stun.Request()
	dl, _ := ctx.Deadline()
	buf := make([]byte, 1500)
	for i := 0; ; i++ {
		if _, err := c.WriteToUDPAddrPort(req, srv[i%len(srv)]); err != nil {
			return netip.Addr{}, err
		}
		rd := time.Now().Add(time.Second)
		if rd.After(dl) {
			rd = dl
		}
		c.SetReadDeadline(rd)
		for {
			n, _, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				if time.Now().After(dl) {
					return netip.Addr{}, err
				}
				break
			}
			if a, err := stun.Parse(buf[:n], id); err == nil {
				return a.Addr(), nil
			}
		}
	}
}

var getTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

func uptime() time.Duration {
	ms, _, _ := getTickCount64.Call()
	return time.Duration(ms) * time.Millisecond
}

func svcState() string {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "?"
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("vpnsbx")
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "нет"
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return "?"
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return "работает"
	case windows.SERVICE_START_PENDING:
		return "запускается"
	case windows.SERVICE_STOPPED:
		return "остановлена"
	}
	return fmt.Sprint(st.CurrentState)
}
