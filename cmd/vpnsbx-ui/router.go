package main

// Панель роутера прямо на вкладке «VMware-контур». Окно ходит в тот же JSON
// API, что и веб-панель роутера (vmgw-web.py: /api/login, /api/status,
// /api/action), — поэтому работает с роутером любой версии как есть: что он
// отдаёт в status и какие действия принимает, то окно и показывает. Тело
// действия передаётся роутеру без разбора: новые действия новых версий
// проходят без правки этого файла.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

type routerReq struct {
	Dir      string
	Op       string // status | login | logout | action
	Password string
	Remember bool
	Body     json.RawMessage
}

// routerRes.State: ok — есть data (или итог действия); login — нужен пароль
// панели; down — роутер не отвечает или не пускает этот компьютер.
type routerRes struct {
	State  string          `json:"state"`
	Ok     bool            `json:"ok"`
	Output string          `json:"output"`
	Data   json.RawMessage `json:"data,omitempty"`
	Base   string          `json:"base"`
	Saved  bool            `json:"saved"` // пароль запомнен в Windows
}

type routerClient struct {
	mu   sync.Mutex
	base string
	jar  http.CookieJar
	pw   string // пароль этого сеанса окна (в памяти)
}

var (
	routersMu sync.Mutex
	routers   = map[string]*routerClient{}
)

func routerFor(dir string) (*routerClient, error) {
	if err := needLab(dir); err != nil {
		return nil, err
	}
	li := readLab(dir, func(string) bool { return false })
	if li.Err != "" {
		return nil, errors.New(li.Err)
	}
	addr, err := netip.ParseAddr(li.MgmtAddr)
	if err != nil || li.PanelPort < 1 || li.PanelPort > 65535 {
		return nil, errors.New("в lab.json нет адреса панели роутера (MgmtAddr, PanelPort)")
	}
	// Панель пускает только по IP-литералу с её портом в Host (защита от DNS rebinding).
	base := "http://" + netip.AddrPortFrom(addr, uint16(li.PanelPort)).String()
	routersMu.Lock()
	defer routersMu.Unlock()
	k := normPath(dir)
	c := routers[k]
	if c == nil {
		c = &routerClient{}
		routers[k] = c
	}
	c.mu.Lock()
	if c.base != base { // адрес в lab.json сменился — старая сессия не годится
		c.base, c.jar = base, nil
	}
	if c.jar == nil {
		c.jar, _ = cookiejar.New(nil)
	}
	c.mu.Unlock()
	return c, nil
}

var routerDialer = &net.Dialer{Timeout: 4 * time.Second}

// call — один запрос к панели. code 0 — сеть (роутер выключен, нет маршрута).
func (c *routerClient) call(method, path string, body any, timeout time.Duration) (int, routerRes, error) {
	c.mu.Lock()
	base, jar := c.base, c.jar
	c.mu.Unlock()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, routerRes{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return 0, routerRes{}, err
	}
	req.Header.Set("X-VMGW", "1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := &http.Client{Jar: jar, Timeout: timeout, Transport: &http.Transport{
		Proxy: nil, DialContext: routerDialer.DialContext, DisableKeepAlives: true,
	}}
	resp, err := hc.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, routerRes{}, errors.New("роутер не ответил вовремя (" + base + ")")
		}
		return 0, routerRes{}, errors.New("роутер недоступен (" + base + "): включите ВМ router и проверьте сеть управления")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	var r struct {
		Ok     bool            `json:"ok"`
		Output json.RawMessage `json:"output"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &r) != nil {
		if resp.StatusCode == http.StatusForbidden {
			return resp.StatusCode, routerRes{}, errors.New("роутер не пускает этот компьютер в панель (403): адрес Windows вне сети управления и AdminNets")
		}
		if resp.StatusCode == http.StatusNotFound {
			return resp.StatusCode, routerRes{}, errors.New("по адресу " + base + " нет такой функции панели (404)")
		}
		return resp.StatusCode, routerRes{}, fmt.Errorf("панель роутера ответила HTTP %d", resp.StatusCode)
	}
	out := routerRes{Ok: r.Ok, Data: r.Data, Base: base}
	// output — строка; на случай иного формата у другой версии — как есть.
	if json.Unmarshal(r.Output, &out.Output) != nil && len(r.Output) > 0 && string(r.Output) != "null" {
		out.Output = string(r.Output)
	}
	return resp.StatusCode, out, nil
}

func (c *routerClient) login(dir, pw string) (int, routerRes, error) {
	code, r, err := c.call("POST", "/api/login", map[string]string{"password": pw}, 15*time.Second)
	if err == nil && code == http.StatusOK && r.Ok {
		c.mu.Lock()
		c.pw = pw
		c.mu.Unlock()
	}
	return code, r, err
}

// relogin входит заново паролем сеанса или запомненным; false — пароля нет
// или он больше не подходит (тогда окно спросит его).
func (c *routerClient) relogin(dir string) (bool, string) {
	c.mu.Lock()
	pw := c.pw
	c.mu.Unlock()
	saved := false
	if pw == "" {
		pw, saved = loadPanelPass(dir), true
	}
	if pw == "" {
		return false, ""
	}
	code, r, err := c.login(dir, pw)
	if err != nil {
		return false, err.Error()
	}
	if code == http.StatusOK && r.Ok {
		return true, ""
	}
	if code == http.StatusForbidden {
		c.mu.Lock()
		c.pw = ""
		c.mu.Unlock()
		if saved {
			savePanelPass(dir, "")
		}
		return false, "сохранённый пароль панели больше не подходит"
	}
	return false, r.Output
}

func vmgwRouter(a routerReq) (routerRes, error) {
	c, err := routerFor(a.Dir)
	if err != nil {
		return routerRes{}, err
	}
	down := func(err error) (routerRes, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return routerRes{State: "down", Output: err.Error(), Base: c.base}, nil
	}
	needLogin := func(msg string) (routerRes, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return routerRes{State: "login", Output: msg, Base: c.base, Saved: loadPanelPass(a.Dir) != ""}, nil
	}
	// do выполняет запрос; на 401 один раз входит заново и повторяет.
	do := func(method, path string, body any, timeout time.Duration) (routerRes, error) {
		code, r, err := c.call(method, path, body, timeout)
		if err == nil && code == http.StatusUnauthorized {
			ok, msg := c.relogin(a.Dir)
			if !ok {
				return needLogin(msg)
			}
			code, r, err = c.call(method, path, body, timeout)
		}
		if err != nil {
			if code == 0 || code == http.StatusForbidden {
				return down(err)
			}
			return routerRes{}, err
		}
		if code == http.StatusUnauthorized {
			return needLogin(r.Output)
		}
		r.State = "ok"
		r.Saved = loadPanelPass(a.Dir) != ""
		return r, nil
	}

	switch a.Op {
	case "status":
		return do("GET", "/api/status", nil, 40*time.Second)
	case "login":
		if a.Password == "" {
			return needLogin("введите пароль панели")
		}
		code, r, err := c.login(a.Dir, a.Password)
		if err != nil {
			return down(err)
		}
		if code != http.StatusOK || !r.Ok {
			if r.Output == "" {
				r.Output = fmt.Sprintf("вход не удался (HTTP %d)", code)
			}
			return needLogin(r.Output)
		}
		if a.Remember {
			if err := savePanelPass(a.Dir, a.Password); err != nil {
				return routerRes{}, errors.New("вход выполнен, но пароль не сохранён: " + err.Error())
			}
		}
		return do("GET", "/api/status", nil, 40*time.Second)
	case "logout":
		c.call("POST", "/api/logout", nil, 5*time.Second)
		c.mu.Lock()
		c.pw = ""
		c.jar, _ = cookiejar.New(nil)
		c.mu.Unlock()
		savePanelPass(a.Dir, "")
		return needLogin("")
	case "action":
		var probe map[string]any
		if json.Unmarshal(a.Body, &probe) != nil || probe["action"] == nil {
			return routerRes{}, errors.New("неверное действие")
		}
		// Контроллер роутера ждёт до 180 с (пересборка туннелей, OpenVPN).
		return do("POST", "/api/action", a.Body, 200*time.Second)
	}
	return routerRes{}, errors.New("неизвестная операция: " + a.Op)
}

// ---------------------------------------------------------------- пароль панели

// Пароли панелей, если пользователь попросил их запомнить, хранятся
// зашифрованными DPAPI (расшифровать может только эта учётная запись Windows).
var passMu sync.Mutex

func panelPassPath() string {
	return filepath.Join(filepath.Dir(uiStatePath()), "vmgw-panel.json")
}

func readPanelPasses() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(panelPassPath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func loadPanelPass(dir string) string {
	passMu.Lock()
	enc := readPanelPasses()[normPath(dir)]
	passMu.Unlock()
	if enc == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return ""
	}
	p, err := dpapi(b, false)
	if err != nil {
		return ""
	}
	return string(p)
}

// savePanelPass("") — забыть пароль.
func savePanelPass(dir, pw string) error {
	passMu.Lock()
	defer passMu.Unlock()
	m := readPanelPasses()
	k := normPath(dir)
	if pw == "" {
		if _, ok := m[k]; !ok {
			return nil
		}
		delete(m, k)
	} else {
		b, err := dpapi([]byte(pw), true)
		if err != nil {
			return err
		}
		m[k] = base64.StdEncoding.EncodeToString(b)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	p := panelPassPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func dpapi(in []byte, protect bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("пусто")
	}
	src := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	var dst windows.DataBlob
	name := u16("vpnsbx vmgw panel")
	var err error
	if protect {
		err = windows.CryptProtectData(&src, name, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &dst)
	} else {
		err = windows.CryptUnprotectData(&src, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &dst)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(dst.Data)))
	return bytes.Clone(unsafe.Slice(dst.Data, dst.Size)), nil
}

// ---------------------------------------------------------------- файлы профилей

type pickedText struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

// readProfileFile читает выбранный профиль как текст (как FileReader.readAsText
// в веб-панели: UTF-8 без BOM).
func readProfileFile(path string) (*pickedText, error) {
	if path == "" {
		return nil, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > 2<<20 {
		return nil, errors.New("файл больше 2 МБ — это не профиль")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(b) {
		b = []byte(strings.ToValidUTF8(string(b), "�"))
	}
	return &pickedText{Name: filepath.Base(path), Data: string(b)}, nil
}
