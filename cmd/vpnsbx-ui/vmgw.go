package main

// Вкладка «VMware-контур»: лаборатории vmgw (роутер + ведомые ВМ в VMware
// Workstation). Окно само читает lab.json и состояние ВМ, а создание ВМ и
// обновление выполняют те же скрипты комплекта, что Setup.cmd и Update.cmd
// (windows\*.ps1): поведение одно и то же, из окна или из консоли.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	vmNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	userRe   = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	cidrRe   = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+/\d+$`)
	netsRe   = regexp.MustCompile(`^(auto|none|[0-9./, ]*)$`)
)

// vmgwRoot — папка комплекта (guest\, windows\, README.md): рядом с
// программой (vmgw\ — так её кладёт установщик) или, при запуске из сборки,
// vmware-gateway\ в одной из родительских папок. VMGW_KIT — явно.
func vmgwRoot() (string, error) {
	ok := func(d string) bool {
		_, err := os.Stat(filepath.Join(d, "windows", "Update-VmGwLab.ps1"))
		return err == nil
	}
	if d := os.Getenv("VMGW_KIT"); d != "" && ok(d) {
		return d, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	if d := filepath.Join(dir, "vmgw"); ok(d) {
		return d, nil
	}
	for d := dir; ; d = filepath.Dir(d) {
		if c := filepath.Join(d, "vmware-gateway"); ok(c) {
			return c, nil
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return "", errors.New("не найден комплект vmgw (папка vmgw рядом с программой)")
}

func findVMware() (string, error) {
	var dirs []string
	for _, k := range []string{`SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation`, `SOFTWARE\VMware, Inc.\VMware Workstation`} {
		if key, err := registry.OpenKey(registry.LOCAL_MACHINE, k, registry.QUERY_VALUE); err == nil {
			if p, _, err := key.GetStringValue("InstallPath"); err == nil {
				dirs = append(dirs, p)
			}
			key.Close()
		}
	}
	dirs = append(dirs, filepath.Join(os.Getenv("ProgramFiles(x86)"), `VMware\VMware Workstation`),
		filepath.Join(os.Getenv("ProgramFiles"), `VMware\VMware Workstation`))
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "vmrun.exe")); err == nil {
			return d, nil
		}
	}
	return "", errors.New("VMware Workstation не найден")
}

func defaultLabDir() string {
	docs, err := windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
	if err != nil {
		docs = filepath.Join(os.Getenv("USERPROFILE"), "Documents")
	}
	return filepath.Join(docs, "Virtual Machines", "VmGw")
}

// kitStamp — версия комплекта: VERSION + отпечаток файлов. Тот же алгоритм —
// Get-KitStamp (VmGwCommon.ps1) и kit_stamp (guest/lib.sh).
func kitStamp(dir string) (string, error) {
	ver, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return "", err
	}
	var rel []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if n := d.Name(); n == "lab.conf" || n == "README.md" {
			return nil
		}
		r, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = append(rel, filepath.ToSlash(r))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(rel)
	var list bytes.Buffer
	for _, r := range rel {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(r)))
		if err != nil {
			return "", err
		}
		s := sha256.Sum256(b)
		fmt.Fprintf(&list, "%x  %s\n", s, r)
	}
	sum := sha256.Sum256(list.Bytes())
	return strings.Join(strings.Fields(string(ver)), "") + "+" + hex.EncodeToString(sum[:])[:12], nil
}

// ---------------------------------------------------------------- лаборатории

type labVM struct {
	Name    string `json:"name"`
	Role    string `json:"role"` // router | client
	Os      string `json:"os"`   // ubuntu | windows
	Mac     string `json:"mac"`
	Vmx     string `json:"vmx"`
	Exists  bool   `json:"exists"`
	Running bool   `json:"running"`
}

type labInfo struct {
	Dir        string  `json:"dir"`
	Err        string  `json:"err,omitempty"`
	Default    bool    `json:"default"`
	MgmtAddr   string  `json:"mgmtAddr"`
	PanelPort  int     `json:"panelPort"`
	SshPort    int     `json:"sshPort"`
	LanNet     string  `json:"lanNet"`
	RouterUser string  `json:"routerUser"`
	DesktopIso string  `json:"desktopIso"`
	WindowsIso string  `json:"windowsIso"`
	KitStamp   string  `json:"kitStamp"`
	VMs        []labVM `json:"vms"`
}

type vmgwInfo struct {
	Root       string    `json:"root"`
	RootErr    string    `json:"rootErr,omitempty"`
	VMware     string    `json:"vmware"`
	VMwareErr  string    `json:"vmwareErr,omitempty"`
	KitStamp   string    `json:"kitStamp"`
	DefaultDir string    `json:"defaultDir"`
	Labs       []labInfo `json:"labs"`
}

type labFile struct {
	MgmtAddr   string
	PanelPort  int
	SshPort    int
	LanNet     string
	RouterUser string
	DesktopIso string
	WindowsIso string
	Router     struct{ LanMac, Vmx string }
	Clients    json.RawMessage
}

func readLab(dir string, running func(string) bool) labInfo {
	li := labInfo{Dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, "lab.json"))
	if err != nil {
		li.Err = "нет lab.json"
		return li
	}
	var f labFile
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &f); err != nil {
		li.Err = "lab.json: " + err.Error()
		return li
	}
	li.MgmtAddr, li.PanelPort, li.SshPort, li.LanNet = f.MgmtAddr, f.PanelPort, f.SshPort, f.LanNet
	li.RouterUser, li.DesktopIso, li.WindowsIso = f.RouterUser, f.DesktopIso, f.WindowsIso
	// ConvertTo-Json (PowerShell 5) пишет массив из одного элемента как объект.
	type client struct{ Name, Mac, Vmx, Os string }
	var cs []client
	if len(f.Clients) > 0 && f.Clients[0] == '{' {
		var c client
		if json.Unmarshal(f.Clients, &c) == nil {
			cs = []client{c}
		}
	} else if len(f.Clients) > 0 {
		json.Unmarshal(f.Clients, &cs)
	}
	vm := func(name, role, mac, vmx, osName string) labVM {
		_, err := os.Stat(vmx)
		if osName == "" {
			osName = "ubuntu"
		}
		return labVM{Name: name, Role: role, Os: osName, Mac: strings.ToLower(mac), Vmx: vmx, Exists: vmx != "" && err == nil, Running: running(vmx)}
	}
	li.VMs = append(li.VMs, vm("router", "router", f.Router.LanMac, f.Router.Vmx, ""))
	for _, c := range cs {
		li.VMs = append(li.VMs, vm(c.Name, "client", c.Mac, c.Vmx, strings.ToLower(c.Os)))
	}
	if s, err := kitStamp(filepath.Join(dir, "kit")); err == nil {
		li.KitStamp = s
	}
	return li
}

func normPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	return strings.ToLower(filepath.Clean(p))
}

// runningVMs — пути .vmx запущенных ВМ (vmrun list).
func runningVMs(vmware string) ([]string, error) {
	c := exec.Command(filepath.Join(vmware, "vmrun.exe"), "-T", "ws", "list")
	hideWindow(c)
	out, err := c.Output()
	if err != nil {
		return nil, errors.New("vmrun list: " + errText(err))
	}
	var vms []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); strings.HasSuffix(strings.ToLower(l), ".vmx") {
			vms = append(vms, l)
		}
	}
	return vms, nil
}

// vmgwState собирает всё для вкладки. extra — папки лабораторий, добавленные
// пользователем; кроме них — папка по умолчанию и лаборатории запущенных ВМ
// (ЛАБ\имя\имя.vmx, как в Update-VmGwLab.ps1).
func vmgwState(extra []string) vmgwInfo {
	inf := vmgwInfo{DefaultDir: defaultLabDir()}
	if r, err := vmgwRoot(); err != nil {
		inf.RootErr = err.Error()
	} else {
		inf.Root = r
		if s, err := kitStamp(filepath.Join(r, "guest")); err == nil {
			inf.KitStamp = s
		} else {
			inf.RootErr = "версия комплекта: " + err.Error()
		}
	}
	run := map[string]bool{}
	var vms []string
	if d, err := findVMware(); err != nil {
		inf.VMwareErr = err.Error()
	} else {
		inf.VMware = d
		if vms, err = runningVMs(d); err != nil {
			inf.VMwareErr = err.Error()
		}
		for _, v := range vms {
			run[normPath(v)] = true
		}
	}
	running := func(vmx string) bool { return vmx != "" && run[normPath(vmx)] }

	seen := map[string]bool{}
	add := func(dir string, def bool) {
		k := normPath(dir)
		if dir == "" || seen[k] {
			return
		}
		if _, err := os.Stat(filepath.Join(dir, "lab.json")); err != nil && !def {
			if !containsFold(extra, dir) {
				return // найдена по запущенной ВМ, но это не лаборатория
			}
		} else if err != nil {
			return // папки по умолчанию ещё нет
		}
		seen[k] = true
		li := readLab(dir, running)
		li.Default = def
		inf.Labs = append(inf.Labs, li)
	}
	add(inf.DefaultDir, true)
	for _, d := range extra {
		add(d, false)
	}
	for _, v := range vms {
		add(filepath.Dir(filepath.Dir(v)), false)
	}
	return inf
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if normPath(x) == normPath(s) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- запуск скриптов

func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

func powershell() string {
	return filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`)
}

// psq — строка PowerShell в одинарных кавычках. Двойных кавычек в командах
// нет: так командная строка Windows передаёт их без искажений.
func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func script(name string) (string, error) {
	r, err := vmgwRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(r, "windows", name), nil
}

// runHidden выполняет команду PowerShell без окна и возвращает весь вывод.
// Вопросы (Read-Host) в этом режиме — ошибка, а не зависание.
func runHidden(cmd string) (string, error) {
	c := exec.Command(powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"[Console]::OutputEncoding = [Text.Encoding]::UTF8; try { "+cmd+
			" } catch { [Console]::Out.Flush(); [Console]::Error.WriteLine('ОШИБКА: ' + $_.Exception.Message); exit 1 }")
	hideWindow(c)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	err := c.Run()
	return strings.TrimSpace(strings.ReplaceAll(out.String(), "\r\n", "\n")), err
}

// runConsole выполняет команду в отдельном окне консоли (там вводят пароль
// sudo и отвечают на вопросы) и ждёт, пока его закроют.
func runConsole(title, cmd string) error {
	c := exec.Command(powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		"$Host.UI.RawUI.WindowTitle = "+psq(title)+"; $c = 0; try { "+cmd+
			" } catch { Write-Host ''; Write-Host ('ОШИБКА: ' + $_.Exception.Message) -ForegroundColor Red; $c = 1 }; "+
			"Write-Host ''; Read-Host 'Готово. Enter - закрыть окно' | Out-Null; exit $c")
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	if err := c.Start(); err != nil {
		return err
	}
	c.Wait() // итог виден в окне; вкладка после этого перепроверяет версии сама
	return nil
}

// busyLabs: одна операция на лабораторию за раз (два обновления разом
// толкались бы в одних и тех же ВМ).
var (
	busyMu   sync.Mutex
	busyLabs = map[string]string{}
)

func withLab(dir, what string, f func() (any, error)) (any, error) {
	k := normPath(dir)
	busyMu.Lock()
	if w, ok := busyLabs[k]; ok {
		busyMu.Unlock()
		return nil, errors.New("с этой лабораторией уже идёт операция: " + w)
	}
	busyLabs[k] = what
	busyMu.Unlock()
	defer func() { busyMu.Lock(); delete(busyLabs, k); busyMu.Unlock() }()
	return f()
}

func needLab(dir string) error {
	if dir == "" {
		return errors.New("не указана папка лаборатории")
	}
	if _, err := os.Stat(filepath.Join(dir, "lab.json")); err != nil {
		return errors.New("нет лаборатории: " + filepath.Join(dir, "lab.json"))
	}
	return nil
}

type checkRow struct {
	Lab, Vm, Before, After, Result string
}

type checkResult struct {
	KitStamp string     `json:"kitStamp"`
	Rows     []checkRow `json:"rows"`
	Log      string     `json:"log"`
}

// vmgwCheck — версии в ВМ лаборатории (Update-VmGwLab.ps1 -CheckOnly -Json).
func vmgwCheck(dir string) (any, error) {
	if err := needLab(dir); err != nil {
		return nil, err
	}
	s, err := script("Update-VmGwLab.ps1")
	if err != nil {
		return nil, err
	}
	out, err := runHidden("& " + psq(s) + " -CheckOnly -Json -LabDir " + psq(dir))
	res := checkResult{}
	var log []string
	for _, l := range strings.Split(out, "\n") {
		if j, ok := strings.CutPrefix(l, "VMGW-JSON:"); ok {
			var r struct {
				KitStamp string
				Rows     json.RawMessage
			}
			if json.Unmarshal([]byte(j), &r) == nil {
				res.KitStamp = r.KitStamp
				if len(r.Rows) > 0 && r.Rows[0] == '{' {
					var one checkRow
					json.Unmarshal(r.Rows, &one)
					res.Rows = []checkRow{one}
				} else {
					json.Unmarshal(r.Rows, &res.Rows)
				}
			}
			continue
		}
		log = append(log, l)
	}
	res.Log = strings.Join(log, "\n")
	if err != nil && res.KitStamp == "" {
		return nil, errors.New(lastLine(res.Log, err))
	}
	return res, nil
}

func lastLine(s string, err error) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if l := strings.TrimSpace(ls[len(ls)-1]); l != "" {
		return l
	}
	return errText(err)
}

type updateArgs struct {
	Dir                           string
	RebuildAwg, Force, RouterOnly bool
}

func vmgwUpdate(a updateArgs) (any, error) {
	if err := needLab(a.Dir); err != nil {
		return nil, err
	}
	s, err := script("Update-VmGwLab.ps1")
	if err != nil {
		return nil, err
	}
	cmd := "& " + psq(s) + " -LabDir " + psq(a.Dir)
	for _, f := range []struct {
		on   bool
		name string
	}{{a.RebuildAwg, "-RebuildAwg"}, {a.Force, "-Force"}, {a.RouterOnly, "-RouterOnly"}} {
		if f.on {
			cmd += " " + f.name
		}
	}
	return nil, runConsole("vmgw: обновление "+filepath.Base(a.Dir), cmd)
}

type addClientArgs struct {
	Dir, Name, Iso, Os string
	Open               bool
}

// vmgwAddClient — новая ВМ (Ubuntu Desktop или Windows) в лаборатории
// (New-VmGwLab.ps1 -AddClient), без окна.
func vmgwAddClient(a addClientArgs) (any, error) {
	if err := needLab(a.Dir); err != nil {
		return nil, err
	}
	if !vmNameRe.MatchString(a.Name) {
		return nil, errors.New("имя ВМ: латиница в нижнем регистре, цифры, дефис (до 31 символа)")
	}
	if _, err := os.Stat(a.Iso); a.Iso == "" || err != nil {
		return nil, errors.New("выберите ISO с установщиком")
	}
	s, err := script("New-VmGwLab.ps1")
	if err != nil {
		return nil, err
	}
	cmd := "& " + psq(s) + " -LabDir " + psq(a.Dir) + " -AddClient " + psq(a.Name)
	switch a.Os {
	case "", "ubuntu":
		cmd += " -DesktopIso " + psq(a.Iso)
	case "windows":
		cmd += " -ClientOs windows -WindowsIso " + psq(a.Iso)
	default:
		return nil, errors.New("неизвестная ОС: " + a.Os)
	}
	if !a.Open {
		cmd += " -NoOpen"
	}
	out, err := runHidden(cmd)
	if err != nil {
		return nil, errors.New(lastLine(out, err))
	}
	return out, nil
}

type newLabArgs struct {
	Dir, ServerIso, DesktopIso, Clients, MgmtVnet, LanNet, AdminNets, LocalNets string
	SshPort, PanelPort                                                          int
}

// vmgwNewLab — новая лаборатория (New-VmGwLab.ps1) в окне консоли: там
// проверка образов и вопрос о маршруте Windows → LAN.
func vmgwNewLab(a newLabArgs) (any, error) {
	if a.Dir == "" {
		return nil, errors.New("укажите папку лаборатории")
	}
	if _, err := os.Stat(filepath.Join(a.Dir, "lab.json")); err == nil {
		return nil, errors.New("в этой папке уже есть лаборатория")
	}
	if _, err := os.Stat(a.ServerIso); a.ServerIso == "" || err != nil {
		return nil, errors.New("выберите ISO Ubuntu Server для роутера")
	}
	var names []string
	for _, n := range strings.FieldsFunc(a.Clients, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if !vmNameRe.MatchString(n) {
			return nil, fmt.Errorf("имя ВМ «%s»: латиница в нижнем регистре, цифры, дефис", n)
		}
		names = append(names, n)
	}
	if len(names) > 0 {
		if _, err := os.Stat(a.DesktopIso); a.DesktopIso == "" || err != nil {
			return nil, errors.New("выберите ISO Ubuntu Desktop для ведомых ВМ")
		}
	}
	if a.MgmtVnet != "VMnet1" && a.MgmtVnet != "VMnet8" {
		return nil, errors.New("сеть управления: VMnet1 или VMnet8")
	}
	if !cidrRe.MatchString(a.LanNet) {
		return nil, errors.New("LAN-сегмент: сеть вида 192.168.150.0/24")
	}
	if _, err := netip.ParsePrefix(a.LanNet); err != nil {
		return nil, errors.New("LAN-сегмент: " + err.Error())
	}
	for _, p := range []int{a.SshPort, a.PanelPort} {
		if p < 1 || p > 65535 {
			return nil, errors.New("порт: от 1 до 65535")
		}
	}
	if !netsRe.MatchString(a.AdminNets) || !netsRe.MatchString(a.LocalNets) {
		return nil, errors.New("сети: адреса через запятую, auto или none")
	}
	s, err := script("New-VmGwLab.ps1")
	if err != nil {
		return nil, err
	}
	cmd := "& " + psq(s) + " -LabDir " + psq(a.Dir) + " -ServerIso " + psq(a.ServerIso) +
		" -MgmtVnet " + a.MgmtVnet + " -LanNet " + psq(a.LanNet) +
		" -SshPort " + strconv.Itoa(a.SshPort) + " -PanelPort " + strconv.Itoa(a.PanelPort) +
		" -AdminNets " + psq(a.AdminNets) + " -LocalNets " + psq(a.LocalNets)
	if len(names) > 0 {
		q := make([]string, len(names))
		for i, n := range names {
			q[i] = psq(n)
		}
		cmd += " -DesktopIso " + psq(a.DesktopIso) + " -Clients " + strings.Join(q, ",")
	} else {
		cmd += " -Clients @()"
	}
	return nil, runConsole("vmgw: новая лаборатория", cmd)
}

// ---------------------------------------------------------------- открыть

func shellOpen(target string) error {
	return windows.ShellExecute(0, u16("open"), u16(target), nil, nil, windows.SW_SHOWNORMAL)
}

func findSsh() (string, error) {
	for _, d := range []string{filepath.Join(os.Getenv("SystemRoot"), `System32\OpenSSH`), filepath.Join(os.Getenv("ProgramFiles"), "OpenSSH")} {
		if p := filepath.Join(d, "ssh.exe"); fileExists(p) {
			return p, nil
		}
	}
	if p, err := exec.LookPath("ssh.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("не найден ssh.exe: установите «Клиент OpenSSH» (Параметры → Система → Дополнительные компоненты)")
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// vmgwOpen: panel — панель роутера в браузере; ssh — консоль SSH на роутер;
// vm — ВМ в VMware (vmx из lab.json); folder — папка лаборатории; readme.
func vmgwOpen(kind, dir, arg string) error {
	switch kind {
	case "readme":
		r, err := vmgwRoot()
		if err != nil {
			return err
		}
		return shellOpen(filepath.Join(r, "README.md"))
	case "folder":
		if !fileExists(dir) {
			return errors.New("нет папки " + dir)
		}
		return shellOpen(dir)
	}
	if err := needLab(dir); err != nil {
		return err
	}
	li := readLab(dir, func(string) bool { return false })
	if li.Err != "" {
		return errors.New(li.Err)
	}
	addr, err := netip.ParseAddr(li.MgmtAddr)
	if err != nil && kind != "vm" {
		return errors.New("в lab.json неверный MgmtAddr")
	}
	switch kind {
	case "panel":
		return shellOpen(fmt.Sprintf("http://%s:%d/", addr, li.PanelPort))
	case "ssh":
		ssh, err := findSsh()
		if err != nil {
			return err
		}
		u := li.RouterUser
		if u == "" {
			u = strings.ToLower(os.Getenv("USERNAME"))
		}
		if !userRe.MatchString(u) {
			return errors.New("неверное имя пользователя роутера: " + u)
		}
		c := exec.Command(ssh, "-p", strconv.Itoa(li.SshPort), u+"@"+addr.String())
		c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
		if err := c.Start(); err != nil {
			return err
		}
		go c.Wait()
		return nil
	case "vm":
		for _, v := range li.VMs {
			if v.Name == arg && v.Exists {
				vmw, err := findVMware()
				if err != nil {
					return err
				}
				c := exec.Command(filepath.Join(vmw, "vmware.exe"), v.Vmx)
				if err := c.Start(); err != nil {
					return err
				}
				go c.Wait()
				return nil
			}
		}
		return errors.New("ВМ не найдена: " + arg)
	}
	return errors.New("неизвестное действие: " + kind)
}
