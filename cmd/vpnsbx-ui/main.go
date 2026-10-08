// vpnsbx-ui — окно управления песочницей: профили, правила, процессы.
// Всё делает служба (vpnsbx daemon); окно только шлёт ей команды.
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"vpnsbx/internal/config"
	"vpnsbx/internal/ipc"
	"vpnsbx/internal/proc"
)

//go:embed ui.html
var page string

func main() {
	trayOnly := len(os.Args) > 1 && os.Args[1] == "--tray" // автозапуск: только значок
	if _, err := windows.CreateMutex(nil, false, u16(`Local\vpnsbx-ui`)); err == windows.ERROR_ALREADY_EXISTS {
		if !trayOnly {
			showOther()
		}
		return
	}
	t := newTray()
	if t != nil {
		defer t.remove()
		if trayOnly && !t.waitOpen() {
			return
		}
	}
	data := filepath.Join(os.Getenv("LOCALAPPDATA"), "vpnsbx", "webview")
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		DataPath:  data,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "VPN-песочница", Width: 1100, Height: 780, Center: true, IconId: 1,
		},
	})
	if w == nil {
		windows.MessageBox(0, u16("Не удалось открыть окно: нужен Microsoft Edge WebView2 Runtime."),
			u16("VPN-песочница"), windows.MB_ICONERROR)
		os.Exit(1)
	}
	w.SetSize(900, 600, webview2.HintMin)
	owner := uintptr(w.Window())

	w.Bind("call", func(cmd string, args json.RawMessage) (json.RawMessage, error) {
		var out json.RawMessage
		var a any
		if len(args) > 0 && string(args) != "null" {
			a = args
		}
		err := ipc.Call(cmd, a, &out)
		if errors.Is(err, ipc.ErrNotRunning) {
			return nil, errors.New("NOT_RUNNING")
		}
		return out, err
	})
	w.Bind("pickExe", func() (string, error) {
		return openDialog(owner, "Программа для песочницы", false,
			[]Filter{{"Программы (*.exe)", "*.exe"}, {"Все файлы", "*.*"}})
	})
	w.Bind("pickFolder", func() (string, error) {
		return openDialog(owner, "Папка: все программы внутри — в песочнице", true, nil)
	})
	w.Bind("pickProfile", func() (string, error) {
		return openDialog(owner, "Профиль VPN", false,
			[]Filter{{"Профили (*.conf;*.vpn;*.txt)", "*.conf;*.vpn;*.txt"}, {"Все файлы", "*.*"}})
	})
	w.Bind("running", func() []proc.Entry {
		var out []proc.Entry
		self := uint32(os.Getpid())
		for _, e := range proc.List() {
			if e.Path != "" && e.PID != self {
				out = append(out, e)
			}
		}
		return out
	})
	w.Bind("startDaemon", startDaemon)
	w.Bind("dataDir", config.Dir)

	w.SetHtml(page)
	if t != nil {
		t.attach(w)
	}
	w.Run()
}

// startService запускает установленную службу vpnsbx и ждёт канал.
// handled=false — службы нет (запуск из папки сборки).
func startService() (handled bool, err error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, nil
	}
	defer windows.CloseServiceHandle(m)
	s, err := windows.OpenService(m, u16("vpnsbx"), windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return false, nil
	}
	if err != nil {
		return true, errors.New("служба vpnsbx: " + err.Error())
	}
	defer windows.CloseServiceHandle(s)
	if err := windows.StartService(s, 0, nil); err != nil && err != windows.ERROR_SERVICE_ALREADY_RUNNING {
		return true, errors.New("запуск службы vpnsbx: " + err.Error())
	}
	for i := 0; i < 100; i++ {
		if ipc.Call("status", nil, nil) == nil {
			return true, nil
		}
		var st windows.SERVICE_STATUS
		if windows.QueryServiceStatus(s, &st) == nil && st.CurrentState == windows.SERVICE_STOPPED {
			return true, errors.New("служба остановилась при запуске (см. " +
				filepath.Join(config.Dir(), "daemon.log") + ")")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return true, errors.New("служба не ответила за 10 с")
}

// startDaemon запускает службу; если она не установлена — vpnsbx.exe daemon
// (лежит рядом) без окна. Ждёт канал.
func startDaemon() error {
	if handled, err := startService(); handled {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bin := filepath.Join(filepath.Dir(exe), "vpnsbx.exe")
	if _, err := os.Stat(bin); err != nil {
		return errors.New("не найден " + bin)
	}
	cmd := exec.Command(bin, "daemon")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for i := 0; i < 50; i++ {
		if err := ipc.Call("status", nil, nil); err == nil {
			cmd.Process.Release()
			return nil
		}
		select {
		case err := <-exited:
			return errors.New("служба завершилась при запуске: " + errText(err) +
				" (см. " + filepath.Join(config.Dir(), "daemon.log") + ")")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("служба не ответила за 5 с")
}

func errText(err error) string {
	if err == nil {
		return "код 0"
	}
	return err.Error()
}
