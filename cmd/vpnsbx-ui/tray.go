package main

import (
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"vpnsbx/internal/ipc"
)

// Значок в трее: живёт всё время работы UI, окно WebView2 создаётся только
// по запросу (при --tray его нет до первого «Открыть») и при закрытии
// прячется, а не уничтожается. Все вызовы окон — в главном потоке.

var (
	user32                      = windows.NewLazySystemDLL("user32.dll")
	shell32                     = windows.NewLazySystemDLL("shell32.dll")
	procRegisterClassExW        = user32.NewProc("RegisterClassExW")
	procCreateWindowExW         = user32.NewProc("CreateWindowExW")
	procDefWindowProcW          = user32.NewProc("DefWindowProcW")
	procCallWindowProcW         = user32.NewProc("CallWindowProcW")
	procSetWindowLongPtrW       = user32.NewProc("SetWindowLongPtrW")
	procRegisterWindowMessageW  = user32.NewProc("RegisterWindowMessageW")
	procLoadImageW              = user32.NewProc("LoadImageW")
	procGetSystemMetrics        = user32.NewProc("GetSystemMetrics")
	procCreatePopupMenu         = user32.NewProc("CreatePopupMenu")
	procAppendMenuW             = user32.NewProc("AppendMenuW")
	procSetMenuDefaultItem      = user32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenu          = user32.NewProc("TrackPopupMenu")
	procDestroyMenu             = user32.NewProc("DestroyMenu")
	procGetCursorPos            = user32.NewProc("GetCursorPos")
	procSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	procAllowSetForegroundWindw = user32.NewProc("AllowSetForegroundWindow")
	procPostMessageW            = user32.NewProc("PostMessageW")
	procFindWindowW             = user32.NewProc("FindWindowW")
	procShowWindow              = user32.NewProc("ShowWindow")
	procIsIconic                = user32.NewProc("IsIconic")
	procGetMessageW             = user32.NewProc("GetMessageW")
	procTranslateMessage        = user32.NewProc("TranslateMessage")
	procDispatchMessageW        = user32.NewProc("DispatchMessageW")
	procPostQuitMessage         = user32.NewProc("PostQuitMessage")
	procShellNotifyIconW        = shell32.NewProc("Shell_NotifyIconW")
	procRegisterAppRestart      = windows.NewLazySystemDLL("kernel32.dll").NewProc("RegisterApplicationRestart")
)

const (
	trayClass = "vpnsbx-tray"

	wmNull        = 0x0000
	wmClose       = 0x0010
	wmQuit        = 0x0012
	wmEndSession  = 0x0016
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B
	wmApp         = 0x8000 // занят Dispatch у webview (сообщение потоку)
	wmTray        = wmApp + 1
	wmShow        = wmApp + 2
	wmStatus      = wmApp + 3

	nimAdd, nimModify, nimDelete = 0, 1, 2
	nifMessage, nifIcon, nifTip  = 1, 2, 4

	mfString, mfChecked, mfSeparator = 0, 8, 0x800
	tpmRightButton, tpmReturnCmd     = 2, 0x100

	swHide, swShow, swRestore = 0, 5, 9
	imageIcon, lrShared       = 1, 0x8000
	smCxSmIcon, smCySmIcon    = 49, 50
	gwlpWndProc               = ^uintptr(3) // -4

	cmdOpen, cmdProtect, cmdExit = 1, 2, 3
)

// NOTIFYICONDATAW (x64, 976 байт).
type notifyIconData struct {
	CbSize           uint32
	Wnd              windows.Handle
	ID               uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             windows.Handle
	Tip              [128]uint16
	State, StateMask uint32
	Info             [256]uint16
	Version          uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GUIDItem         windows.GUID
	BalloonIcon      windows.Handle
}

type wndClassEx struct {
	Size, Style                   uint32
	WndProc                       uintptr
	ClsExtra, WndExtra            int32
	Instance, Icon, Cursor, Bkgnd windows.Handle
	MenuName, ClassName           *uint16
	IconSm                        windows.Handle
}

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	_       uint32
}

// trayState — то, что показывает значок; пишет опрос, читает главный поток.
type trayState struct {
	service bool // служба отвечает
	enabled bool
	tip     string
}

type tray struct {
	hwnd           uintptr
	taskbarCreated uintptr
	icons          [2]windows.Handle // включена / выключена
	w              webview2.WebView  // nil, пока окно не открыто
	wantWindow     bool

	mu    sync.Mutex
	state trayState
	poke  chan struct{}
}

var theTray *tray

func init() { runtime.LockOSThread() }

// showOther просит уже запущенный экземпляр показать окно.
func showOther() {
	h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(u16(trayClass))), 0)
	if h == 0 {
		return
	}
	var pid uint32
	windows.GetWindowThreadProcessId(windows.HWND(h), &pid)
	procAllowSetForegroundWindw.Call(uintptr(pid))
	procPostMessageW.Call(h, wmShow, 0, 0)
}

func newTray() *tray {
	var inst windows.Handle
	windows.GetModuleHandleEx(0, nil, &inst)
	t := &tray{poke: make(chan struct{}, 1)}
	cx, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	cy, _, _ := procGetSystemMetrics.Call(smCySmIcon)
	for i := range t.icons {
		h, _, _ := procLoadImageW.Call(uintptr(inst), uintptr(i+1), imageIcon, cx, cy, lrShared)
		t.icons[i] = windows.Handle(h)
	}
	wc := wndClassEx{
		WndProc:   windows.NewCallback(trayProc),
		Instance:  inst,
		ClassName: u16(trayClass),
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	// Обычное скрытое окно, не message-only: TaskbarCreated рассылается
	// только окнам верхнего уровня, а FindWindow ищет именно их.
	t.hwnd, _, _ = procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(u16(trayClass))),
		uintptr(unsafe.Pointer(u16("VPN-песочница"))), 0, 0, 0, 0, 0, 0, 0, uintptr(inst), 0)
	if t.hwnd == 0 {
		return nil
	}
	t.taskbarCreated, _, _ = procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(u16("TaskbarCreated"))))
	t.state = trayState{tip: "VPN-песочница"}
	theTray = t
	t.notify(nimAdd)
	// Установщик закрывает UI через Restart Manager и после обновления
	// запускает его снова — сразу в трей.
	procRegisterAppRestart.Call(uintptr(unsafe.Pointer(u16("--tray"))), 0)
	go t.poll()
	return t
}

func (t *tray) notify(op uintptr) {
	nid := notifyIconData{Wnd: windows.Handle(t.hwnd), ID: 1, Flags: nifMessage | nifIcon | nifTip,
		CallbackMessage: wmTray}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	t.mu.Lock()
	st := t.state
	t.mu.Unlock()
	nid.Icon = t.icons[1]
	if st.service && st.enabled {
		nid.Icon = t.icons[0]
	}
	tip, _ := windows.UTF16FromString(st.tip)
	copy(nid.Tip[:len(nid.Tip)-1], tip)
	procShellNotifyIconW.Call(op, uintptr(unsafe.Pointer(&nid)))
}

func (t *tray) remove() { t.notify(nimDelete) }

// poll раз в 3 с (и сразу по poke) спрашивает службу о состоянии.
func (t *tray) poll() {
	for {
		st := trayState{tip: "VPN-песочница: служба не запущена"}
		var s struct {
			Enabled bool   `json:"enabled"`
			Running bool   `json:"running"`
			Err     string `json:"err"`
			Tunnels []struct {
				Name    string `json:"name"`
				Started bool   `json:"started"`
				Up      bool   `json:"up"`
			} `json:"tunnels"`
		}
		var raw json.RawMessage
		if ipc.Call("status", nil, &raw) == nil && json.Unmarshal(raw, &s) == nil {
			st.service, st.enabled = true, s.Enabled
			switch {
			case !s.Enabled:
				st.tip = "VPN-песочница: защита выключена"
			case s.Err != "" || !s.Running:
				st.tip = "VPN-песочница: защита включена, фильтр не работает — сети у программ нет"
			default:
				st.tip = "VPN-песочница: защита включена"
				for _, tn := range s.Tunnels {
					if tn.Started && !tn.Up {
						st.tip = "VPN-песочница: защита включена, VPN не отвечает — сети у программ нет"
						break
					}
				}
			}
		}
		t.mu.Lock()
		changed := t.state != st
		t.state = st
		t.mu.Unlock()
		if changed {
			procPostMessageW.Call(t.hwnd, wmStatus, 0, 0)
		}
		select {
		case <-t.poke:
		case <-time.After(3 * time.Second):
		}
	}
}

func (t *tray) refresh() {
	select {
	case t.poke <- struct{}{}:
	default:
	}
}

func trayProc(hwnd, msg, wp, lp uintptr) uintptr {
	t := theTray
	if t != nil && hwnd == t.hwnd {
		switch {
		case msg == wmTray:
			switch lp & 0xFFFF {
			case wmLButtonUp, wmLButtonDbl:
				t.open()
			case wmRButtonUp, wmContextMenu:
				t.menu()
			}
			return 0
		case msg == wmShow:
			t.open()
			return 0
		case msg == wmStatus:
			t.notify(nimModify)
			return 0
		case msg == t.taskbarCreated && msg != 0: // проводник перезапустился
			t.notify(nimAdd)
			return 0
		case msg == wmEndSession && wp != 0: // выход из системы или установщик
			t.remove()
			os.Exit(0)
		}
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
}

func (t *tray) open() {
	if t.w == nil {
		t.wantWindow = true // waitOpen выйдет из своего цикла и создаст окно
		procPostMessageW.Call(t.hwnd, wmNull, 0, 0)
		return
	}
	h := uintptr(t.w.Window())
	if r, _, _ := procIsIconic.Call(h); r != 0 {
		procShowWindow.Call(h, swRestore)
	} else {
		procShowWindow.Call(h, swShow)
	}
	procSetForegroundWindow.Call(h)
}

func (t *tray) menu() {
	t.mu.Lock()
	st := t.state
	t.mu.Unlock()
	m, _, _ := procCreatePopupMenu.Call()
	defer procDestroyMenu.Call(m)
	procAppendMenuW.Call(m, mfString, cmdOpen, uintptr(unsafe.Pointer(u16("Открыть"))))
	flags := uintptr(mfString)
	if st.service && st.enabled {
		flags |= mfChecked
	}
	procAppendMenuW.Call(m, flags, cmdProtect, uintptr(unsafe.Pointer(u16("Защита"))))
	procAppendMenuW.Call(m, mfSeparator, 0, 0)
	procAppendMenuW.Call(m, mfString, cmdExit, uintptr(unsafe.Pointer(u16("Выход (служба продолжит работу)"))))
	procSetMenuDefaultItem.Call(m, cmdOpen, 0)
	var pt struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(t.hwnd) // иначе меню не закроется щелчком мимо
	cmd, _, _ := procTrackPopupMenu.Call(m, tpmRightButton|tpmReturnCmd, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	procPostMessageW.Call(t.hwnd, wmNull, 0, 0)
	switch cmd {
	case cmdOpen:
		t.open()
	case cmdProtect:
		go t.toggle(st)
	case cmdExit:
		t.remove()
		procPostQuitMessage.Call(0)
	}
}

// toggle включает или выключает защиту; если службы нет — запускает её.
func (t *tray) toggle(st trayState) {
	defer t.refresh()
	on := !(st.service && st.enabled)
	if !st.service {
		if err := startDaemon(); err != nil {
			errorBox(err.Error())
			return
		}
	}
	if err := ipc.Call("enable", map[string]bool{"on": on}, nil); err != nil {
		errorBox("Не удалось переключить защиту: " + err.Error())
	}
}

func errorBox(text string) {
	windows.MessageBox(0, u16(text), u16("VPN-песочница"), windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

// waitOpen крутит очередь сообщений, пока не попросят окно (true) или
// не выберут «Выход» (false).
func (t *tray) waitOpen() bool {
	var m winMsg
	for !t.wantWindow {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 || m.Message == wmQuit {
			return false
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return true
}

var webviewProc uintptr

// attach запоминает окно и подменяет его оконную процедуру: крестик прячет
// окно в трей, а не закрывает программу.
func (t *tray) attach(w webview2.WebView) {
	t.w = w
	webviewProc, _, _ = procSetWindowLongPtrW.Call(uintptr(w.Window()), gwlpWndProc, windows.NewCallback(hideOnClose))
	procSetForegroundWindow.Call(uintptr(w.Window()))
}

func hideOnClose(hwnd, msg, wp, lp uintptr) uintptr {
	if msg == wmClose {
		procShowWindow.Call(hwnd, swHide)
		return 0
	}
	r, _, _ := procCallWindowProcW.Call(webviewProc, hwnd, msg, wp, lp)
	return r
}
