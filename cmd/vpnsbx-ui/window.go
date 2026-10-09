package main

import (
	"encoding/json"
	"fmt"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

var (
	procGetDpiForWindow  = user32.NewProc("GetDpiForWindow")
	procMonitorFromWin   = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfo   = user32.NewProc("GetMonitorInfoW")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	monitorDefaultToNear = uintptr(2)
)

type monitorInfo struct {
	size          uint32
	monitor, work windows.Rect
	flags         uint32
}

// fitWindow задаёт размер окна в логических пикселях (с учётом масштаба
// экрана), не больше рабочей области монитора, и ставит окно по центру
// её: на маленьком экране ВМ окно не должно уезжать за край вместе с
// заголовком и кнопками.
func fitWindow(w webview2.WebView, width, height, minW, minH int) {
	hwnd := uintptr(w.Window())
	dpi := 96
	if procGetDpiForWindow.Find() == nil {
		if d, _, _ := procGetDpiForWindow.Call(hwnd); d != 0 {
			dpi = int(d)
		}
	}
	scale := func(v int) int { return v * dpi / 96 }
	mi := monitorInfo{size: uint32(unsafe.Sizeof(monitorInfo{}))}
	mon, _, _ := procMonitorFromWin.Call(hwnd, monitorDefaultToNear)
	if r, _, _ := procGetMonitorInfo.Call(mon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return
	}
	wa := mi.work
	aw, ah := int(wa.Right-wa.Left), int(wa.Bottom-wa.Top)
	cw, ch := min(scale(width), aw*95/100), min(scale(height), ah*95/100)
	w.SetSize(min(scale(minW), cw), min(scale(minH), ch), webview2.HintMin)
	x, y := int(wa.Left)+(aw-cw)/2, int(wa.Top)+(ah-ch)/2
	const swpNoZOrder, swpNoActivate = 0x0004, 0x0010
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(cw), uintptr(ch), swpNoZOrder|swpNoActivate)
}

// async выполняет f вне потока окна (go-webview2 зовёт привязки прямо в
// нём, и долгий вызов замораживает окно) и отдаёт результат странице
// через window._done(id, err, result).
func async(w webview2.WebView, id int, f func() (any, error)) {
	go func() {
		res, err := f()
		var js string
		if err != nil {
			e, _ := json.Marshal(err.Error())
			js = fmt.Sprintf("window._done(%d,%s,null)", id, e)
		} else {
			b, err := json.Marshal(res)
			if err != nil || len(b) == 0 {
				b = []byte("null")
			}
			js = fmt.Sprintf("window._done(%d,null,%s)", id, b)
		}
		w.Dispatch(func() { w.Eval(js) })
	}()
}
