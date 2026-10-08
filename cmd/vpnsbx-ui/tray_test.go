package main

import (
	"testing"
	"unsafe"
)

func TestTrayLayout(t *testing.T) {
	if got := unsafe.Sizeof(notifyIconData{}); got != 976 {
		t.Errorf("NOTIFYICONDATAW = %d, want 976", got)
	}
	if got := unsafe.Sizeof(wndClassEx{}); got != 80 {
		t.Errorf("WNDCLASSEXW = %d, want 80", got)
	}
	if got := unsafe.Sizeof(winMsg{}); got != 48 {
		t.Errorf("MSG = %d, want 48", got)
	}
}
