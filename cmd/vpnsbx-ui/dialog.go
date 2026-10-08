package main

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Системный диалог выбора файла/папки (IFileOpenDialog). Вызывать из
// потока окна: COM там уже инициализирован (STA).

var (
	ole32                = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procCoTaskMemFree    = ole32.NewProc("CoTaskMemFree")

	clsidFileOpenDialog = windows.GUID{Data1: 0xDC1C5A9C, Data2: 0xE88A, Data3: 0x4DDE,
		Data4: [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	iidIFileOpenDialog = windows.GUID{Data1: 0xD57C7288, Data2: 0xD4AD, Data3: 0x4768,
		Data4: [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}
)

const (
	fosPickFolders     = 0x20
	fosForceFileSystem = 0x40
	fosPathMustExist   = 0x800
	fosFileMustExist   = 0x1000
	sigdnFileSysPath   = 0x80058000
	errCancelled       = 0x800704C7
	clsctxInproc       = 1
)

// индексы методов в vtable
const (
	mRelease        = 2
	mShow           = 3
	mSetFileTypes   = 4
	mSetOptions     = 9
	mGetOptions     = 10
	mSetTitle       = 17
	mGetResult      = 20
	mGetDisplayName = 5 // IShellItem
)

type filterSpec struct {
	name, spec *uint16
}

// comObj — COM-объект: первым полем указатель на таблицу методов.
type comObj struct{ vtbl *[32]uintptr }

func vcall(obj *comObj, idx int, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(obj.vtbl[idx], append([]uintptr{uintptr(unsafe.Pointer(obj))}, args...)...)
	return r
}

func u16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

// Filter — пара «название, маска» (маски через ;).
type Filter struct{ Name, Spec string }

// openDialog показывает диалог. Пустая строка без ошибки — пользователь отменил.
func openDialog(owner uintptr, title string, folder bool, filters []Filter) (string, error) {
	var d *comObj
	if hr, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidFileOpenDialog)), 0, clsctxInproc,
		uintptr(unsafe.Pointer(&iidIFileOpenDialog)), uintptr(unsafe.Pointer(&d))); hr != 0 {
		return "", syscall.Errno(hr)
	}
	defer vcall(d, mRelease)

	var opts uint32
	vcall(d, mGetOptions, uintptr(unsafe.Pointer(&opts)))
	opts |= fosForceFileSystem | fosPathMustExist
	if folder {
		opts |= fosPickFolders
	} else {
		opts |= fosFileMustExist
	}
	vcall(d, mSetOptions, uintptr(opts))
	vcall(d, mSetTitle, uintptr(unsafe.Pointer(u16(title))))
	if len(filters) > 0 && !folder {
		specs := make([]filterSpec, len(filters))
		for i, f := range filters {
			specs[i] = filterSpec{u16(f.Name), u16(f.Spec)}
		}
		vcall(d, mSetFileTypes, uintptr(len(specs)), uintptr(unsafe.Pointer(&specs[0])))
	}
	if hr := vcall(d, mShow, owner); hr != 0 {
		if uint32(hr) == errCancelled {
			return "", nil
		}
		return "", syscall.Errno(hr)
	}
	var item *comObj
	if hr := vcall(d, mGetResult, uintptr(unsafe.Pointer(&item))); hr != 0 || item == nil {
		return "", errors.New("диалог не вернул результат")
	}
	defer vcall(item, mRelease)
	var p *uint16
	if hr := vcall(item, mGetDisplayName, sigdnFileSysPath, uintptr(unsafe.Pointer(&p))); hr != 0 {
		return "", syscall.Errno(hr)
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
	return windows.UTF16PtrToString(p), nil
}
