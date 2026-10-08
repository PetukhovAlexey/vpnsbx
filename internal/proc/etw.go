package proc

import (
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ETW-провайдер Microsoft-Windows-Kernel-Process: о каждом запуске процесса
// сообщает с PID родителя и путём exe, даже если процесс уже завершился.
// Так короткоживущий посредник (cmd /c start …) не рвёт цепочку предков.
// Нужны права администратора.

var (
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	tdh                  = windows.NewLazySystemDLL("tdh.dll")
	procStartTraceW      = advapi32.NewProc("StartTraceW")
	procControlTraceW    = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2   = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW       = advapi32.NewProc("OpenTraceW")
	procProcessTrace     = advapi32.NewProc("ProcessTrace")
	procCloseTrace       = advapi32.NewProc("CloseTrace")
	procTdhGetProperty   = tdh.NewProc("TdhGetProperty")
	procTdhGetPropertySz = tdh.NewProc("TdhGetPropertySize")

	etwSession = "vpnsbx-proc" // имя сессии (в тестах — своё)

	kernelProcessGUID = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B,
		Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}
)

const (
	wnodeFlagTracedGUID    = 0x00020000
	eventTraceRealTimeMode = 0x00000100
	eventTraceUseMsFlush   = 0x00000010
	controlStop            = 1
	enableProvider         = 1
	keywordProcess         = 0x10
	traceModeRealTime      = 0x00000100
	traceModeEventRecord   = 0x10000000
	invalidTrace           = ^uint64(0)
	errAlreadyExists       = 183
	eventProcessStart      = 1
	traceLevelInformation  = 4
	wnodeClientContextQPC  = 1
)

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	TimeStamp         int64
	GUID              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type traceProps struct {
	Wnode                                                                    wnodeHeader
	BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode uint32
	FlushTimer, EnableFlags                                                  uint32
	AgeLimit                                                                 int32
	NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost uint32
	RealTimeBuffersLost                                                      uint32
	LoggerThreadID                                                           windows.Handle
	LogFileNameOffset, LoggerNameOffset                                      uint32
	name                                                                     [64]uint16
}

// EVENT_TRACE_LOGFILEW (x64, 448 байт); неиспользуемые части — массивами.
type traceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        [88]byte
	LogfileHeader       [280]byte
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	_                   uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	_                   uint32
	Context             uintptr
}

type eventRecord struct {
	Size, HeaderType, Flags, EventProperty uint16
	ThreadID, ProcessID                    uint32
	TimeStamp                              int64
	ProviderID                             windows.GUID
	ID                                     uint16
	Version, Channel, Level, Opcode        uint8
	Task                                   uint16
	Keyword                                uint64
	ProcessorTime                          uint64
	ActivityID                             windows.GUID
	BufferContext                          uint32
	ExtendedDataCount, UserDataLength      uint16
	ExtendedData, UserData, UserContext    uintptr
}

type propDesc struct {
	name  uintptr
	index uint32
	_     uint32
}

// procWatch — ETW-сессия. started вызывается в потоке ProcessTrace.
type procWatch struct {
	trace   uint64
	session uint64
	done    chan struct{}
}

func newProps() *traceProps {
	p := &traceProps{}
	p.Wnode.BufferSize = uint32(unsafe.Sizeof(*p))
	p.Wnode.Flags = wnodeFlagTracedGUID
	p.Wnode.ClientContext = wnodeClientContextQPC
	p.LoggerNameOffset = uint32(unsafe.Offsetof(p.name))
	return p
}

var startedFn func(pid, parent uint32, created int64, path string) // одна сессия на процесс

func watchProcesses(started func(pid, parent uint32, created int64, path string)) (*procWatch, error) {
	name, _ := windows.UTF16PtrFromString(etwSession)
	props := newProps()
	props.BufferSize = 16 // КБ
	props.MinimumBuffers = 4
	props.MaximumBuffers = 32
	props.LogFileMode = eventTraceRealTimeMode | eventTraceUseMsFlush
	props.FlushTimer = 10 // мс
	var session uint64
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(props)))
	if r == errAlreadyExists { // осталась от прошлого запуска
		procControlTraceW.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(newProps())), controlStop)
		r, _, _ = procStartTraceW.Call(uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(props)))
	}
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	w := &procWatch{session: session, done: make(chan struct{})}
	if r, _, _ := procEnableTraceEx2.Call(uintptr(session), uintptr(unsafe.Pointer(&kernelProcessGUID)), enableProvider,
		traceLevelInformation, keywordProcess, 0, 0, 0); r != 0 {
		w.stopSession()
		return nil, syscall.Errno(r)
	}
	startedFn = started
	lf := &traceLogfile{
		LoggerName:          name,
		ProcessTraceMode:    traceModeRealTime | traceModeEventRecord,
		EventRecordCallback: eventCallback,
	}
	t, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(lf)))
	if uint64(t) == invalidTrace {
		w.stopSession()
		return nil, err
	}
	w.trace = uint64(t)
	go func() {
		defer close(w.done)
		runtime.LockOSThread()
		procProcessTrace.Call(uintptr(unsafe.Pointer(&w.trace)), 1, 0, 0)
	}()
	return w, nil
}

func (w *procWatch) stopSession() {
	name, _ := windows.UTF16PtrFromString(etwSession)
	procControlTraceW.Call(uintptr(w.session), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(newProps())), controlStop)
}

func (w *procWatch) Close() {
	w.stopSession()
	procCloseTrace.Call(uintptr(w.trace))
	<-w.done
}

var eventCallback = syscall.NewCallback(func(rec *eventRecord) uintptr {
	if rec.ID != eventProcessStart || rec.ProviderID != kernelProcessGUID || startedFn == nil {
		return 0
	}
	pid, ok1 := propU32(rec, "ProcessID")
	parent, ok2 := propU32(rec, "ParentProcessID")
	if !ok1 || !ok2 {
		return 0
	}
	created, _ := propI64(rec, "CreateTime")
	startedFn(pid, parent, created, ntToDos(propString(rec, "ImageName")))
	return 0
})

func getProp(rec *eventRecord, name string, buf []byte) bool {
	n, _ := windows.UTF16PtrFromString(name)
	d := propDesc{name: uintptr(unsafe.Pointer(n)), index: ^uint32(0)}
	r, _, _ := procTdhGetProperty.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)),
		uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	runtime.KeepAlive(n)
	return r == 0
}

func propU32(rec *eventRecord, name string) (uint32, bool) {
	var b [4]byte
	if !getProp(rec, name, b[:]) {
		return 0, false
	}
	return *(*uint32)(unsafe.Pointer(&b[0])), true
}

func propI64(rec *eventRecord, name string) (int64, bool) {
	var b [8]byte
	if !getProp(rec, name, b[:]) {
		return 0, false
	}
	return *(*int64)(unsafe.Pointer(&b[0])), true
}

func propString(rec *eventRecord, name string) string {
	n, _ := windows.UTF16PtrFromString(name)
	d := propDesc{name: uintptr(unsafe.Pointer(n)), index: ^uint32(0)}
	var size uint32
	if r, _, _ := procTdhGetPropertySz.Call(uintptr(unsafe.Pointer(rec)), 0, 0, 1, uintptr(unsafe.Pointer(&d)),
		uintptr(unsafe.Pointer(&size))); r != 0 || size < 2 {
		return ""
	}
	runtime.KeepAlive(n)
	buf := make([]uint16, (size+1)/2)
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*2)
	if !getProp(rec, name, b) {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// ntToDos: \Device\HarddiskVolume3\x → C:\x.
func ntToDos(p string) string {
	if !strings.HasPrefix(p, `\Device\`) {
		return p
	}
	for _, m := range devMap() {
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(m.dev)+`\`) {
			return m.drive + p[len(m.dev):]
		}
	}
	return p
}

type devDrive struct{ dev, drive string }

var devs []devDrive

func devMap() []devDrive {
	if devs != nil {
		return devs
	}
	buf := make([]uint16, 512)
	for c := 'A'; c <= 'Z'; c++ {
		d := string(c) + ":"
		dp, _ := windows.UTF16PtrFromString(d)
		n, err := windows.QueryDosDevice(dp, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		devs = append(devs, devDrive{windows.UTF16ToString(buf[:n]), d})
	}
	if devs == nil {
		devs = []devDrive{}
	}
	return devs
}
