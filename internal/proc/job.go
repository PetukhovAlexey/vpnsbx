package proc

import (
	"encoding/json"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Job Object на корневой процесс правила. Потомки попадают в него ядром в
// момент создания, поэтому короткоживущий посредник (cmd /c start …) уже не
// рвёт цепочку. Флаг KILL_ON_JOB_CLOSE — сторож: если служба умерла, ядро
// закрывает её дескрипторы и завершает процессы песочницы. При штатной
// остановке флаг снимается до закрытия дескриптора, а участники job
// сохраняются (см. saveMembers): следующий запуск возьмёт их под правило
// снова, иначе программа, запущенная в песочнице до перезапуска, вышла бы
// в сеть напрямую. Сам job по имени не открыть: имя исчезает вместе с
// последним дескриптором.
type job struct {
	h     windows.Handle
	key   uintptr  // ключ уведомлений в порту
	root  uint32   // PID корня
	chain []string // цепочка путей корня: по ней правило пересчитывается
	rule  string
}

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob            = kernel32.NewProc("IsProcessInJob")
	procGetQueuedCompletionStatus = kernel32.NewProc("GetQueuedCompletionStatus")
)

const (
	msgNewProcess = 6 // JOB_OBJECT_MSG_NEW_PROCESS
	quitKey       = 0 // ключ, по которому поток порта завершается
)

type associatePort struct {
	key  uintptr
	port windows.Handle
}

func setKillOnClose(h windows.Handle, on bool) error {
	var li windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if on {
		li.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	_, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&li)), uint32(unsafe.Sizeof(li)))
	return err
}

// newJob создаёт job с KILL_ON_JOB_CLOSE и уведомлениями в порт.
func newJob(port windows.Handle, key uintptr) (windows.Handle, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	if err := setKillOnClose(h, true); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	ap := associatePort{key, port}
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&ap)), uint32(unsafe.Sizeof(ap))); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// jobPIDs — процессы в job (включая вложенные job).
func jobPIDs(h windows.Handle) []uint32 {
	const jobObjectBasicProcessIdList = 3
	buf := make([]uintptr, 2+4096)
	if windows.QueryInformationJobObject(h, jobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buf[0])),
		uint32(len(buf))*uint32(unsafe.Sizeof(buf[0])), nil) != nil {
		return nil
	}
	n := uint32(buf[0] >> 32) // NumberOfProcessIdsInList — второй ULONG
	var out []uint32
	for i := uint32(0); i < n && int(i)+1 < len(buf); i++ {
		out = append(out, uint32(buf[1+i]))
	}
	return out
}

// member — процесс песочницы, отпущенный при штатной остановке.
type member struct {
	PID     uint32   `json:"pid"`
	Created int64    `json:"created"`
	Chain   []string `json:"chain"`
	Rule    string   `json:"rule"`
}

func saveMembers(path string, list []member) {
	if path == "" {
		return
	}
	if len(list) == 0 {
		os.Remove(path)
		return
	}
	b, _ := json.Marshal(list)
	os.WriteFile(path, b, 0o600)
}

// loadMembers читает и удаляет файл: он нужен только одному запуску.
func loadMembers(path string) []member {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	os.Remove(path)
	if err != nil {
		return nil
	}
	var list []member
	json.Unmarshal(b, &list)
	return list
}

// release отпускает процессы: снимает флаг и закрывает дескриптор.
func (j *job) release() {
	setKillOnClose(j.h, false)
	windows.CloseHandle(j.h)
}

func inJob(proc, job windows.Handle) bool {
	var res int32
	r, _, _ := procIsProcessInJob.Call(uintptr(proc), uintptr(job), uintptr(unsafe.Pointer(&res)))
	return r != 0 && res != 0
}

// waitPort ждёт уведомление. Для сообщений job в overlapped лежит PID,
// поэтому принимаем его как число, а не как указатель.
func waitPort(port windows.Handle) (msg uint32, key uintptr, pid uint32, ok bool) {
	var ov uintptr
	r, _, _ := procGetQueuedCompletionStatus.Call(uintptr(port), uintptr(unsafe.Pointer(&msg)),
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&ov)), uintptr(windows.INFINITE))
	return msg, key, uint32(ov), r != 0
}

// parentOf — PID родителя по ядру (для процессов, о которых сообщил job
// раньше, чем их увидел снимок).
func parentOf(pid uint32) uint32 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var bi windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&bi),
		uint32(unsafe.Sizeof(bi)), nil) != nil {
		return 0
	}
	return uint32(bi.InheritedFromUniqueProcessId)
}

func createdOf(h windows.Handle) int64 {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
}
