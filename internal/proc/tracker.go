package proc

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Rules — пути exe (точное совпадение) и папки (всё внутри, рекурсивно).
type Rules struct {
	exes    map[string]bool
	folders []string // с завершающим \
}

// NewRules принимает пути к exe или папкам.
func NewRules(paths []string) (*Rules, error) {
	r := &Rules{exes: map[string]bool{}}
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		st, err := os.Stat(abs)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(filepath.Clean(abs))
		if st.IsDir() {
			r.folders = append(r.folders, strings.TrimSuffix(key, `\`)+`\`)
		} else {
			r.exes[key] = true
		}
	}
	return r, nil
}

func (r *Rules) Match(path string) bool {
	if path == "" {
		return false
	}
	k := strings.ToLower(path)
	if r.exes[k] {
		return true
	}
	for _, f := range r.folders {
		if strings.HasPrefix(k, f) {
			return true
		}
	}
	return false
}

type procInfo struct {
	parent  uint32
	created int64 // FILETIME, 100 нс
	path    string
	matched bool
	seen    time.Time // последний снимок, где процесс был жив
}

// Tracker следит за деревом процессов: процесс под правилом, если его exe
// подходит под правило или его родитель под правилом (и родитель старше,
// т.е. PID родителя не переиспользован).
type Tracker struct {
	rules *Rules
	self  uint32

	mu      sync.Mutex
	procs   map[uint32]*procInfo
	updated time.Time
	stop    chan struct{}
}

// Keep — сколько помнить завершившиеся процессы (их потомки ещё живы,
// а пакеты ещё в пути).
const Keep = 10 * time.Second

func NewTracker(r *Rules) *Tracker {
	t := &Tracker{rules: r, self: uint32(os.Getpid()), procs: map[uint32]*procInfo{}, stop: make(chan struct{})}
	t.mu.Lock()
	t.refresh()
	t.mu.Unlock()
	go t.loop()
	return t
}

func (t *Tracker) Close() { close(t.stop) }

func (t *Tracker) loop() {
	tk := time.NewTicker(250 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			t.mu.Lock()
			t.refresh()
			t.mu.Unlock()
		case <-t.stop:
			return
		}
	}
}

// Matched — подпадает ли PID под правило. Неизвестный PID вызывает
// внеочередной снимок (не чаще раза в 5 мс). known=false — процесс не найден.
func (t *Tracker) Matched(pid uint32) (matched, known bool) {
	if pid == t.self || pid == 0 || pid == 4 {
		return false, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.procs[pid]
	if !ok && time.Since(t.updated) > 5*time.Millisecond {
		t.refresh()
		p, ok = t.procs[pid]
	}
	if !ok {
		return false, false
	}
	return p.matched, true
}

// Path возвращает путь exe (для логов).
func (t *Tracker) Path(pid uint32) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.procs[pid]; ok {
		return p.path
	}
	return ""
}

// MatchedPIDs — все живые PID под правилом.
func (t *Tracker) MatchedPIDs() []uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []uint32
	for pid, p := range t.procs {
		if p.matched && p.seen.Equal(t.updated) {
			out = append(out, pid)
		}
	}
	return out
}

func (t *Tracker) refresh() {
	now := time.Now()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	type ent struct{ pid, parent uint32 }
	var list []ent
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		list = append(list, ent{pe.ProcessID, pe.ParentProcessID})
	}

	var fresh []uint32
	for _, e := range list {
		p := t.procs[e.pid]
		if p != nil {
			// тот же процесс, если совпадает родитель (PID мог переиспользоваться)
			if p.parent == e.parent {
				p.seen = now
				continue
			}
			delete(t.procs, e.pid)
		}
		path, created := query(e.pid)
		t.procs[e.pid] = &procInfo{parent: e.parent, created: created, path: path, seen: now}
		fresh = append(fresh, e.pid)
	}
	// Новые процессы: сортировка по времени создания не нужна — разрешаем
	// цепочку рекурсивно через родителя.
	for _, pid := range fresh {
		t.resolve(pid, 0)
	}
	for pid, p := range t.procs {
		if now.Sub(p.seen) > Keep {
			delete(t.procs, pid)
		}
	}
	t.updated = now
}

func (t *Tracker) resolve(pid uint32, depth int) bool {
	p := t.procs[pid]
	if p == nil {
		return false
	}
	if p.matched || depth > 64 {
		return p.matched
	}
	if pid == t.self {
		return false
	}
	if t.rules.Match(p.path) {
		p.matched = true
		return true
	}
	if par := t.procs[p.parent]; par != nil && p.parent != pid && par.created != 0 && par.created <= p.created {
		if par.matched || t.resolve(p.parent, depth+1) {
			p.matched = true
		}
	}
	return p.matched
}

func query(pid uint32) (string, int64) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", 0
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	var created int64
	if windows.GetProcessTimes(h, &c, &e, &k, &u) == nil {
		created = int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return "", created
	}
	return windows.UTF16ToString(buf[:n]), created
}
