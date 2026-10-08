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

// Rule — путь exe (точное совпадение) или папка (всё внутри, рекурсивно),
// ID — метка, которую получают процессы под правилом.
type Rule struct {
	ID     string
	Path   string
	Folder bool
}

// RuleFromPath определяет по файловой системе, exe это или папка.
func RuleFromPath(id, path string) (Rule, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Rule{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return Rule{}, err
	}
	return Rule{ID: id, Path: filepath.Clean(abs), Folder: st.IsDir()}, nil
}

// Rules — набор правил. Точное совпадение exe сильнее папки,
// из папок побеждает самая глубокая.
type Rules struct {
	exes    map[string]string // путь в нижнем регистре → ID
	folders []folderRule
}

type folderRule struct {
	prefix string // в нижнем регистре, с завершающим \
	id     string
}

func NewRules(list []Rule) *Rules {
	r := &Rules{exes: map[string]string{}}
	for _, x := range list {
		key := strings.ToLower(filepath.Clean(x.Path))
		if x.Folder {
			r.folders = append(r.folders, folderRule{strings.TrimSuffix(key, `\`) + `\`, x.ID})
		} else {
			r.exes[key] = x.ID
		}
	}
	return r
}

// Match возвращает ID правила для пути exe ("" — не под правилом).
func (r *Rules) Match(path string) string {
	if path == "" || r == nil {
		return ""
	}
	k := strings.ToLower(path)
	if id, ok := r.exes[k]; ok {
		return id
	}
	best, id := 0, ""
	for _, f := range r.folders {
		if len(f.prefix) > best && strings.HasPrefix(k, f.prefix) {
			best, id = len(f.prefix), f.id
		}
	}
	return id
}

type procInfo struct {
	parent  uint32
	created int64 // FILETIME, 100 нс
	path    string
	chain   []string // пути: свой, родителя, деда… (на момент появления)
	linked  bool     // chain собрана
	rule    string   // ID правила ("" — не под правилом)
	seen    time.Time
}

// Tracker следит за деревом процессов. Процесс под правилом, если под
// правилом его exe или exe любого предка (ближайший побеждает). Цепочка
// предков запоминается при появлении процесса, поэтому смена правил
// пересчитывается верно, даже если предки давно завершились.
type Tracker struct {
	self uint32

	mu      sync.Mutex
	rules   *Rules
	procs   map[uint32]*procInfo
	updated time.Time
	stop    chan struct{}
}

// Keep — сколько помнить завершившиеся процессы (их потомки ещё живы,
// а пакеты ещё в пути).
const Keep = 10 * time.Second

const maxChain = 64

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

// SetRules заменяет правила и пересчитывает все известные процессы.
func (t *Tracker) SetRules(r *Rules) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rules = r
	for _, p := range t.procs {
		p.rule = t.match(p.chain)
	}
}

// Matched — ID правила для PID ("" — не под правилом). Неизвестный PID
// вызывает внеочередной снимок (не чаще раза в 5 мс). known=false — процесс
// не найден.
func (t *Tracker) Matched(pid uint32) (rule string, known bool) {
	if pid == t.self || pid == 0 || pid == 4 {
		return "", true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.procs[pid]
	if !ok && time.Since(t.updated) > 5*time.Millisecond {
		t.refresh()
		p, ok = t.procs[pid]
	}
	if !ok {
		return "", false
	}
	return p.rule, true
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

// Proc — живой процесс под правилом.
type Proc struct {
	PID    uint32 `json:"pid"`
	Parent uint32 `json:"parent"`
	Path   string `json:"path"`
	Rule   string `json:"rule"`
}

// Sandboxed — все живые процессы под правилами.
func (t *Tracker) Sandboxed() []Proc {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Proc
	for pid, p := range t.procs {
		if p.rule != "" && p.seen.Equal(t.updated) {
			out = append(out, Proc{pid, p.parent, p.path, p.rule})
		}
	}
	return out
}

func (t *Tracker) refresh() {
	now := time.Now()
	list := snapshot()
	if list == nil {
		return
	}
	var fresh []uint32
	for _, e := range list {
		p := t.procs[e.PID]
		if p != nil {
			// тот же процесс, если совпадает родитель (PID мог переиспользоваться)
			if p.parent == e.Parent {
				p.seen = now
				continue
			}
			delete(t.procs, e.PID)
		}
		path, created := query(e.PID)
		t.procs[e.PID] = &procInfo{parent: e.Parent, created: created, path: path, seen: now}
		fresh = append(fresh, e.PID)
	}
	// Новые процессы: цепочку собираем рекурсивно через родителя,
	// поэтому порядок обхода не важен.
	for _, pid := range fresh {
		t.link(pid, 0)
	}
	for pid, p := range t.procs {
		if now.Sub(p.seen) > Keep {
			delete(t.procs, pid)
		}
	}
	t.updated = now
}

// link собирает цепочку путей предков и вычисляет правило.
func (t *Tracker) link(pid uint32, depth int) []string {
	p := t.procs[pid]
	if p == nil {
		return nil
	}
	if p.linked || depth > maxChain {
		return p.chain
	}
	p.linked = true
	p.chain = []string{p.path}
	// родитель годится, только если он старше (иначе PID переиспользован)
	if par := t.procs[p.parent]; par != nil && p.parent != pid && par.created != 0 && par.created <= p.created &&
		p.parent != t.self {
		pc := t.link(p.parent, depth+1)
		if len(pc) > maxChain-1 {
			pc = pc[:maxChain-1]
		}
		p.chain = append(p.chain, pc...)
	}
	if pid != t.self {
		p.rule = t.match(p.chain)
	}
	return p.chain
}

func (t *Tracker) match(chain []string) string {
	for _, path := range chain {
		if id := t.rules.Match(path); id != "" {
			return id
		}
	}
	return ""
}

// Entry — процесс из снимка системы.
type Entry struct {
	PID    uint32 `json:"pid"`
	Parent uint32 `json:"parent"`
	Path   string `json:"path,omitempty"`
}

func snapshot() []Entry {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var list []Entry
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		list = append(list, Entry{PID: pe.ProcessID, Parent: pe.ParentProcessID})
	}
	return list
}

// List — все процессы системы с путями exe (где путь доступен).
func List() []Entry {
	list := snapshot()
	for i := range list {
		list[i].Path, _ = query(list[i].PID)
	}
	return list
}

// Kill завершает процесс.
func Kill(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
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
