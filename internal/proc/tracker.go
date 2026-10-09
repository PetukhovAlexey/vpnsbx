package proc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// Empty — правил нет.
func (r *Rules) Empty() bool {
	return r == nil || (len(r.exes) == 0 && len(r.folders) == 0)
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
	job     *job // наш job, в котором процесс (самый вложенный)
	tried   bool // поместить в job не удалось — больше не пытаемся
	orphan  bool // при сборке цепочки родитель был неизвестен
	pinned  bool // цепочка взята из прошлого запуска службы, не пересобирается
}

// Tracker следит за деревом процессов. Процесс под правилом, если под
// правилом его exe или exe любого предка (ближайший побеждает). Цепочка
// предков запоминается при появлении процесса, поэтому смена правил
// пересчитывается верно, даже если предки давно завершились.
//
// О запусках процессов сообщает ETW (см. etw.go) — сразу, с родителем и
// путём, даже если процесс уже завершился; снимок — запасной путь. Процесс
// под правилом помещается в job (см. job.go): его потомки наследуют правило,
// даже если цепочка предков оборвалась.
type Tracker struct {
	self  uint32
	logf  func(string, ...any)
	state string     // файл участников песочницы между запусками ("" — не сохранять)
	etw   *procWatch // nil — ETW недоступен, только снимки

	mu      sync.Mutex
	rules   *Rules
	procs   map[uint32]*procInfo
	updated time.Time
	stop    chan struct{}

	port     windows.Handle // уведомления job; 0 — job не используются
	portDone chan struct{}
	jobs     map[uintptr]*job
	lastKey  uintptr

	gen atomic.Uint64 // растёт, когда у какого-либо процесса меняется правило
}

// Gen растёт при каждой смене правила у любого процесса: решения «не под
// правилом», принятые раньше, надо перепроверить.
func (t *Tracker) Gen() uint64 { return t.gen.Load() }

func (t *Tracker) setRule(p *procInfo, rule string) {
	if p.rule != rule {
		p.rule = rule
		t.gen.Add(1)
	}
}

// Keep — сколько помнить завершившиеся процессы (их потомки ещё живы,
// а пакеты ещё в пути).
const Keep = 10 * time.Second

const maxChain = 64

// Период снимка процессов: с ETW снимок только страхует, без него — основной.
const (
	pollETW   = 250 * time.Millisecond
	pollNoETW = 50 * time.Millisecond
)

// Young — сколько процесс с неизвестным родителем считается «ещё не
// разобранным» (ETW мог не успеть сообщить о родителе).
const Young = 2 * time.Second

// NewTracker запускает слежение. logf — для сообщений о job (может быть nil).
// state — файл, где при штатной остановке запоминаются процессы песочницы,
// чтобы следующий запуск взял их под правило снова.
func NewTracker(r *Rules, logf func(string, ...any), state string) *Tracker {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &Tracker{rules: r, self: uint32(os.Getpid()), logf: logf, state: state, procs: map[uint32]*procInfo{},
		stop: make(chan struct{}), jobs: map[uintptr]*job{}, portDone: make(chan struct{})}
	if port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1); err != nil {
		logf("job недоступны (порт: %v), наследование только по цепочке предков", err)
		close(t.portDone)
	} else {
		t.port = port
		go t.portLoop()
	}
	// ETW до первого снимка: родители всех процессов, запущенных после
	// снимка, будут известны.
	if w, err := watchProcesses(t.started); err != nil {
		logf("ETW недоступен (%v): запуски видны только по снимкам раз в %v", err, pollNoETW)
	} else {
		t.etw = w
	}
	t.mu.Lock()
	t.refresh()
	t.restore(loadMembers(state))
	t.mu.Unlock()
	go t.loop()
	return t
}

// restore возвращает в песочницу процессы прошлого запуска: тот же PID и
// время создания — тот же процесс; его цепочка берётся из файла (предки
// могли завершиться), потомки получают её через родителя.
func (t *Tracker) restore(list []member) {
	n := 0
	for _, m := range list {
		if p := t.procs[m.PID]; p != nil && p.created == m.Created && m.Created != 0 {
			p.chain, p.pinned = m.Chain, true
			n++
		}
	}
	if n > 0 {
		t.relinkAll()
		t.logf("из прошлого запуска возвращено в песочницу процессов: %d", n)
	}
}

// members — процессы песочницы для сохранения: под правилом и все члены
// наших job (о некоторых снимок может ещё не знать).
func (t *Tracker) members() []member {
	seen := map[uint32]bool{}
	var out []member
	for pid, p := range t.procs {
		if p.rule != "" && p.created != 0 && p.seen.Equal(t.updated) {
			seen[pid] = true
			chain := p.chain
			if t.match(chain) == "" && p.job != nil { // правило от job
				chain = append([]string{p.path}, p.job.chain...)
			}
			out = append(out, member{pid, p.created, chain, p.rule})
		}
	}
	for _, j := range t.jobs {
		for _, pid := range jobPIDs(j.h) {
			if seen[pid] {
				continue
			}
			seen[pid] = true
			if path, created := query(pid); created != 0 {
				out = append(out, member{pid, created, append([]string{path}, j.chain...), j.rule})
			}
		}
	}
	return out
}

// started — ETW: запущен процесс.
func (t *Tracker) started(pid, parent uint32, created int64, path string) {
	if pid == t.self || pid == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.procs[pid]; p != nil && p.created == created {
		// снимок увидел его раньше; если родителя тогда не знал — теперь знает
		if p.orphan {
			t.relinkAll()
		}
		return
	}
	t.procs[pid] = &procInfo{parent: parent, created: created, path: path, seen: time.Now()}
	t.link(pid, 0)
	t.ensureJobs()
}

// relinkAll пересобирает все цепочки (узнали пропущенного предка).
func (t *Tracker) relinkAll() {
	for _, p := range t.procs {
		p.linked = false
	}
	for pid := range t.procs {
		t.link(pid, 0)
	}
	t.ensureJobs()
}

// Uncertain — процесс не под правилом, но решить это наверняка нельзя:
//   - путь его exe неизвестен (правило не сравнить), пока правила есть;
//   - только что запущен, а его родитель неизвестен: возможно, ETW ещё не
//     сообщил о посреднике.
//
// Его пакеты лучше отбросить (TCP и DNS повторят), чем выпустить мимо туннеля.
func (t *Tracker) Uncertain(pid uint32) bool {
	if pid == t.self || pid == 0 || pid == 4 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.procs[pid]
	if p == nil || p.rule != "" {
		return false
	}
	if !t.rules.Empty() && (unresolved(p.path) || ntChain(p.chain)) {
		return true
	}
	if t.etw == nil || !p.orphan || p.created == 0 {
		return false
	}
	ft := windows.Filetime{LowDateTime: uint32(p.created), HighDateTime: uint32(p.created >> 32)}
	return time.Since(time.Unix(0, ft.Nanoseconds())) < Young
}

// Close останавливает слежение. kill=false — штатно: процессы отпускаются.
// kill=true — служба трафика не может продолжать: закрытие job завершает
// процессы песочницы (то же сделает ядро, если служба умрёт).
func (t *Tracker) Close(kill bool) {
	close(t.stop)
	if t.etw != nil {
		t.etw.Close()
	}
	t.mu.Lock()
	if kill {
		os.Remove(t.state)
	} else {
		saveMembers(t.state, t.members())
	}
	for _, j := range t.jobs {
		if kill {
			windows.CloseHandle(j.h)
		} else {
			j.release()
		}
	}
	if kill && len(t.jobs) > 0 {
		t.logf("песочница завершена: закрыто job %d", len(t.jobs))
	}
	t.jobs = map[uintptr]*job{}
	t.mu.Unlock()
	if t.port != 0 {
		windows.PostQueuedCompletionStatus(t.port, 0, quitKey, nil)
		<-t.portDone
		windows.CloseHandle(t.port)
	}
}

func (t *Tracker) portLoop() {
	defer close(t.portDone)
	for {
		msg, key, pid, ok := waitPort(t.port)
		if !ok || key == quitKey {
			return
		}
		if msg == msgNewProcess {
			t.mu.Lock()
			t.joined(key, pid)
			t.mu.Unlock()
		}
	}
}

// joined — ядро сообщило, что pid вошёл в job.
func (t *Tracker) joined(key uintptr, pid uint32) {
	j := t.jobs[key]
	if j == nil || pid == t.self {
		return
	}
	path, created := query(pid)
	p := t.procs[pid]
	if p == nil || (created != 0 && p.created != created) {
		p = &procInfo{parent: parentOf(pid), created: created, path: path, seen: time.Now()}
		t.procs[pid] = p
	}
	if p.job == nil || p.job.key < key {
		p.job = j
	}
	if unresolved(p.path) && !unresolved(path) {
		p.path = path
		t.relinkAll()
	} else if p.linked {
		t.setRule(p, t.resolve(p))
	} else {
		t.link(pid, 0)
	}
}

func (t *Tracker) loop() {
	poll := pollNoETW
	if t.etw != nil {
		poll = pollETW
	}
	tk := time.NewTicker(poll)
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
	for k, j := range t.jobs {
		if j.rule = t.match(j.chain); j.rule == "" {
			j.release()
			delete(t.jobs, k)
			t.logf("job процесса %d отпущен: правила больше нет", j.root)
		}
	}
	for _, p := range t.procs {
		if p.job != nil && p.job.rule == "" {
			p.job = nil
		}
		p.tried = false
		t.setRule(p, t.resolve(p))
	}
	t.gen.Add(1)
	t.ensureJobs()
}

// KillRule завершает все процессы правила: job целиком (вместе с
// потомками, о которых снимок ещё не знает), остальные — по одному.
func (t *Tracker) KillRule(id string) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var errs []error
	for _, j := range t.jobs {
		if j.rule == id {
			if err := windows.TerminateJobObject(j.h, 1); err != nil {
				errs = append(errs, fmt.Errorf("job %d: %w", j.root, err))
			}
		}
	}
	n := 0
	for pid, p := range t.procs {
		if p.rule != id || !p.seen.Equal(t.updated) {
			continue
		}
		if p.job == nil || p.job.rule != id {
			if err := Kill(pid); err != nil {
				errs = append(errs, fmt.Errorf("%d: %w", pid, err))
				continue
			}
		}
		n++
	}
	return n, errors.Join(errs...)
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
	relink := false
	for _, e := range list {
		p := t.procs[e.PID]
		if p != nil {
			// тот же процесс, если совпадает родитель (PID мог переиспользоваться)
			if p.parent == e.Parent {
				p.seen = now
				if unresolved(p.path) && t.fixPath(e.PID, p) {
					relink = true
				}
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
	if relink {
		t.relinkAll() // путь предка стал известен: цепочки потомков тоже
	} else {
		t.ensureJobs()
	}
}

// fixPath — путь процесса не был известен (ETW дал NT-путь тома, которого
// ещё не было в таблице, или процесс не открылся): спросить снова.
func (t *Tracker) fixPath(pid uint32, p *procInfo) bool {
	path := ntToDos(p.path)
	if unresolved(path) {
		var created int64
		if path, created = query(pid); created != p.created && p.created != 0 {
			return false // PID уже другого процесса
		}
	}
	if unresolved(path) {
		return false
	}
	t.logf("pid %d: путь выяснен позже: %s", pid, path)
	p.path = path
	return true
}

// ensureJobs помещает в job живые процессы под правилом, которые ещё не в
// job этого правила.
func (t *Tracker) ensureJobs() {
	if t.port == 0 {
		return
	}
	for pid, p := range t.procs {
		if p.rule == "" || p.tried || pid == t.self || (p.job != nil && p.job.rule == p.rule) {
			continue
		}
		t.assign(pid, p)
	}
}

func (t *Tracker) assign(pid uint32, p *procInfo) {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|
		windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		p.tried = true
		if p.seen.Equal(t.updated) {
			t.logf("pid %d %s: в job не поместить (%v), только цепочка предков", pid, p.path, err)
		}
		return
	}
	defer windows.CloseHandle(h)
	if createdOf(h) != p.created {
		p.tried = true // PID уже другого процесса
		return
	}
	// создан после того, как родитель попал в job, — уже там
	if par := t.procs[p.parent]; par != nil && par.job != nil && par.job.rule == p.rule && inJob(h, par.job.h) {
		p.job = par.job
		return
	}
	t.lastKey++
	key := t.lastKey
	jh, err := newJob(t.port, key)
	if err == nil {
		if err = windows.AssignProcessToJobObject(jh, h); err != nil {
			windows.CloseHandle(jh) // пустой: закрытие никого не завершит
		}
	}
	if err != nil {
		p.tried = true
		t.logf("pid %d %s: в job не поместить (%v), только цепочка предков", pid, p.path, err)
		return
	}
	t.jobs[key] = &job{h: jh, key: key, root: pid, chain: p.chain, rule: p.rule}
	t.logf("pid %d %s: в job правила %s", pid, p.path, p.rule)
	p.job = t.jobs[key]
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
	if p.pinned {
		p.orphan = false
		t.setRule(p, t.resolve(p))
		return p.chain
	}
	p.chain = []string{p.path}
	p.orphan = true
	// родитель годится, только если он старше (иначе PID переиспользован)
	if par := t.procs[p.parent]; par != nil && p.parent != pid && par.created != 0 && par.created <= p.created &&
		p.parent != t.self {
		p.orphan = false
		pc := t.link(p.parent, depth+1)
		if len(pc) > maxChain-1 {
			pc = pc[:maxChain-1]
		}
		p.chain = append(p.chain, pc...)
	}
	if pid != t.self {
		t.setRule(p, t.resolve(p))
	}
	return p.chain
}

// resolve: цепочка предков (ближайшее совпадение), иначе — job.
func (t *Tracker) resolve(p *procInfo) string {
	if id := t.match(p.chain); id != "" {
		return id
	}
	if p.job != nil {
		return p.job.rule
	}
	return ""
}

func (t *Tracker) match(chain []string) string {
	for _, path := range chain {
		if unresolved(path) {
			path = ntToDos(path) // предок мог завершиться, пока его том был без буквы
		}
		if id := t.rules.Match(path); id != "" {
			return id
		}
	}
	return ""
}

// ntChain — в цепочке есть предок, чей путь так и не перевести в C:\….
func ntChain(chain []string) bool {
	for _, path := range chain {
		if path != "" && unresolved(path) && unresolved(ntToDos(path)) {
			return true
		}
	}
	return false
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
