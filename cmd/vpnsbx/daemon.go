package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"vpnsbx/internal/config"
	"vpnsbx/internal/engine"
	"vpnsbx/internal/ipc"
	"vpnsbx/internal/proc"
	"vpnsbx/internal/profile"
)

// ring хранит последние строки лога для интерфейса.
type ring struct {
	mu    sync.Mutex
	lines []string
}

func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, strings.TrimRight(string(p), "\n"))
	if len(r.lines) > 300 {
		r.lines = r.lines[len(r.lines)-300:]
	}
	return len(p), nil
}

func (r *ring) tail() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

type daemon struct {
	log  *log.Logger
	ring *ring
	srv  *ipc.Server

	mu     sync.Mutex
	cfg    *config.Config
	eng    *engine.Engine
	cancel context.CancelFunc
	done   chan struct{}
	runErr atomic.Pointer[string] // почему движок остановился сам
}

// daemonCmd: vpnsbx daemon — служба: фильтр по config.json и команды по каналу.
func daemonCmd(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	fs.Parse(args)
	if err := config.Ensure(); err != nil {
		return fmt.Errorf("каталог %s: %w", config.Dir(), err)
	}
	logPath := filepath.Join(config.Dir(), "daemon.log")
	if st, err := os.Stat(logPath); err == nil && st.Size() > 5<<20 {
		os.Remove(logPath)
	}
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	d := &daemon{ring: &ring{}}
	// stdout последним: у отсоединённого процесса его нет, а MultiWriter
	// останавливается на первой ошибке.
	d.log = log.New(io.MultiWriter(d.ring, lf, os.Stdout), "", log.Ldate|log.Ltime)

	if d.srv, err = ipc.Listen(ipc.Pipe); err != nil {
		return err
	}
	if d.cfg, err = config.Load(); err != nil {
		return fmt.Errorf("config.json: %w", err)
	}
	d.log.Printf("служба запущена (pid %d), защита: %v", os.Getpid(), onOff(d.cfg.Enabled))
	d.mu.Lock()
	if d.cfg.Enabled {
		d.startEngine()
	}
	d.mu.Unlock()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		d.srv.Close()
	}()
	err = d.srv.Serve(d.handle)
	d.mu.Lock()
	d.stopEngine()
	d.mu.Unlock()
	d.log.Printf("служба остановлена")
	return err
}

func onOff(v bool) string {
	if v {
		return "вкл"
	}
	return "выкл"
}

func (d *daemon) running() bool {
	if d.eng == nil {
		return false
	}
	select {
	case <-d.done:
		return false
	default:
		return true
	}
}

// startEngine — под d.mu.
func (d *daemon) startEngine() {
	if d.running() {
		return
	}
	d.runErr.Store(nil)
	e, err := engine.New(engine.Config{Log: d.log, SandboxFile: filepath.Join(config.Dir(), "sandbox.json")})
	if err != nil {
		s := err.Error()
		d.runErr.Store(&s)
		d.log.Printf("фильтр не запущен: %v", err)
		return
	}
	e.Apply(d.setup())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.eng, d.cancel, d.done = e, cancel, done
	go func() {
		defer close(done)
		if err := e.Run(ctx); err != nil {
			s := err.Error()
			d.runErr.Store(&s)
			d.log.Printf("фильтр остановлен с ошибкой: %v", err)
		}
	}()
}

// stopEngine — под d.mu. Ждёт, пока драйвер отпустит адаптеры.
func (d *daemon) stopEngine() {
	if d.eng == nil {
		return
	}
	d.cancel()
	<-d.done
	d.eng = nil
	d.log.Printf("фильтр снят")
}

// setup собирает профили и включённые правила для движка.
func (d *daemon) setup() engine.Setup {
	var s engine.Setup
	for _, p := range d.cfg.Profiles {
		b, err := os.ReadFile(config.ProfilePath(p.ID))
		if err != nil {
			d.log.Printf("профиль %q: %v", p.Name, err)
			continue
		}
		s.Profiles = append(s.Profiles, engine.ProfileSpec{ID: p.ID, Name: p.Name, Text: string(b)})
	}
	for _, r := range d.cfg.Rules {
		if r.Enabled {
			s.Rules = append(s.Rules, engine.RuleSpec{
				Rule: proc.Rule{ID: r.ID, Path: r.Path, Folder: r.Folder}, Profile: r.Profile})
		}
	}
	return s
}

// commit сохраняет конфигурацию и применяет её к работающему фильтру. Под d.mu.
func (d *daemon) commit() error {
	if err := d.cfg.Save(); err != nil {
		return err
	}
	if d.running() {
		d.eng.Apply(d.setup())
	}
	return nil
}

type status struct {
	Enabled  bool                  `json:"enabled"`
	Running  bool                  `json:"running"`
	Err      string                `json:"err,omitempty"`
	Adapters []string              `json:"adapters"`
	Tunnels  []engine.TunnelStatus `json:"tunnels"`
	Stats    map[string]uint64     `json:"stats"`
	Profiles []config.Profile      `json:"profiles"`
	Rules    []config.Rule         `json:"rules"`
	PID      int                   `json:"pid"`
}

type procView struct {
	proc.Proc
	Profile string `json:"profile"`
}

func (d *daemon) handle(pid uint32, cmd string, raw json.RawMessage) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running() && d.eng.RuleOf(pid) != "" {
		d.log.Printf("отказ: команда %q от процесса %d из песочницы", cmd, pid)
		return nil, errors.New("команды из песочницы запрещены")
	}
	arg := func(v any) error {
		if len(raw) == 0 {
			return errors.New("нет аргументов")
		}
		return json.Unmarshal(raw, v)
	}
	switch cmd {
	case "status":
		s := status{Enabled: d.cfg.Enabled, Running: d.running(), Profiles: d.cfg.Profiles, Rules: d.cfg.Rules,
			PID: os.Getpid()}
		if p := d.runErr.Load(); p != nil {
			s.Err = *p
		}
		if s.Running {
			s.Adapters = d.eng.AdapterNames()
			s.Tunnels = d.eng.Tunnels()
			st := &d.eng.Stats
			s.Stats = map[string]uint64{"out": st.Out.Load(), "toTunnel": st.ToTunnel.Load(),
				"fromTunnel": st.FromTunnel.Load(), "blocked": st.Blocked.Load(), "dropped": st.Dropped.Load(), "deferred": st.Deferred.Load()}
		}
		return s, nil

	case "procs":
		out := []procView{}
		if d.running() {
			for _, p := range d.eng.Sandboxed() {
				v := procView{Proc: p}
				if r := d.cfg.Rule(p.Rule); r != nil {
					v.Profile = r.Profile
				}
				out = append(out, v)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
		return out, nil

	case "log":
		return d.ring.tail(), nil

	case "enable":
		var a struct{ On bool }
		if err := arg(&a); err != nil {
			return nil, err
		}
		d.cfg.Enabled = a.On
		if err := d.cfg.Save(); err != nil {
			return nil, err
		}
		d.log.Printf("защита: %s (pid %d)", onOff(a.On), pid)
		if a.On {
			d.startEngine()
		} else {
			d.stopEngine()
		}
		return nil, nil

	case "addProfile":
		var a struct{ Path, Text, Name string }
		if err := arg(&a); err != nil {
			return nil, err
		}
		var p *profile.Profile
		var err error
		if a.Path != "" {
			p, err = profile.Load(a.Path)
		} else {
			p, err = profile.Parse(a.Text, a.Name)
		}
		if err != nil {
			return nil, err
		}
		if p.Kind != profile.KindAWG {
			return nil, fmt.Errorf("поддерживаются только AmneziaWG/WireGuard (это %s)", p.Kind)
		}
		if _, err := profile.ParseAWG(p.Text); err != nil {
			return nil, err
		}
		if a.Name != "" {
			p.Name = a.Name
		}
		id := config.NewID()
		if err := config.Ensure(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(config.ProfilePath(id), []byte(p.Text), 0o600); err != nil {
			return nil, err
		}
		d.cfg.Profiles = append(d.cfg.Profiles, config.Profile{ID: id, Name: p.Name})
		d.log.Printf("профиль %q добавлен", p.Name)
		return id, d.commit()

	case "renameProfile":
		var a struct{ ID, Name string }
		if err := arg(&a); err != nil {
			return nil, err
		}
		p := d.cfg.Profile(a.ID)
		if p == nil || strings.TrimSpace(a.Name) == "" {
			return nil, errors.New("нет такого профиля или пустое имя")
		}
		p.Name = strings.TrimSpace(a.Name)
		return nil, d.commit()

	case "removeProfile":
		var a struct{ ID string }
		if err := arg(&a); err != nil {
			return nil, err
		}
		var used []string
		for _, r := range d.cfg.Rules {
			if r.Profile == a.ID {
				used = append(used, filepath.Base(r.Path))
			}
		}
		if len(used) > 0 {
			return nil, fmt.Errorf("профиль используется правилами: %s", strings.Join(used, ", "))
		}
		for i, p := range d.cfg.Profiles {
			if p.ID == a.ID {
				d.cfg.Profiles = append(d.cfg.Profiles[:i], d.cfg.Profiles[i+1:]...)
				os.Remove(config.ProfilePath(a.ID))
				d.log.Printf("профиль %q удалён", p.Name)
				return nil, d.commit()
			}
		}
		return nil, errors.New("нет такого профиля")

	case "addRule":
		var a struct{ Path, Profile string }
		if err := arg(&a); err != nil {
			return nil, err
		}
		r, err := proc.RuleFromPath("", a.Path)
		if err != nil {
			return nil, err
		}
		for _, x := range d.cfg.Rules {
			if strings.EqualFold(x.Path, r.Path) {
				return nil, fmt.Errorf("правило для %s уже есть", r.Path)
			}
		}
		if a.Profile == "" && len(d.cfg.Profiles) == 1 {
			a.Profile = d.cfg.Profiles[0].ID
		}
		if a.Profile != "" && d.cfg.Profile(a.Profile) == nil {
			return nil, errors.New("нет такого профиля")
		}
		id := config.NewID()
		d.cfg.Rules = append(d.cfg.Rules, config.Rule{ID: id, Path: r.Path, Folder: r.Folder, Profile: a.Profile, Enabled: true})
		d.log.Printf("правило добавлено: %s", r.Path)
		return id, d.commit()

	case "updateRule":
		var a struct {
			ID      string
			Profile *string
			Enabled *bool
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		r := d.cfg.Rule(a.ID)
		if r == nil {
			return nil, errors.New("нет такого правила")
		}
		if a.Profile != nil {
			if *a.Profile != "" && d.cfg.Profile(*a.Profile) == nil {
				return nil, errors.New("нет такого профиля")
			}
			r.Profile = *a.Profile
		}
		if a.Enabled != nil {
			r.Enabled = *a.Enabled
			d.log.Printf("правило %s: %s", r.Path, onOff(r.Enabled))
		}
		return nil, d.commit()

	case "removeRule":
		var a struct{ ID string }
		if err := arg(&a); err != nil {
			return nil, err
		}
		for i, r := range d.cfg.Rules {
			if r.ID == a.ID {
				d.cfg.Rules = append(d.cfg.Rules[:i], d.cfg.Rules[i+1:]...)
				d.log.Printf("правило удалено: %s", r.Path)
				return nil, d.commit()
			}
		}
		return nil, errors.New("нет такого правила")

	case "kill", "killRule":
		var a struct {
			PID uint32
			ID  string
		}
		if err := arg(&a); err != nil {
			return nil, err
		}
		if !d.running() {
			return nil, errors.New("фильтр не работает")
		}
		if cmd == "killRule" {
			n, err := d.eng.KillRule(a.ID)
			d.log.Printf("правило %s: завершено процессов %d", a.ID, n)
			return n, err
		}
		n := 0
		var errs []string
		for _, p := range d.eng.Sandboxed() {
			if (cmd == "kill" && p.PID == a.PID) || (cmd == "killRule" && p.Rule == a.ID) {
				if err := proc.Kill(p.PID); err != nil {
					errs = append(errs, fmt.Sprintf("%d: %v", p.PID, err))
				} else {
					n++
					d.log.Printf("завершён процесс %d %s", p.PID, p.Path)
				}
			}
		}
		if len(errs) > 0 {
			return n, errors.New(strings.Join(errs, "; "))
		}
		if n == 0 && cmd == "kill" {
			return 0, errors.New("процесс не в песочнице или уже завершён")
		}
		return n, nil

	case "shutdown":
		d.log.Printf("остановка службы по команде (pid %d)", pid)
		go d.srv.Close()
		return nil, nil
	}
	return nil, fmt.Errorf("неизвестная команда %q", cmd)
}
