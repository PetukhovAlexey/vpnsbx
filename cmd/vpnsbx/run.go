package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"vpnsbx/internal/engine"
	"vpnsbx/internal/proc"
	"vpnsbx/internal/profile"
)

type multi []string

func (m *multi) String() string     { return fmt.Sprint(*m) }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// runCmd: vpnsbx run --profile <файл> --rule <exe|папка> [--rule ...] [--adapter имя] [--for 30s] [-v]
func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var rules multi
	prof := fs.String("profile", "", "профиль AWG (.conf или vpn://)")
	fs.Var(&rules, "rule", "exe или папка (можно несколько раз)")
	adapter := fs.String("adapter", "", "только этот адаптер (по умолчанию — все)")
	dur := fs.Duration("for", 0, "остановиться через это время (0 — до Ctrl+C)")
	verbose := fs.Bool("v", false, "подробный лог")
	cutFrom := fs.Duration("test-cut-from", 0, "испытание: имитировать обрыв туннеля с этого момента")
	cutTo := fs.Duration("test-cut-to", 0, "испытание: …и до этого момента")
	fs.Parse(args)
	if *prof == "" || len(rules) == 0 {
		return fmt.Errorf("нужны --profile и хотя бы один --rule")
	}
	p, err := profile.Load(*prof)
	if err != nil {
		return err
	}
	if p.Kind != profile.KindAWG {
		return fmt.Errorf("%s: поддерживается только AWG/WireGuard", p.Name)
	}
	if _, err := profile.ParseAWG(p.Text); err != nil {
		return fmt.Errorf("%s: %w", p.Name, err)
	}
	var specs []engine.RuleSpec
	for _, path := range rules {
		r, err := proc.RuleFromPath("cli", path)
		if err != nil {
			return err
		}
		specs = append(specs, engine.RuleSpec{Rule: r, Profile: "cli"})
	}
	lg := log.New(os.Stdout, "", log.Ltime|log.Lmicroseconds)
	e, err := engine.New(engine.Config{Adapter: *adapter, Log: lg, Verbose: *verbose,
		CutFrom: *cutFrom, CutTo: *cutTo})
	if err != nil {
		return err
	}
	e.Apply(engine.Setup{
		Profiles: []engine.ProfileSpec{{ID: "cli", Name: p.Name, Text: p.Text}},
		Rules:    specs,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *dur > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, *dur)
		defer c()
	}
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				s := &e.Stats
				up := false
				for _, t := range e.Tunnels() {
					up = t.Up
				}
				lg.Printf("связь=%v исходящих=%d в туннель=%d из туннеля=%d блок=%d без владельца=%d потеряно=%d",
					up, s.Out.Load(), s.ToTunnel.Load(), s.FromTunnel.Load(),
					s.Blocked.Load(), s.Unknown.Load(), s.Dropped.Load())
			case <-ctx.Done():
				return
			}
		}
	}()
	lg.Printf("профиль %s", p.Name)
	err = e.Run(ctx)
	lg.Printf("фильтр снят")
	return err
}
