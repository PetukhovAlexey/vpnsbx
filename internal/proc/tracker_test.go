package proc

import (
	"os"
	"strings"
	"testing"
)

func TestUnresolved(t *testing.T) {
	for p, want := range map[string]bool{
		"":                              true,
		`\Device\HarddiskVolume3\a.exe`: true,
		`\SystemRoot\System32\smss.exe`: true,
		`C:\Windows\notepad.exe`:        false,
		`\\srv\share\a.exe`:             false,
		`\Device\Mup\srv\share\a.exe`:   true,
	} {
		if got := unresolved(p); got != want {
			t.Errorf("unresolved(%q) = %v, want %v", p, got, want)
		}
	}
	if got := ntToDos(`\Device\Mup\srv\share\a.exe`); got != `\\srv\share\a.exe` {
		t.Errorf("Mup: %q", got)
	}
}

// Путь, который не перевести в C:\…, — процесс под сомнением, пока есть
// правила; когда путь выяснится, сомнение снимается и правило применяется.
func TestUnresolvedPathUncertain(t *testing.T) {
	exe, _ := os.Executable()
	tr := &Tracker{rules: NewRules(nil), procs: map[uint32]*procInfo{}, logf: t.Logf}
	tr.procs[100] = &procInfo{parent: 1, created: 1, path: `\Device\NoSuchVolume\x\app.exe`}
	tr.link(100, 0)
	if tr.Uncertain(100) {
		t.Fatal("без правил сомнений быть не должно")
	}
	tr.SetRules(NewRules([]Rule{{ID: "r", Path: exe}}))
	g := tr.Gen()
	if !tr.Uncertain(100) {
		t.Fatal("неизвестный путь при правилах — под сомнением")
	}
	tr.procs[100].path = exe
	tr.relinkAll()
	if tr.Uncertain(100) {
		t.Fatal("путь известен — сомнений нет")
	}
	if r := tr.procs[100].rule; r != "r" {
		t.Fatalf("правило %q", r)
	}
	if tr.Gen() == g {
		t.Fatal("смена правила процесса должна менять Gen")
	}
}

// Предок с NT-путём в цепочке: правило по нему не сравнить — сомнение.
func TestNTChainUncertain(t *testing.T) {
	tr := &Tracker{rules: NewRules([]Rule{{ID: "r", Path: `C:\nowhere\x.exe`}}), procs: map[uint32]*procInfo{}, logf: t.Logf}
	tr.procs[1] = &procInfo{created: 1, path: `\Device\NoSuchVolume\launcher.exe`}
	tr.procs[2] = &procInfo{parent: 1, created: 2, path: `C:\Windows\notepad.exe`}
	tr.link(2, 0)
	if !strings.HasPrefix(tr.procs[2].chain[1], `\Device\`) {
		t.Fatalf("цепочка %q", tr.procs[2].chain)
	}
	if !tr.Uncertain(2) {
		t.Fatal("предок с NT-путём — под сомнением")
	}
}
