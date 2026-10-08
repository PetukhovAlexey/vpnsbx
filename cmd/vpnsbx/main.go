package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"vpnsbx/internal/profile"
)

func usage() {
	fmt.Fprintln(os.Stderr, `vpnsbx — песочница VPN для процессов

  vpnsbx profile inspect <файл>...   структура профиля (секреты скрыты)
  vpnsbx tunnel test [-v] <файл>     поднять туннель в userspace и проверить внешний IP
  vpnsbx run --profile <файл> --rule <exe|папка>... [--adapter имя] [--for 30s] [-v]
                                     перенаправить трафик программ из правила в туннель
  vpnsbx daemon                      служба: фильтр по %ProgramData%\vpnsbx\config.json
  vpnsbx ctl <команда> [json]        команда службе (status, procs, log, enable {"on":true}, …)`)
	os.Exit(2)
}

func main() {
	if len(os.Args) >= 2 {
		cmds := map[string]func([]string) error{"run": runCmd, "daemon": daemonCmd, "ctl": ctlCmd}
		if f, ok := cmds[os.Args[1]]; ok {
			if err := f(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "ОШИБКА:", err)
				os.Exit(1)
			}
			return
		}
	}
	if len(os.Args) < 3 {
		usage()
	}
	switch os.Args[1] + " " + os.Args[2] {
	case "profile inspect":
		for _, f := range os.Args[3:] {
			inspect(f)
		}
	case "tunnel test":
		args := os.Args[3:]
		verbose := len(args) > 0 && args[0] == "-v"
		if verbose {
			args = args[1:]
		}
		if len(args) != 1 {
			usage()
		}
		if err := tunnelTest(args[0], verbose); err != nil {
			fmt.Fprintln(os.Stderr, "ОШИБКА:", err)
			os.Exit(1)
		}
	default:
		usage()
	}
}

var (
	reUint  = regexp.MustCompile(`^\d+$`)
	reRange = regexp.MustCompile(`^\d+-\d+$`)
	reHex   = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reB64   = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	reTag   = regexp.MustCompile(`<(\w+)[^>]*>`)
)

// shape описывает формат значения, не раскрывая его.
func shape(v string) string {
	switch {
	case v == "":
		return "пусто"
	case reUint.MatchString(v):
		return "число"
	case reRange.MatchString(v):
		return "диапазон"
	case strings.EqualFold(v, "true") || strings.EqualFold(v, "false"):
		return "bool"
	case reHex.MatchString(v):
		return fmt.Sprintf("hex(%d)", len(v))
	case reB64.MatchString(v):
		return fmt.Sprintf("base64(%d)", len(v))
	case strings.HasPrefix(v, "<"):
		var tags []string
		for _, m := range reTag.FindAllStringSubmatch(v, -1) {
			tags = append(tags, m[1])
		}
		return "цепочка <" + strings.Join(tags, "><") + ">"
	default:
		return fmt.Sprintf("строка(%d), элементов через запятую: %d", len(v), strings.Count(v, ",")+1)
	}
}

func inspect(path string) {
	p, err := profile.Load(path)
	if err != nil {
		fmt.Println("ОШИБКА:", err)
		return
	}
	fmt.Printf("== %s: name=%s kind=%s source=%s\n", path, p.Name, p.Kind, p.Source)
	if p.Kind != profile.KindAWG {
		return
	}
	for _, s := range profile.ParseINI(p.Text) {
		fmt.Printf("  [%s]\n", s.Name)
		for _, kv := range s.Keys {
			sh := shape(kv.Value)
			if kv.Key == "RandomTrailers" || kv.Key == "DisableCookies" {
				sh = kv.Value // флаги, не секрет
			}
			fmt.Printf("    %-24s %s\n", kv.Key, sh)
		}
	}
}
