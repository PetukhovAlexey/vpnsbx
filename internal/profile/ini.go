package profile

import (
	"bufio"
	"strings"
)

type KV struct {
	Key, Value string
}

type Section struct {
	Name string // Interface, Peer
	Keys []KV
}

// ParseINI разбирает wg-quick-подобный конфиг. Порядок секций и ключей сохраняется.
func ParseINI(text string) []Section {
	var out []Section
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			out = append(out, Section{Name: strings.TrimSpace(line[1 : len(line)-1])})
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || len(out) == 0 {
			continue
		}
		s := &out[len(out)-1]
		s.Keys = append(s.Keys, KV{strings.TrimSpace(k), strings.TrimSpace(v)})
	}
	return out
}
