// Package profile разбирает VPN-профили: AmneziaWG/WireGuard (.conf),
// OpenVPN (.ovpn) и экспорт Amnezia (vpn://).
package profile

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Kind string

const (
	KindAWG     Kind = "awg"
	KindOpenVPN Kind = "openvpn"
)

// Profile — профиль в исходном текстовом виде (секреты внутри Text).
type Profile struct {
	Name   string // безопасное имя: латиница, цифры, -_ ; до 32 символов
	Kind   Kind
	Text   string // текст .conf / .ovpn
	Source string // conf | ovpn | amnezia:<container>
}

var reUnsafe = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func safeName(path string) string {
	n := reUnsafe.ReplaceAllString(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), "")
	if n == "" {
		n = "vpn"
	}
	if len(n) > 32 {
		n = n[:32]
	}
	return n
}

var (
	reInterface = regexp.MustCompile(`(?m)^\s*\[Interface\]`)
	reOpenVPN   = regexp.MustCompile(`(?m)^\s*(client|remote|dev)\b`)
)

// Load читает профиль из файла.
func Load(path string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(string(raw), safeName(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse разбирает текст профиля (.conf, .ovpn или vpn://).
func Parse(text, name string) (*Profile, error) {
	text = strings.TrimPrefix(text, "\xEF\xBB\xBF")
	if name == "" {
		name = "vpn"
	}
	if strings.HasPrefix(strings.TrimSpace(text), "vpn://") {
		p, err := fromAmneziaExport(text)
		if err != nil {
			return nil, err
		}
		p.Name = name
		return p, nil
	}
	if reInterface.MatchString(text) {
		return &Profile{Name: name, Kind: KindAWG, Text: text, Source: "conf"}, nil
	}
	if reOpenVPN.MatchString(text) {
		return &Profile{Name: name, Kind: KindOpenVPN, Text: text, Source: "ovpn"}, nil
	}
	return nil, errors.New("не удалось определить формат профиля")
}

// DecodeAmneziaExport: vpn://<base64url(qCompress(json))>,
// qCompress = 4 байта длины (big-endian) + zlib-поток.
func DecodeAmneziaExport(text string) ([]byte, error) {
	s := strings.TrimPrefix(strings.TrimSpace(text), "vpn://")
	s = strings.TrimRight(s, "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("vpn://: base64: %w", err)
	}
	if len(b) < 6 {
		return nil, errors.New("vpn://: слишком короткие данные")
	}
	z, err := zlib.NewReader(bytes.NewReader(b[4:]))
	if err != nil {
		return nil, fmt.Errorf("vpn://: zlib: %w", err)
	}
	defer z.Close()
	return io.ReadAll(z)
}

func fromAmneziaExport(text string) (*Profile, error) {
	data, err := DecodeAmneziaExport(text)
	if err != nil {
		return nil, err
	}
	var j struct {
		DefaultContainer string                       `json:"defaultContainer"`
		Containers       []map[string]json.RawMessage `json:"containers"`
		DNS1             string                       `json:"dns1"`
		DNS2             string                       `json:"dns2"`
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("vpn://: json: %w", err)
	}
	cname := func(c map[string]json.RawMessage) string {
		var s string
		json.Unmarshal(c["container"], &s)
		return s
	}
	// Сначала контейнер по умолчанию, затем остальные по порядку
	order := append([]map[string]json.RawMessage(nil), j.Containers...)
	sort.SliceStable(order, func(a, b int) bool {
		return cname(order[a]) == j.DefaultContainer && cname(order[b]) != j.DefaultContainer
	})
	var have []string
	for _, c := range order {
		cn := cname(c)
		have = append(have, cn)
		protos := make([]string, 0, len(c))
		for k := range c {
			if k != "container" {
				protos = append(protos, k)
			}
		}
		sort.Strings(protos)
		for _, proto := range protos {
			var kind Kind
			switch proto {
			case "awg", "wireguard":
				kind = KindAWG
			case "openvpn":
				kind = KindOpenVPN
			default:
				continue
			}
			var pc struct {
				LastConfig string `json:"last_config"`
			}
			if json.Unmarshal(c[proto], &pc) != nil || pc.LastConfig == "" {
				continue
			}
			var lc struct {
				Config string `json:"config"`
			}
			if json.Unmarshal([]byte(pc.LastConfig), &lc) != nil || lc.Config == "" {
				continue
			}
			cfg := strings.NewReplacer("$PRIMARY_DNS", j.DNS1, "$SECONDARY_DNS", j.DNS2).Replace(lc.Config)
			return &Profile{Kind: kind, Text: cfg, Source: "amnezia:" + cn}, nil
		}
	}
	return nil, fmt.Errorf("в экспорте Amnezia нет поддерживаемого протокола (есть: %s)", strings.Join(have, ", "))
}
