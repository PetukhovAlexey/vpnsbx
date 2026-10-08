// Package config — настройки песочницы в %ProgramData%\vpnsbx: config.json
// и копии профилей (profiles\<id>.conf). Каталог закрыт для всех, кроме
// SYSTEM, администраторов и владельца: в профилях приватные ключи.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Rule struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Folder  bool   `json:"folder"`
	Profile string `json:"profile"` // ID профиля
	Enabled bool   `json:"enabled"`
}

type Config struct {
	Enabled  bool      `json:"enabled"` // защита включена (фильтр работает)
	Profiles []Profile `json:"profiles"`
	Rules    []Rule    `json:"rules"`
}

// Dir — каталог данных.
func Dir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "vpnsbx")
}

func path() string { return filepath.Join(Dir(), "config.json") }

// ProfilePath — файл с текстом профиля.
func ProfilePath(id string) string { return filepath.Join(Dir(), "profiles", id+".conf") }

// sddl: полный доступ SYSTEM, администраторам и владельцу, наследуется.
const sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// Ensure создаёт каталоги с закрытыми правами (существующие не трогает).
func Ensure() error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	for _, d := range []string{Dir(), filepath.Join(Dir(), "profiles")} {
		p, _ := windows.UTF16PtrFromString(d)
		if err := windows.CreateDirectory(p, sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return err
		}
	}
	return nil
}

func Load() (*Config, error) {
	b, err := os.ReadFile(path())
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

// Save пишет атомарно: во временный файл, затем переименование.
func (c *Config) Save() error {
	if err := Ensure(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path())
}

// NewID — случайный короткий идентификатор.
func NewID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Config) Profile(id string) *Profile {
	for i := range c.Profiles {
		if c.Profiles[i].ID == id {
			return &c.Profiles[i]
		}
	}
	return nil
}

func (c *Config) Rule(id string) *Rule {
	for i := range c.Rules {
		if c.Rules[i].ID == id {
			return &c.Rules[i]
		}
	}
	return nil
}
