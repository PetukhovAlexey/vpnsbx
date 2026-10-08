package main

import (
	"encoding/json"
	"fmt"
	"os"

	"vpnsbx/internal/ipc"
)

// ctlCmd: vpnsbx ctl <команда> [json-аргументы] — печатает ответ службы.
func ctlCmd(args []string) error {
	if len(args) == 0 || len(args) > 2 {
		usage()
	}
	var a any
	if len(args) == 2 {
		a = json.RawMessage(args[1])
	}
	var out json.RawMessage
	if err := ipc.Call(args[0], a, &out); err != nil {
		return err
	}
	if len(out) > 0 && string(out) != "null" {
		var v any
		json.Unmarshal(out, &v)
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(os.Stdout, string(b))
	}
	return nil
}
