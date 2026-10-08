package proc

import (
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestETWLayout(t *testing.T) {
	var p traceProps
	if got := unsafe.Offsetof(p.name); got != 120 {
		t.Errorf("EVENT_TRACE_PROPERTIES = %d, want 120", got)
	}
	if got := unsafe.Sizeof(traceLogfile{}); got != 448 {
		t.Errorf("EVENT_TRACE_LOGFILEW = %d, want 448", got)
	}
	if got := unsafe.Sizeof(eventRecord{}); got != 112 {
		t.Errorf("EVENT_RECORD = %d, want 112", got)
	}
}

// Короткоживущий cmd и его потомок: ETW сообщает обоих с родителем и путём.
func TestETWStarted(t *testing.T) {
	type ev struct {
		pid, parent uint32
		path        string
	}
	var mu sync.Mutex
	var got []ev
	etwSession = "vpnsbx-proc-test"
	w, err := watchProcesses(func(pid, parent uint32, _ int64, path string) {
		mu.Lock()
		got = append(got, ev{pid, parent, path})
		mu.Unlock()
	})
	if err != nil {
		t.Skip("ETW:", err)
	}
	defer w.Close()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	c := exec.Command("cmd.exe", "/c", "start", "/b", "", "ping.exe", "-n", "1", "127.0.0.1")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	cmdPID := uint32(c.Process.Pid)
	for time.Since(start) < 3*time.Second {
		mu.Lock()
		for _, e := range got {
			if e.parent == cmdPID && strings.HasSuffix(strings.ToLower(e.path), `\ping.exe`) {
				mu.Unlock()
				t.Logf("ping %d ← cmd %d, путь %s, через %v", e.pid, e.parent, e.path, time.Since(start))
				return
			}
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("нет события о ping от cmd %d; событий %d", cmdPID, len(got))
}
