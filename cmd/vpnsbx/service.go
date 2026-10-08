package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"vpnsbx/internal/config"
)

// Имя службы Windows; MSI регистрирует её с тем же именем.
const serviceName = "vpnsbx"

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

func runService() {
	if err := svc.Run(serviceName, &service{}); err != nil {
		svcLog(err)
		os.Exit(1)
	}
}

type service struct{}

func (*service) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	var once sync.Once
	halt := func() { once.Do(func() { close(stop) }) }
	done := make(chan error, 1)
	go func() { done <- runDaemon(stop, nil) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				svcLog(err)
				return true, 1 // SCM перезапустит службу по настройкам восстановления
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending, WaitHint: 15000}
				halt()
			}
		}
	}
}

// svcLog дописывает ошибку запуска в daemon.log: консоли у службы нет.
func svcLog(err error) {
	f, e := os.OpenFile(filepath.Join(config.Dir(), "daemon.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if e != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s служба: %v\n", time.Now().Format("2006/01/02 15:04:05"), err)
}
