// Package ipc — команды демону по именованному каналу: один JSON-запрос
// и один JSON-ответ на соединение. Демон знает PID клиента и может
// отказать процессам из песочницы.
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Pipe — имя канала демона.
const Pipe = `\\.\pipe\vpnsbx`

type request struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

type response struct {
	Err  string          `json:"err,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// ErrNotRunning — демон не запущен (канала нет).
var ErrNotRunning = errors.New("служба vpnsbx не запущена")

// Handler обрабатывает команду клиента с данным PID.
type Handler func(pid uint32, cmd string, args json.RawMessage) (any, error)

type Server struct {
	name   string
	sa     *windows.SecurityAttributes
	next   windows.Handle
	closed atomic.Bool
}

// SYSTEM и администраторы — всё; владелец и интерактивные пользователи —
// чтение/запись (создавать свои экземпляры канала им нельзя).
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;OW)(A;;GRGW;;;IU)"

// Listen создаёт канал. Ошибка, если канал уже есть (демон уже запущен).
func Listen(name string) (*Server, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, err
	}
	s := &Server{name: name, sa: &windows.SecurityAttributes{SecurityDescriptor: sd}}
	s.sa.Length = uint32(unsafe.Sizeof(*s.sa))
	h, err := s.create(true)
	if err != nil {
		if err == windows.ERROR_ACCESS_DENIED || err == windows.ERROR_PIPE_BUSY {
			return nil, errors.New("служба vpnsbx уже запущена")
		}
		return nil, err
	}
	s.next = h
	return s, nil
}

func (s *Server) create(first bool) (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	n, _ := windows.UTF16PtrFromString(s.name)
	return windows.CreateNamedPipe(n, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, s.sa)
}

// Serve принимает клиентов до Close.
func (s *Server) Serve(h Handler) error {
	for {
		cur := s.next
		err := windows.ConnectNamedPipe(cur, nil)
		if s.closed.Load() {
			windows.CloseHandle(cur)
			return nil
		}
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(cur)
			if s.next, err = s.create(false); err != nil {
				return err
			}
			continue
		}
		if s.next, err = s.create(false); err != nil {
			windows.CloseHandle(cur)
			return err
		}
		go serveConn(cur, h)
	}
}

// Close останавливает Serve (подключаясь к себе, чтобы разбудить его).
func (s *Server) Close() {
	if s.closed.Swap(true) {
		return
	}
	if f, err := open(s.name); err == nil {
		f.Close()
	}
}

func serveConn(h windows.Handle, hd Handler) {
	var pid uint32
	windows.GetNamedPipeClientProcessId(h, &pid)
	f := os.NewFile(uintptr(h), "pipe")
	defer func() {
		windows.FlushFileBuffers(h)
		windows.DisconnectNamedPipe(h)
		f.Close()
	}()
	line, err := bufio.NewReader(f).ReadBytes('\n')
	if err != nil {
		return
	}
	var req request
	var resp response
	if err := json.Unmarshal(line, &req); err != nil {
		resp.Err = "неверный запрос"
	} else if data, err := hd(pid, req.Cmd, req.Args); err != nil {
		resp.Err = err.Error()
	} else if resp.Data, err = json.Marshal(data); err != nil {
		resp.Err = err.Error()
	}
	b, _ := json.Marshal(resp)
	f.Write(append(b, '\n'))
}

func open(name string) (*os.File, error) {
	n, _ := windows.UTF16PtrFromString(name)
	for i := 0; ; i++ {
		h, err := windows.CreateFile(n, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			return os.NewFile(uintptr(h), "pipe"), nil
		}
		if err == windows.ERROR_FILE_NOT_FOUND {
			return nil, ErrNotRunning
		}
		if err != windows.ERROR_PIPE_BUSY || i == 20 {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Call отправляет команду демону и раскладывает ответ в out (может быть nil).
func Call(cmd string, args, out any) error {
	f, err := open(Pipe)
	if err != nil {
		return err
	}
	type result struct {
		resp response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var r result
		req := request{Cmd: cmd}
		if args != nil {
			if req.Args, r.err = json.Marshal(args); r.err != nil {
				ch <- r
				return
			}
		}
		b, _ := json.Marshal(req)
		if _, r.err = f.Write(append(b, '\n')); r.err == nil {
			var line []byte
			if line, r.err = bufio.NewReader(f).ReadBytes('\n'); r.err == nil {
				r.err = json.Unmarshal(line, &r.resp)
			}
		}
		ch <- r
	}()
	var r result
	select {
	case r = <-ch:
		f.Close()
	case <-time.After(10 * time.Second):
		f.Close()
		return errors.New("служба vpnsbx не отвечает")
	}
	if r.err != nil {
		return r.err
	}
	if r.resp.Err != "" {
		return errors.New(r.resp.Err)
	}
	if out != nil && len(r.resp.Data) > 0 {
		return json.Unmarshal(r.resp.Data, out)
	}
	return nil
}
