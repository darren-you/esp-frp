package xtcpbinding_test

import (
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// A transparent transport relay only permits the fixture to close the old
// provider's actual TLS/yamux connection. FRPS and both Service instances live.
type controlRelay struct {
	listener    net.Listener
	accepted    atomic.Int32
	mu          sync.Mutex
	connections []net.Conn
	first       [2]net.Conn
	workers     sync.WaitGroup
	done        chan struct{}
}

func newControlRelay(t *testing.T, serverPort int) *controlRelay {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &controlRelay{listener: l, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		for {
			front, err := l.Accept()
			if err != nil {
				return
			}
			back, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)))
			if err != nil {
				front.Close()
				t.Error(err)
				continue
			}
			r.mu.Lock()
			r.connections = append(r.connections, front, back)
			if r.accepted.Add(1) == 1 {
				r.first = [2]net.Conn{front, back}
			}
			r.mu.Unlock()
			r.workers.Add(2)
			for _, pair := range [][2]net.Conn{{front, back}, {back, front}} {
				go func() {
					defer r.workers.Done()
					defer pair[0].Close()
					defer pair[1].Close()
					_, _ = io.Copy(pair[0], pair[1])
				}()
			}
		}
	}()
	t.Cleanup(func() {
		l.Close()
		<-r.done
		r.mu.Lock()
		for _, c := range r.connections {
			c.Close()
		}
		r.mu.Unlock()
		r.workers.Wait()
	})
	return r
}

func (r *controlRelay) dropFirst(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.first {
		if c == nil {
			t.Fatal("old provider transport not accepted")
		}
		if e := c.Close(); e != nil && !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
	}
}
