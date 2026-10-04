package client

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

type gracefulCloseTestConnector struct {
	conn net.Conn
}

func (*gracefulCloseTestConnector) Connect() (*msg.Conn, error) { return nil, net.ErrClosed }
func (c *gracefulCloseTestConnector) Close() error              { return c.conn.Close() }

func newGracefulCloseTestService() *Service {
	return newGracefulCloseTestServiceWithParent(context.Background())
}

func newGracefulCloseTestServiceWithParent(parent context.Context) *Service {
	common := &v1.ClientCommonConfig{}
	serverConn, clientConn := net.Pipe()
	ctl, err := NewControl(parent, &SessionContext{
		Common:    common,
		RunID:     "graceful-close-race",
		Conn:      msg.NewConn(clientConn, msg.NewV1ReadWriter(clientConn)),
		Connector: &gracefulCloseTestConnector{conn: serverConn},
		Auth:      &auth.ClientAuth{},
	})
	if err != nil {
		panic(err)
	}
	return &Service{ctl: ctl, cancel: context.CancelCauseFunc(func(error) {})}
}

func TestGracefulCloseAndStopSynchronizeDuration(t *testing.T) {
	for i := range 10000 {
		svr := newGracefulCloseTestService()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			svr.GracefulClose(time.Duration(i))
		}()
		go func() {
			defer wg.Done()
			<-start
			svr.stop()
		}()
		close(start)
		wg.Wait()
	}
}

func TestGracefulCloseDoesNotBlockDuringStop(t *testing.T) {
	const gracefulDuration = 200 * time.Millisecond

	svr := newGracefulCloseTestService()
	svr.GracefulClose(gracefulDuration)
	stopDone := make(chan struct{})
	go func() {
		svr.stop()
		close(stopDone)
	}()
	defer func() {
		select {
		case <-stopDone:
		case <-time.After(time.Second):
			t.Error("stop did not finish")
		}
	}()

	deadline := time.Now().Add(time.Second)
	for svr.ctlMu.TryLock() {
		svr.ctlMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("stop did not acquire ctlMu")
		}
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	svr.GracefulClose(0)
	if elapsed := time.Since(start); elapsed >= gracefulDuration/2 {
		t.Fatalf("GracefulClose blocked for %v while stop was waiting", elapsed)
	}
}

func TestDelayedOldControlCloseDoesNotCancelNewControlOrParent(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := newGracefulCloseTestServiceWithParent(parent).ctl
	newControl := newGracefulCloseTestServiceWithParent(parent).ctl
	defer newControl.closeSession()
	done := make(chan struct{})
	go func() { _ = old.GracefulClose(100 * time.Millisecond); close(done) }()
	// The original graceful interval does not revoke ordinary Control ownership early.
	select {
	case <-old.ctx.Done():
		t.Fatal("control cancelled before original grace interval")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("graceful close did not return")
	}
	if old.ctx.Err() == nil || newControl.ctx.Err() != nil || parent.Err() != nil {
		t.Fatal("old close crossed real Control instances")
	}
	old.closeSession() // Real cancellation and connection close are idempotent.
}
