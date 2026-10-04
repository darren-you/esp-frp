package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

func ownerTestProxy(ctx context.Context) *XTCPProxy {
	cfg := &v1.XTCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "same-name", Type: "xtcp"}}
	common := &v1.ClientCommonConfig{XTCPControlID: make([]byte, 32)}
	common.Transport.WireProtocol = "v2"
	return NewProxy(ctx, cfg, common, nil, nil, nil, "").(*XTCPProxy)
}

type sidReadObserver struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *sidReadObserver) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

func TestXTCPStopInterruptsPendingAndLateWorkSID(t *testing.T) {
	for _, late := range []bool{false, true} {
		p := ownerTestProxy(context.Background())
		if late {
			p.Close()
		}
		work, peer := net.Pipe()
		defer peer.Close()
		observed := &sidReadObserver{Conn: work, started: make(chan struct{})}
		done := make(chan struct{})
		go func() { p.InWorkConn(observed, &msg.StartWorkConn{}); close(done) }()
		if !late {
			select {
			case <-observed.started:
			case <-time.After(time.Second):
				t.Fatal("actual pending SID Read was not reached")
			}
		}
		p.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("pending or late work retained after proxy Close", late)
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if n, e := peer.Read(b[:]); n != 0 || e == nil {
			t.Fatal(n, e)
		}
	}
}

func TestOldProxyCloseCannotCancelSameNameReplacement(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	old := ownerTestProxy(parent)
	newProxy := ownerTestProxy(parent)
	old.Close()
	old.Close()
	if old.ctx.Err() == nil || newProxy.ctx.Err() != nil || parent.Err() != nil {
		t.Fatal("owner identity crossed instances")
	}
	cancel()
	if newProxy.ctx.Err() == nil {
		t.Fatal("Control cancel did not reach new proxy")
	}
	newProxy.Close()
}

func TestXTCPBackendDialUsesCancelledOwner(t *testing.T) {
	p := ownerTestProxy(context.Background())
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	p.baseCfg.LocalIP = "127.0.0.1"
	p.baseCfg.LocalPort = listener.Addr().(*net.TCPAddr).Port
	work, peer := net.Pipe()
	defer peer.Close()
	owner, cancel := context.WithCancel(p.ctx)
	cancel()
	done := make(chan struct{})
	go func() { p.handleTCPWorkConnection(owner, work, &msg.StartWorkConn{}, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backend Dial retained cancelled XTCP owner")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, e := peer.Read(b[:]); n != 0 || e == nil {
		t.Fatal(n, e)
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	if c, e := listener.Accept(); e == nil {
		c.Close()
		t.Fatal("cancelled owner admitted a backend")
	}
	p.Close()
}
