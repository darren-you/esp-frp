// SPDX-License-Identifier: Apache-2.0
package xtcpbinding_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	input  io.WriteCloser
	lines  chan string
	stderr bytes.Buffer
	done   chan struct{}
	err    error
	once   sync.Once
}

func startC(t *testing.T, binary, role string, p int, ca string, local int, stun []string, secret, user, target, mode string, expected int) *cClient {
	t.Helper()
	_, s1, e := net.SplitHostPort(stun[0])
	if e != nil {
		t.Fatal(e)
	}
	_, s2, e := net.SplitHostPort(stun[1])
	if e != nil {
		t.Fatal(e)
	}
	pctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	c := &cClient{t: t, cmd: exec.CommandContext(pctx, binary, role, strconv.Itoa(p), ca, strconv.Itoa(local), s1, s2, secret, user, target, mode, strconv.Itoa(expected)), lines: make(chan string, 64), done: make(chan struct{})}
	c.cmd.Stderr = &c.stderr
	c.input, e = c.cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdout, e := c.cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = c.cmd.Start(); e != nil {
		t.Fatal(e)
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			c.lines <- scanner.Text()
		}
		close(c.lines)
	}()
	go func() { <-readDone; c.err = c.cmd.Wait(); close(c.done) }()
	t.Cleanup(func() {
		c.once.Do(func() {
			_, _ = io.WriteString(c.input, "q")
			_ = c.input.Close()
			select {
			case <-c.done:
				if e := c.err; e != nil {
					t.Errorf("C client process: %v\n%s", e, c.stderr.String())
				}
			case <-time.After(7 * time.Second):
				cancel()
				<-c.done
				t.Error("C client failed synchronous cleanup")
			}
			if c.stderr.Len() > 0 {
				t.Log("C diagnostic:", c.stderr.String())
			}
			cancel()
		})
	})
	c.expect(map[bool]string{true: "READY ", false: "FAILED "}[expected == 0])
	return c
}
func (c *cClient) expect(prefix string) string {
	c.t.Helper()
	select {
	case line, ok := <-c.lines:
		if !ok {
			<-c.done
			e := c.err
			c.t.Fatalf("C client exited before %s: %v\n%s", prefix, e, c.stderr.String())
		}
		if !strings.HasPrefix(line, prefix) {
			c.t.Fatalf("C response %q, want %q", line, prefix)
		}
		return line
	case <-time.After(20 * time.Second):
		c.t.Fatalf("C response timeout for %s", prefix)
	}
	return ""
}
func (c *cClient) command(command, prefix string) string {
	c.t.Helper()
	if _, e := io.WriteString(c.input, command); e != nil {
		c.t.Fatal(e)
	}
	return c.expect(prefix)
}
func echoBackend(t *testing.T) (int, *atomic.Uint32) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := new(atomic.Uint32)
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done; wg.Wait() })
	return l.Addr().(*net.TCPAddr).Port, count
}
func strictServer(t *testing.T) (int, string, []string) {
	t.Helper()
	ca, cert, key := certificates(t)
	p := port(t)
	stun := stunEndpoints(t)
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: p, ProxyBindAddr: "127.0.0.1"}
	cfg.Auth.Token = "public-full-flow-token"
	cfg.Transport.TLS.Force = true
	cfg.Transport.TLS.CertFile = cert
	cfg.Transport.TLS.KeyFile = key
	if e := cfg.Complete(); e != nil {
		t.Fatal(e)
	}
	svc, e := server.NewService(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); _ = svc.Close(); <-done })
	return p, ca, stun
}
func dualFlows(t *testing.T, p int, diagnostic *cClient) []net.Conn {
	t.Helper()
	flows := make([]net.Conn, 2)
	for i := range flows {
		var c net.Conn
		var e error
		deadline := time.Now().Add(5 * time.Second)
		for {
			c, e = net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", p), time.Second)
			if e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(e)
			}
			time.Sleep(10 * time.Millisecond)
		}
		flows[i] = c
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, c := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte(i + 1)}, 300001)
			if _, e := c.Write(payload); e != nil {
				results <- e
				return
			}
			out := make([]byte, len(payload))
			_, e := io.ReadFull(c, out)
			if e == nil && !bytes.Equal(out, payload) {
				e = io.ErrUnexpectedEOF
			}
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Log("C failure state:", diagnostic.command("s", "STATE "))
			t.Fatal(e)
		}
	}
	return flows
}
func TestCClientFullCandidate(t *testing.T) {
	binary := os.Getenv("EFRP_XTCP_CLIENT_PEER")
	if binary == "" {
		t.Skip("formal CMake supplies the required actual C client peer")
	}
	for _, role := range []string{"provider", "visitor"} {
		t.Run(role, func(t *testing.T) {
			p, ca, stun := strictServer(t)
			backend, count := echoBackend(t)
			local := port(t)
			providerCfg := &v1.XTCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "private", Type: "xtcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: backend}}, Secretkey: "public-candidate-secret"}
			var c *cClient
			var stopGo func()
			if role == "provider" {
				c = startC(t, binary, role, p, ca, backend, stun, "public-candidate-secret", "provider", "provider.private", "normal", 0)
				visitorCfg := &v1.XTCPVisitorConfig{VisitorBaseConfig: v1.VisitorBaseConfig{Name: "local", Type: "xtcp", ServerName: "private", ServerUser: "provider", SecretKey: "public-candidate-secret", BindAddr: "127.0.0.1", BindPort: local}, Protocol: "quic"}
				_, stopGo = startClient(t, p, ca, stun[0], "provider", nil, []v1.VisitorConfigurer{visitorCfg})
			} else {
				svc, stop := startClient(t, p, ca, stun[0], "provider", []v1.ProxyConfigurer{providerCfg}, nil)
				stopGo = stop
				deadline := time.Now().Add(5 * time.Second)
				for {
					status, ok := svc.StatusExporter().GetProxyStatus("private")
					if ok && status.Phase == "running" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("maintained provider registration failed", status)
					}
					time.Sleep(time.Millisecond)
				}
				c = startC(t, binary, role, p, ca, local, stun, "public-candidate-secret", "provider", "provider.private", "normal", 0)
			}
			flows := dualFlows(t, local, c)
			if count.Load() != 2 {
				t.Fatal("backend admission count", count.Load())
			}
			line := c.command("s", "STATE ")
			var phase, reason, last int
			var established, rejected, completed, failed uint64
			var active, waiting, cleaning uint
			if _, e := fmt.Sscanf(line, "STATE %d %d %d %d %d %d %d %d %d %d", &phase, &reason, &established, &rejected, &active, &waiting, &cleaning, &completed, &failed, &last); e != nil || phase != 6 || established != 1 || active != 2 || waiting > 1 || cleaning != 0 || reason != 0 {
				t.Fatal("C direct peer/proof status", line, e)
			}
			c.command("z", "STOPPED")
			for _, flow := range flows {
				var b [1]byte
				if n, e := flow.Read(b[:]); n != 0 || e == nil {
					t.Fatal("C stop retained business", n, e)
				}
			}
			c.command("r", "RESTARTED ")
			flows = dualFlows(t, local, c)
			if count.Load() != 4 {
				t.Fatal("same-worker restart backend", count.Load())
			}
			c.command("u", "UNTRUSTED")
			for _, flow := range flows {
				var b [1]byte
				if n, e := flow.Read(b[:]); n != 0 || e == nil {
					t.Fatal("trusted clock revocation retained business", n, e)
				}
			}
			stopGo()
			t.Log("actual public C role: strict FRPS control/owner, two STUN sockets, HMAC SID, mutual peer TLS/exporter proof, dual 300001B, stop/restart and clock revocation passed")
		})
	}
	for _, mode := range []struct {
		name string
		code int
	}{{"wrong-token", -14}, {"wrong-host", -15}, {"untrusted", -18}} {
		t.Run("strict-control-"+mode.name, func(t *testing.T) {
			p, ca, stun := strictServer(t)
			local := port(t)
			c := startC(t, binary, "visitor", p, ca, local, stun, "public-candidate-secret", "provider", "provider.private", mode.name, mode.code)
			c.command("z", "STOPPED")
		})
	}
	for _, bad := range []string{"secret", "user", "target"} {
		t.Run("visitor-reject-"+bad, func(t *testing.T) {
			p, ca, stun := strictServer(t)
			backend, count := echoBackend(t)
			local := port(t)
			cfg := &v1.XTCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "private", Type: "xtcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: backend}}, Secretkey: "public-candidate-secret"}
			svc, stopGo := startClient(t, p, ca, stun[0], "provider", []v1.ProxyConfigurer{cfg}, nil)
			deadline := time.Now().Add(5 * time.Second)
			for {
				status, ok := svc.StatusExporter().GetProxyStatus("private")
				if ok && status.Phase == "running" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("provider failed", status)
				}
				time.Sleep(time.Millisecond)
			}
			secret, user, target := "public-candidate-secret", "provider", "provider.private"
			switch bad {
			case "secret":
				secret = "wrong-public-secret"
			case "user":
				user = "wrong-user"
			case "target":
				target = "provider.absent"
			}
			c := startC(t, binary, "visitor", p, ca, local, stun, secret, user, target, "normal", 0)
			flow, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", local), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer flow.Close()
			_ = flow.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = flow.Write([]byte("forbidden-backend"))
			var b [1]byte
			if n, e := flow.Read(b[:]); n != 0 || e == nil {
				t.Fatal("bad admission reached backend", n, e)
			}
			if count.Load() != 0 {
				t.Fatal("bad secret/user/target opened backend", count.Load())
			}
			line := c.command("s", "STATE ")
			var phase, reason, last int
			var established, rejected, completed, failed uint64
			var active, waiting, cleaning uint
			if _, e := fmt.Sscanf(line, "STATE %d %d %d %d %d %d %d %d %d %d", &phase, &reason, &established, &rejected, &active, &waiting, &cleaning, &completed, &failed, &last); e != nil || established != 0 || active != 0 || reason != -23 {
				t.Fatal("C rejection state", line, e)
			}
			c.command("z", "STOPPED")
			stopGo()
			t.Log("actual C visitor negative produced zero backend and synchronous cleanup")
		})
	}

}
