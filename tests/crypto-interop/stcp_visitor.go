// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

type stcpProvider struct {
	service *client.Service
	cancel  context.CancelFunc
	done    chan error
}

func startSTCPProvider(port, localPort int, caPath string) *stcpProvider {
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: port, User: "provider", ClientID: "official-stcp-provider"}
	common.Auth.Token = "public-session-token"
	common.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	common.Transport.WireProtocol = "v2"
	common.Transport.TLS.ServerName = "frp.fixture.invalid"
	common.Transport.TLS.TrustedCaFile = caPath
	config := &v1.STCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "private", Type: "stcp",
		ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: localPort}}, Secretkey: "public-visitor-secret"}
	configSource := source.NewConfigSource()
	must(configSource.ReplaceAll([]v1.ProxyConfigurer{config}, nil))
	service, err := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(configSource)})
	must(err)
	ctx, cancel := context.WithCancel(context.Background())
	provider := &stcpProvider{service: service, cancel: cancel, done: make(chan error, 1)}
	go func() { provider.done <- service.Run(ctx) }()
	provider.waitReady(true)
	return provider
}
func (provider *stcpProvider) waitReady(ready bool) {
	deadline := time.Now().Add(12 * time.Second)
	for {
		// Status is keyed by configuration name; the wrapper adds the user
		// prefix only to the registration's wire name.
		status, exists := provider.service.StatusExporter().GetProxyStatus("private")
		running := exists && status.Phase == proxy.ProxyPhaseRunning
		if running == ready {
			return
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("official STCP provider ready=%t status=%+v", ready, status))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (provider *stcpProvider) close() {
	provider.cancel()
	select {
	case err := <-provider.done:
		must(err)
	case <-time.After(5 * time.Second):
		panic("official STCP provider did not stop")
	}
}
func startSTCPVisitorHarness(path, caPath string, port, bindPort int, mode, user, target, secret string, expected int) *proxyHarness {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	h := &proxyHarness{cancel: cancel}
	h.cmd = exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, strconv.Itoa(bindPort), mode, user, target, secret, strconv.Itoa(expected))
	var err error
	h.input, err = h.cmd.StdinPipe()
	must(err)
	output, err := h.cmd.StdoutPipe()
	must(err)
	h.output = bufio.NewScanner(output)
	h.cmd.Stderr = &h.stderr
	must(h.cmd.Start())
	return h
}
func visitorReady(h *proxyHarness, prefix string) (string, string) {
	line := h.line()
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != prefix || fields[2] == "" {
		panic("visitor readiness: " + line + "\n" + h.stderr.String())
	}
	return fields[1], fields[2]
}
func visitorCommand(h *proxyHarness, command byte, expected string) {
	_, err := h.input.Write([]byte{command})
	must(err)
	if line := h.line(); line != expected {
		panic("visitor command: expected " + expected + " got " + line)
	}
}
func visitorFreePort() int {
	listener := localListener()
	port := listener.Addr().(*net.TCPAddr).Port
	must(listener.Close())
	return port
}
func visitorAwait(h *proxyHarness, completed, failed uint64) workState {
	deadline := time.Now().Add(5 * time.Second)
	for {
		state := h.state()
		if state.failed > failed || state.completed > completed {
			panic(fmt.Sprintf("visitor counters: %+v want completed=%d failed=%d", state, completed, failed))
		}
		if state.active == 0 && state.waiting == 0 && state.completed == completed && state.failed == failed {
			return state
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("visitor did not drain: %+v want completed=%d failed=%d", state, completed, failed))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func visitorDual(h *proxyHarness, address string, local net.Listener, id uint32, completed, failed uint64) {
	must(local.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)))
	backend := make(chan error, 2)
	go func() {
		for index := range 2 {
			conn, err := local.Accept()
			if err != nil {
				for range 2 - index {
					backend <- err
				}
				return
			}
			go func() { backend <- localWork(conn) }()
		}
	}()
	frontend := make(chan error, 2)
	for index := uint32(0); index < 2; index++ {
		go func() { frontend <- remoteWork(address, id+index) }()
	}
	for range 2 {
		must(<-frontend)
		must(<-backend)
	}
	visitorAwait(h, completed, failed)
}

type visitorHeldPair struct{ frontend, backend net.Conn }

func visitorHeld(address string, local net.Listener, value byte) visitorHeldPair {
	frontend := proxyDial(address)
	must(frontend.SetDeadline(time.Now().Add(5 * time.Second)))
	_, err := frontend.Write([]byte{value})
	must(err)
	must(local.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)))
	backend, err := local.Accept()
	must(err)
	must(backend.SetDeadline(time.Now().Add(5 * time.Second)))
	var received [1]byte
	_, err = io.ReadFull(backend, received[:])
	must(err)
	if received[0] != value {
		panic("visitor live stream reached wrong provider")
	}
	_, err = backend.Write([]byte{value ^ 0xff})
	must(err)
	_, err = io.ReadFull(frontend, received[:])
	must(err)
	if received[0] != value^0xff {
		panic("visitor live stream response mismatch")
	}
	return visitorHeldPair{frontend, backend}
}
func (pair visitorHeldPair) close() {
	_ = pair.frontend.Close()
	_ = pair.backend.Close()
}
func (pair visitorHeldPair) drain() {
	must(pair.backend.(*net.TCPConn).CloseWrite())
	tail, err := io.ReadAll(pair.frontend)
	must(err)
	if len(tail) != 0 {
		panic("visitor unexpected frontend tail")
	}
	must(pair.frontend.(*net.TCPConn).CloseWrite())
	tail, err = io.ReadAll(pair.backend)
	must(err)
	if len(tail) != 0 {
		panic("visitor unexpected backend tail")
	}
	pair.close()
}
func visitorClosed(conn net.Conn) {
	must(conn.SetReadDeadline(time.Now().Add(3 * time.Second)))
	var payload [1]byte
	n, err := conn.Read(payload[:])
	if n != 0 || err == nil {
		panic("old visitor stream survived stop")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		panic("old visitor stream was abandoned")
	}
}
func visitorListenerClosed(address string) {
	conn, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		panic("visitor listener survived stopped control")
	}
}
func visitorNoBackend(local net.Listener) {
	must(local.(*net.TCPListener).SetDeadline(time.Now().Add(80 * time.Millisecond)))
	conn, err := local.Accept()
	if err == nil {
		_ = conn.Close()
		panic("rejected or capacity-limited visitor reached provider backend")
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		panic("visitor backend rejection probe: " + err.Error())
	}
	must(local.(*net.TCPListener).SetDeadline(time.Time{}))
}
func visitorCapacity(h *proxyHarness, address string, local net.Listener) {
	first := visitorHeld(address, local, 0x71)
	defer first.close()
	second := visitorHeld(address, local, 0x72)
	defer second.close()
	third := proxyDial(address)
	defer third.Close()
	_, err := third.Write([]byte{0x73})
	must(err)
	visitorNoBackend(local)
	state := h.state()
	if state.active != 2 || state.waiting != 0 || state.failed != 0 {
		panic(fmt.Sprintf("visitor exceeded two accepted sockets: %+v", state))
	}
	must(third.SetReadDeadline(time.Now().Add(80 * time.Millisecond)))
	var received [1]byte
	n, err := third.Read(received[:])
	if timeout, ok := err.(net.Error); n != 0 || !ok || !timeout.Timeout() {
		panic("third visitor escaped capacity/backlog boundary")
	}
	first.drain()
	must(local.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)))
	backend, err := local.Accept()
	must(err)
	defer backend.Close()
	must(backend.SetDeadline(time.Now().Add(5 * time.Second)))
	_, err = io.ReadFull(backend, received[:])
	must(err)
	if received[0] != 0x73 {
		panic("queued visitor lost input")
	}
	_, err = backend.Write([]byte{0x8c})
	must(err)
	must(third.SetReadDeadline(time.Now().Add(5 * time.Second)))
	_, err = io.ReadFull(third, received[:])
	must(err)
	if received[0] != 0x8c {
		panic("queued visitor response mismatch")
	}
	visitorHeldPair{third, backend}.drain()
	second.drain()
	visitorAwait(h, 5, 0)
}
func visitorRejection(path, caPath string, port int, local net.Listener, user, target, secret string) {
	bindPort := visitorFreePort()
	h := startSTCPVisitorHarness(path, caPath, port, bindPort, "serve", user, target, secret, 0)
	defer h.cleanup()
	address, _ := visitorReady(h, "READY")
	conn := proxyDial(address)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(5 * time.Second)))
	_, err := conn.Write([]byte{0, 0, 0, 99})
	must(err)
	visitorClosed(conn)
	state := visitorAwait(h, 0, 1)
	if state.reason != -23 {
		panic(fmt.Sprintf("STCP visitor authentication error not isolated: %+v", state))
	}
	visitorNoBackend(local)
	h.finish()
}
func visitorBeforeAuthentication(path, caPath string, port int) {
	for _, test := range []struct {
		mode   string
		reason int
	}{{"wrong-token", -14}, {"wrong-host", -15}, {"untrusted", -18}} {
		bindPort := visitorFreePort()
		h := startSTCPVisitorHarness(path, caPath, port, bindPort, test.mode, "provider", "provider.private", "public-visitor-secret", test.reason)
		defer h.cleanup()
		if line := h.line(); line != "REJECTED "+strconv.Itoa(test.reason) {
			panic("visitor pre-authentication rejection: " + line)
		}
		visitorListenerClosed(net.JoinHostPort("127.0.0.1", strconv.Itoa(bindPort)))
		h.finish()
	}
	occupied := localListener()
	defer occupied.Close()
	h := startSTCPVisitorHarness(path, caPath, port, occupied.Addr().(*net.TCPAddr).Port,
		"bind-error", "provider", "provider.private", "public-visitor-secret", -17)
	defer h.cleanup()
	if line := h.line(); line != "REJECTED -17" {
		panic("visitor bind collision not reported: " + line)
	}
	h.finish()
}
func visitorLifecycle(path, caPath string, port int, local net.Listener) {
	h := startSTCPVisitorHarness(path, caPath, port, visitorFreePort(), "serve", "provider", "provider.private", "public-visitor-secret", 0)
	defer h.cleanup()
	address, runID := visitorReady(h, "READY")
	visitorDual(h, address, local, 300, 2, 0)
	visitorCapacity(h, address, local)
	old := []visitorHeldPair{visitorHeld(address, local, 0x81), visitorHeld(address, local, 0x82)}
	defer func() {
		for _, pair := range old {
			pair.close()
		}
	}()
	visitorCommand(h, 'z', "STOPPED")
	for _, pair := range old {
		visitorClosed(pair.frontend)
		visitorClosed(pair.backend)
	}
	visitorListenerClosed(address)
	// Session cancellation releases owned streams without classifying them as
	// business failures. Their closure is proved above at both real endpoints.
	visitorAwait(h, 5, 0)
	_, err := h.input.Write([]byte{'g'})
	must(err)
	recovered, recoveredRunID := visitorReady(h, "RECOVERED")
	if recovered != address || recoveredRunID != runID {
		panic("visitor stop/start changed the owned target/session/listener")
	}
	visitorDual(h, address, local, 400, 7, 0)
	active := []visitorHeldPair{visitorHeld(address, local, 0x91), visitorHeld(address, local, 0x92)}
	defer func() {
		for _, pair := range active {
			pair.close()
		}
	}()
	visitorCommand(h, 't', "FAILED -18")
	for _, pair := range active {
		visitorClosed(pair.frontend)
		visitorClosed(pair.backend)
	}
	visitorListenerClosed(address)
	visitorAwait(h, 7, 0)
	h.finish()
}
func visitorRestart(path, caPath string, port int, local net.Listener, provider *stcpProvider, stop, start func()) {
	h := startSTCPVisitorHarness(path, caPath, port, visitorFreePort(), "serve", "provider", "provider.private", "public-visitor-secret", 0)
	defer h.cleanup()
	address, runID := visitorReady(h, "READY")
	old := []visitorHeldPair{visitorHeld(address, local, 0xa1), visitorHeld(address, local, 0xa2)}
	defer func() {
		for _, pair := range old {
			pair.close()
		}
	}()
	stop()
	_, err := h.input.Write([]byte{'b'})
	must(err)
	if line := h.line(); !strings.HasPrefix(line, "BACKOFF ") {
		panic("visitor missing backoff: " + line)
	}
	for _, pair := range old {
		visitorClosed(pair.frontend)
		visitorClosed(pair.backend)
	}
	visitorListenerClosed(address)
	state := h.state()
	if state.active != 0 || state.waiting != 0 || state.completed != 0 || state.failed != 0 {
		panic(fmt.Sprintf("visitor lost old streams on control failure: %+v", state))
	}
	provider.waitReady(false)
	start()
	provider.waitReady(true)
	_, err = h.input.Write([]byte{'c'})
	must(err)
	recovered, recoveredRunID := visitorReady(h, "RECOVERED")
	if recovered != address || recoveredRunID != runID {
		panic("visitor failed to recover the owned identity/listener")
	}
	visitorDual(h, address, local, 500, 2, 0)
	h.finish()
}
func runSTCPVisitor(path string) {
	withControlledSessionServer(func(port int, caPath, _ string, stop, start func()) {
		local := localListener()
		defer local.Close()
		provider := startSTCPProvider(port, local.Addr().(*net.TCPAddr).Port, caPath)
		defer provider.close()
		visitorBeforeAuthentication(path, caPath, port)
		for _, test := range []struct{ user, target, secret string }{
			{"provider", "provider.private", "wrong-public-secret"}, {"intruder", "provider.private", "public-visitor-secret"},
			{"provider", "provider.absent", "public-visitor-secret"}, {"provider", "private", "public-visitor-secret"},
		} {
			visitorRejection(path, caPath, port, local, test.user, test.target, test.secret)
		}
		visitorLifecycle(path, caPath, port, local)
		visitorRestart(path, caPath, port, local, provider, stop, start)
		fmt.Println("Official FRPS/frpc STCP provider → ESP visitor: strict pre-authentication, target/secret/user rejection, concurrent exact bodies, bounded accepted sockets, repeated admissions, active stop/start, clock loss and FRPS recovery passed")
	})
}
