// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	frplog "github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/server"
)

type proxyHarness struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Scanner
	stderr bytes.Buffer
	cancel context.CancelFunc
	ended  bool
}

func startProxyHarness(path, caPath string, port, localPort int, mode, name string, expected int, domains []string) *proxyHarness {
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	h := &proxyHarness{cancel: cancel}
	args := []string{strconv.Itoa(port), caPath, strconv.Itoa(localPort), mode, name, strconv.Itoa(expected)}
	args = append(args, domains...)
	h.cmd = exec.CommandContext(ctx, path, args...)
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
func (h *proxyHarness) line() string {
	if !h.output.Scan() {
		_ = h.cmd.Wait()
		h.ended = true
		panic("proxy peer lost output: " + h.stderr.String())
	}
	return h.output.Text()
}
func (h *proxyHarness) ready() string {
	line := h.line()
	if !strings.HasPrefix(line, "READY ") {
		panic("proxy expected ready: " + line + "\n" + h.stderr.String())
	}
	return strings.TrimPrefix(line, "READY ")
}
func (h *proxyHarness) state() workState {
	_, err := h.input.Write([]byte{'s'})
	must(err)
	var value workState
	n, err := fmt.Sscanf(h.line(), "STATE %d %d %d %d %d", &value.active, &value.waiting, &value.completed, &value.failed, &value.reason)
	must(err)
	if n != 5 {
		panic("incomplete proxy work state")
	}
	return value
}
func (h *proxyHarness) awaitCompleted(count uint64) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		state := h.state()
		if state.failed != 0 {
			panic(fmt.Sprintf("proxy work failed: %+v", state))
		}
		if state.completed == count && state.active == 0 {
			return
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("proxy did not drain: %+v want=%d", state, count))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (h *proxyHarness) finish() {
	_, err := h.input.Write([]byte{'q'})
	must(err)
	must(h.input.Close())
	h.wait()
}
func (h *proxyHarness) wait() {
	if err := h.cmd.Wait(); err != nil {
		h.ended = true
		panic(fmt.Sprintf("proxy peer exit: %v\n%s", err, h.stderr.String()))
	}
	h.ended = true
	fmt.Print(h.stderr.String())
}
func (h *proxyHarness) cleanup() {
	h.cancel()
	if !h.ended {
		_ = h.cmd.Process.Kill()
		_ = h.cmd.Wait()
	}
}

func withProxyServer(run func(port, httpPort, httpsPort int, caPath, dir string)) {
	dir, err := os.MkdirTemp("", "esp-frp-proxy-")
	must(err)
	defer os.RemoveAll(dir)
	cert, ca := certificate("ok")
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server-key.pem")
	must(os.WriteFile(caPath, ca, 0600))
	must(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	must(err)
	must(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	reserved := []net.Listener{localListener(), localListener(), localListener()}
	ports := make([]int, len(reserved))
	for i, listener := range reserved {
		ports[i] = listener.Addr().(*net.TCPAddr).Port
		must(listener.Close())
	}
	config := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: ports[0], ProxyBindAddr: "127.0.0.1",
		VhostHTTPPort: ports[1], VhostHTTPSPort: ports[2], SubDomainHost: "sub.fixture.test"}
	config.Auth.Token = "public-session-token"
	config.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	config.Transport.TLS.Force = true
	config.Transport.TLS.CertFile = certPath
	config.Transport.TLS.KeyFile = keyPath
	must(config.Complete())
	frplog.InitLogger("console", "error", 1, true)
	service, err := server.NewService(config)
	must(err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { service.Run(ctx); close(done) }()
	defer func() {
		cancel()
		must(service.Close())
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			panic("proxy FRPS did not stop")
		}
	}()
	run(ports[0], ports[1], ports[2], caPath, dir)
}

func proxyVisitor(port int, caPath, user, target, secret string) (string, func()) {
	reserved := localListener()
	visitorPort := reserved.Addr().(*net.TCPAddr).Port
	must(reserved.Close())
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: port, User: user}
	common.Auth.Token = "public-session-token"
	common.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	common.Transport.WireProtocol = "v2"
	common.Transport.TLS.ServerName = "frp.fixture.invalid"
	common.Transport.TLS.TrustedCaFile = caPath
	visitor := &v1.STCPVisitorConfig{VisitorBaseConfig: v1.VisitorBaseConfig{Name: "official-visitor", Type: "stcp",
		ServerUser: "provider", ServerName: target, SecretKey: secret, BindAddr: "127.0.0.1", BindPort: visitorPort}}
	configSource := source.NewConfigSource()
	must(configSource.ReplaceAll(nil, []v1.VisitorConfigurer{visitor}))
	service, err := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(configSource)})
	must(err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			must(err)
		case <-time.After(5 * time.Second):
			panic("official visitor did not stop")
		}
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(visitorPort)), stop
}
func proxyDial(address string) net.Conn {
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			panic("official visitor did not bind: " + err.Error())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func proxyRemoteWork(conn net.Conn, id uint32) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	written := make(chan error, 1)
	go func() {
		err := binary.Write(conn, binary.BigEndian, id)
		if err == nil {
			_, err = conn.Write(workPattern(id, false))
		}
		written <- err
	}()
	payload := make([]byte, 300001)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	if !bytes.Equal(payload, workPattern(id, true)) {
		return fmt.Errorf("STCP provider payload mismatch")
	}
	if err := <-written; err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x5a}); err != nil {
		return err
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 0xa5 {
		return fmt.Errorf("STCP provider receipt: %v", err)
	}
	tail, err := io.ReadAll(conn)
	if err == nil && len(tail) != 0 {
		err = fmt.Errorf("STCP unexpected tail")
	}
	return err
}
func proxySTCP(path, caPath string, port int) {
	local := localListener()
	defer local.Close()
	localPort := local.Addr().(*net.TCPAddr).Port
	h := startProxyHarness(path, caPath, port, localPort, "stcp", "provider.private", 0, nil)
	defer h.cleanup()
	if remote := h.ready(); remote != "" {
		panic("STCP unexpectedly advertised public port")
	}
	results := make(chan error, 2)
	var accepted atomic.Int32
	go func() {
		for range 2 {
			conn, err := local.Accept()
			if err != nil {
				results <- err
				return
			}
			accepted.Add(1)
			go func() { results <- localWork(conn) }()
		}
	}()
	address, stop := proxyVisitor(port, caPath, "provider", "private", "public-proxy-secret")
	remote := make(chan error, 2)
	for id := uint32(0); id < 2; id++ {
		go func() { remote <- proxyRemoteWork(proxyDial(address), id) }()
	}
	for range 2 {
		must(<-remote)
		must(<-results)
	}
	stop()
	h.awaitCompleted(2)
	for _, test := range []struct{ user, target, secret string }{
		{"provider", "private", "wrong-public-secret"}, {"intruder", "private", "public-proxy-secret"},
		{"provider", "absent", "public-proxy-secret"},
	} {
		address, stop := proxyVisitor(port, caPath, test.user, test.target, test.secret)
		conn := proxyDial(address)
		must(conn.SetDeadline(time.Now().Add(5 * time.Second)))
		_, err := conn.Write([]byte{0, 0, 0, 99})
		must(err)
		var data [1]byte
		n, err := conn.Read(data[:])
		_ = conn.Close()
		stop()
		if n != 0 || err == nil {
			panic("invalid STCP visitor reached provider")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			panic("STCP authentication did not reject before timeout")
		}
		if accepted.Load() != 2 {
			panic("invalid STCP visitor opened local socket")
		}
		must(local.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond)))
		unexpected, err := local.Accept()
		if err == nil {
			_ = unexpected.Close()
			panic("invalid STCP visitor opened an unhandled local socket")
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			panic("local socket rejection probe failed: " + err.Error())
		}
	}
	h.awaitCompleted(2)
	duplicate := startProxyHarness(path, caPath, port, localPort, "stcp", "provider.private", -22, nil)
	defer duplicate.cleanup()
	if line := duplicate.line(); line != "REJECTED -22" {
		panic("duplicate STCP registration: " + line)
	}
	duplicate.wait()
	h.finish()
	fmt.Println("Official FRPS/STCP visitor: ESP provider dual flow, secret/user/target rejection and duplicate registration passed")
}
func proxyTCP(path, caPath string, port int) {
	local := localListener()
	defer local.Close()
	h := startProxyHarness(path, caPath, port, local.Addr().(*net.TCPAddr).Port, "tcp", "provider.tcp", 0, nil)
	defer h.cleanup()
	remote := h.ready()
	host, remotePort, err := net.SplitHostPort(remote)
	must(err)
	if host != "" {
		panic("TCP proxy escaped configured loopback")
	}
	address := net.JoinHostPort("127.0.0.1", remotePort)
	localResults := make(chan error, 2)
	go func() {
		for range 2 {
			conn, err := local.Accept()
			if err != nil {
				localResults <- err
				return
			}
			go func() { localResults <- localWork(conn) }()
		}
	}()
	remoteResults := make(chan error, 2)
	for id := uint32(0); id < 2; id++ {
		go func() { remoteResults <- remoteWork(address, id) }()
	}
	for range 2 {
		must(<-remoteResults)
		must(<-localResults)
	}
	h.awaitCompleted(2)
	h.finish()
	fmt.Println("Official FRPS/TCP: typed provider retained dual-flow byte-exact forwarding")
}

func proxyBusinessCertificate(hosts []string) (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(17), DNSNames: hosts, IsCA: true, BasicConstraintsValid: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	must(err)
	parsed, err := x509.ParseCertificate(der)
	must(err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// Give the opaque TCP provider an unambiguous, drained close sequence. An HTTP
// client can close as soon as Content-Length bytes arrive, before close_notify;
// keep the backend's receive half alive until the provider forwards that tail.
func proxyHTTPSBackend(listener net.Listener, cert tls.Certificate, handler http.Handler) func() {
	var workers sync.WaitGroup
	done := make(chan struct{})
	failures := make(chan error, 16)
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					failures <- err
				}
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				err := conn.Handshake()
				if err == nil {
					var request *http.Request
					request, err = http.ReadRequest(bufio.NewReader(conn))
					if err == nil {
						state := conn.ConnectionState()
						request.TLS = &state
						recorder := httptest.NewRecorder()
						handler.ServeHTTP(recorder, request)
						_ = request.Body.Close()
						response := recorder.Result()
						response.Close = true
						response.ContentLength = int64(recorder.Body.Len())
						err = response.Write(conn)
						_ = response.Body.Close()
					}
				}
				if err == nil {
					err = conn.CloseWrite()
				}
				if err == nil {
					err = raw.(*net.TCPConn).CloseWrite()
				}
				if err == nil {
					_, err = io.Copy(io.Discard, conn)
				}
				if err == nil {
					_, err = io.Copy(io.Discard, raw)
				}
				if err != nil {
					failures <- err
				}
			}()
		}
	}()
	return func() {
		_ = listener.Close()
		<-done
		workers.Wait()
		close(failures)
		for err := range failures {
			must(err)
		}
	}
}

func proxyHTTP(path, caPath string, port, vhostPort int, secure bool) {
	domains := []string{"frp.fixture.invalid", "alternate.fixture.invalid", "board"}
	hosts := []string{domains[0], domains[1], "board.sub.fixture.test"}
	mode := "http"
	if secure {
		mode = "https"
	}
	var requests atomic.Int32
	var badBackendHost atomic.Bool
	backend := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		valid := false
		for _, host := range hosts {
			if request.Host == host {
				valid = true
			}
		}
		if !valid || (secure && (request.TLS == nil || request.TLS.ServerName != request.Host)) {
			badBackendHost.Store(true)
			http.Error(writer, "wrong backend Host/SNI", http.StatusBadRequest)
			return
		}
		if request.Header.Get("Authorization") != "Bearer public-backend-token" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := strconv.ParseUint(request.URL.Query().Get("id"), 10, 32)
		if err != nil {
			http.Error(writer, "bad id", http.StatusBadRequest)
			return
		}
		payload := workPattern(uint32(id), true)
		writer.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = writer.Write(payload)
	})}
	backend.SetKeepAlivesEnabled(false)
	local := localListener()
	localPort := local.Addr().(*net.TCPAddr).Port
	var roots *x509.CertPool
	var closeBackend func()
	if secure {
		cert, pool := proxyBusinessCertificate(hosts)
		roots = pool
		closeBackend = proxyHTTPSBackend(local, cert, backend.Handler)
	} else {
		served := make(chan error, 1)
		go func() { served <- backend.Serve(local) }()
		closeBackend = func() {
			_ = backend.Close()
			err := <-served
			if err != http.ErrServerClosed {
				must(err)
			}
		}
	}
	defer closeBackend()
	h := startProxyHarness(path, caPath, port, localPort, mode, "provider."+mode, 0, domains)
	defer h.cleanup()
	wantRemote := []string{}
	for _, host := range hosts {
		wantRemote = append(wantRemote, net.JoinHostPort(host, strconv.Itoa(vhostPort)))
	}
	if remote := h.ready(); remote != strings.Join(wantRemote, ",") {
		panic("proxy domain registration response: " + remote)
	}
	transport := &http.Transport{DisableKeepAlives: true, Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(vhostPort)))
		}, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	requester := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	request := func(host string, id uint32, authorized bool) error {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		req, err := http.NewRequest(http.MethodGet, scheme+"://"+net.JoinHostPort(host, strconv.Itoa(vhostPort))+"/body?id="+strconv.FormatUint(uint64(id), 10), nil)
		if err != nil {
			return err
		}
		req.Host = host
		if authorized {
			req.Header.Set("Authorization", "Bearer public-backend-token")
		}
		response, err := requester.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		if !authorized && response.StatusCode == http.StatusUnauthorized {
			return nil
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(payload, workPattern(id, true)) {
			return fmt.Errorf("%s response code=%d bytes=%d", mode, response.StatusCode, len(payload))
		}
		return nil
	}
	for round := uint32(0); round < 3; round++ {
		results := make(chan error, 2)
		for index := uint32(0); index < 2; index++ {
			go func() { results <- request(hosts[(round+index)%3], round*2+index, true) }()
		}
		for range 2 {
			must(<-results)
		}
		h.awaitCompleted(uint64((round + 1) * 2))
	}
	must(request(hosts[0], 99, false))
	h.awaitCompleted(7)
	before := requests.Load()
	err := request("absent.fixture.invalid", 100, true)
	if err == nil {
		panic("wrong Host/SNI accepted")
	}
	if requests.Load() != before || badBackendHost.Load() {
		panic("incorrect route reached local business service")
	}
	duplicate := startProxyHarness(path, caPath, port, localPort, mode, "provider.duplicate-"+mode, -22, domains)
	defer duplicate.cleanup()
	if line := duplicate.line(); line != "REJECTED -22" {
		panic("duplicate domain registration: " + line)
	}
	duplicate.wait()
	h.finish()
	fmt.Printf("Official FRPS/%s: two domains/subdomain, correct/wrong Host/SNI, local authorization, concurrent 300001-byte bodies and duplicate routes passed\n", mode)
}
func proxyLongResponse(path, caPath string, port, httpPort int) {
	labels := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	other := "e" + labels[1:]
	local := localListener()
	defer local.Close()
	h := startProxyHarness(path, caPath, port, local.Addr().(*net.TCPAddr).Port, "http", "provider.long-domains", 0, []string{labels, other, "long-board"})
	defer h.cleanup()
	want := net.JoinHostPort(labels, strconv.Itoa(httpPort)) + "," + net.JoinHostPort(other, strconv.Itoa(httpPort)) + "," + net.JoinHostPort("long-board.sub.fixture.test", strconv.Itoa(httpPort))
	if address := h.ready(); address != want || len(address) <= 256 {
		panic("long domain response was truncated: " + address)
	}
	h.finish()
	fmt.Println("Official FRPS: two legal 253-byte domains and subdomain returned completely; insufficient getter capacity rejected without truncation")
}
func runProxy(path string) {
	withProxyServer(func(port, httpPort, httpsPort int, caPath, _ string) {
		proxyTCP(path, caPath, port)
		proxySTCP(path, caPath, port)
		proxyHTTP(path, caPath, port, httpPort, false)
		proxyHTTP(path, caPath, port, httpsPort, true)
		proxyLongResponse(path, caPath, port, httpPort)
	})
}
