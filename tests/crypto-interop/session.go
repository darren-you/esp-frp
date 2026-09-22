// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	frplog "github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/server"
)

func localListener() net.Listener {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	return listener
}
func sessionCase(path, caPath, mode string, port, proxyPort, rounds int) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, mode, strconv.Itoa(rounds), strconv.Itoa(proxyPort))
	output, err := cmd.StdoutPipe()
	must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var ports []string
	var requests []net.Conn
	defer func() {
		for _, connection := range requests {
			_ = connection.Close()
		}
	}()
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "REGISTERED ") {
			panic("unexpected peer output: " + line)
		}
		address := strings.TrimPrefix(line, "REGISTERED ")
		host, port, err := net.SplitHostPort(address)
		must(err)
		if host != "" && host != "127.0.0.1" {
			panic("proxy escaped loopback")
		}
		// Official TCPProxy advertises only :port; this test explicitly binds
		// ProxyBindAddr to loopback and never dials an advertised remote host.
		address = net.JoinHostPort("127.0.0.1", port)
		ports = append(ports, address)
		if mode == "request" {
			connection, err := net.DialTimeout("tcp4", address, 2*time.Second)
			must(err)
			requests = append(requests, connection)
		}
	}
	must(scanner.Err())
	if err := cmd.Wait(); err != nil {
		panic(fmt.Sprintf("control %s: %v\n%s", mode, err, stderr.String()))
	}
	want := rounds
	if mode == "wrong-token" || mode == "proxy-error" || strings.HasPrefix(mode, "cancel-") {
		want = 0
	}
	if len(ports) != want {
		panic(fmt.Sprintf("registered=%d want=%d", len(ports), want))
	}
	// The real FRPS must retire each proxy after the client has stopped.
	for _, address := range ports {
		deadline := time.Now().Add(5 * time.Second)
		for {
			connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
			if err != nil {
				break
			}
			_ = connection.Close()
			if time.Now().After(deadline) {
				panic("FRPS proxy remained after client destroy")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	fmt.Print(stderr.String())
}
func withSessionServer(run func(port int, caPath, dir string)) {
	withControlledSessionServer(func(port int, caPath, dir string, stop, start func()) { run(port, caPath, dir) })
}
func withControlledSessionServer(run func(port int, caPath, dir string, stop, start func())) {
	dir, err := os.MkdirTemp("", "esp-frp-session-")
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
	reserved := localListener()
	port := reserved.Addr().(*net.TCPAddr).Port
	must(reserved.Close())
	config := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: port, ProxyBindAddr: "127.0.0.1"}
	config.Auth.Token = "public-session-token"
	config.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	config.Transport.TLS.Force = true
	config.Transport.TLS.CertFile = certPath
	config.Transport.TLS.KeyFile = keyPath
	must(config.Complete())
	frplog.InitLogger("console", "error", 1, true)
	var service *server.Service
	var cancel context.CancelFunc
	var done chan struct{}
	start := func() {
		if service != nil {
			panic("already started")
		}
		var err error
		service, err = server.NewService(config)
		must(err)
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		done = make(chan struct{})
		current := service
		go func() { current.Run(ctx); close(done) }()
	}
	stop := func() {
		if service == nil {
			return
		}
		cancel()
		must(service.Close())
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			panic("FRPS did not stop")
		}
		service = nil
	}
	start()
	defer stop()
	run(port, caPath, dir, stop, start)
}
func runSession(path string) {
	withSessionServer(func(port int, caPath, dir string) {
		sessionCase(path, caPath, "ok", port, 0, 100)
		sessionCase(path, caPath, "request", port, 0, 1)
		sessionCase(path, caPath, "heartbeat", port, 0, 1)
		sessionCase(path, caPath, "split", port, 0, 1)
		sessionCase(path, caPath, "wrong-token", port, 0, 1)
		occupied := localListener()
		sessionCase(path, caPath, "proxy-error", port, occupied.Addr().(*net.TCPAddr).Port, 1)
		must(occupied.Close())
		sessionCase(path, caPath, "cancel-login", port, 0, 1)
		sessionCase(path, caPath, "cancel-register", port, 0, 1)
		fmt.Println("Official FRPS: strict TLS/Yamux/Login/AEAD/NewProxy/Token heartbeat, work request and cancellation passed")
		runSessionFixtures(path, dir)
	})
}
