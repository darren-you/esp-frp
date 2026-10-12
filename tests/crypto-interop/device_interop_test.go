// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
)

func deviceTestConfig(t *testing.T) deviceInteropConfig {
	t.Helper()
	dir := t.TempDir()
	cert, ca := certificate("ok")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.pem")}
	data := [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), ca}
	for i, path := range paths {
		if err := os.WriteFile(path, data[i], 0600); err != nil {
			t.Fatal(err)
		}
	}
	return deviceInteropConfig{ListenIPv4: "127.0.0.1", ListenPort: visitorFreePort(), DeviceIPv4: "127.0.0.1", Transport: "tcp", Role: "provider", ProxyType: "tcp", ProxyName: "board.echo", User: "board", ClientID: "fixture-device", Token: "public-device-interop-token", RemotePort: visitorFreePort(), CertificateFile: paths[0], PrivateKeyFile: paths[1], CAFile: paths[2], ServerName: "frp.fixture.invalid", TimeoutMS: 30000, EvidenceDirectory: filepath.Join(dir, "evidence")}
}
func TestDeviceInteropConfig(t *testing.T) {
	base := deviceTestConfig(t)
	path := filepath.Join(t.TempDir(), "device.json")
	for _, tc := range []struct {
		name   string
		mutate func(*deviceInteropConfig)
		want   bool
	}{
		{"explicit-tcp", func(c *deviceInteropConfig) {}, true},
		{"wildcard-host", func(c *deviceInteropConfig) { c.ListenIPv4 = "0.0.0.0" }, false},
		{"host-name-device", func(c *deviceInteropConfig) { c.DeviceIPv4 = "device.example" }, false},
		{"quic-missing-port", func(c *deviceInteropConfig) { c.Transport = "quic" }, false},
		{"tcp-with-quic", func(c *deviceInteropConfig) { c.QUICPort = visitorFreePort() }, false},
		{"visitor-udp", func(c *deviceInteropConfig) { c.Role = "visitor" }, false},
		{"unprefixed-wire-name", func(c *deviceInteropConfig) { c.ProxyName = "echo" }, false},
		{"implicit-maintained-peer", func(c *deviceInteropConfig) { c.ProxyType = "xtcp"; c.SecretKey = "public-secret" }, false},
		{"unused-http-field", func(c *deviceInteropConfig) { c.BackendToken = "unused" }, false},
		{"unused-visitor-field", func(c *deviceInteropConfig) { c.VisitorPort = 18001 }, false},
		{"unused-private-secret", func(c *deviceInteropConfig) { c.SecretKey = "unused" }, false},
		{"private-secret-too-long", func(c *deviceInteropConfig) {
			c.ProxyType = "stcp"
			c.RemotePort = 0
			c.SecretKey = strings.Repeat("s", 129)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			if err := deviceWriteJSON(path, c); err != nil {
				t.Fatal(err)
			}
			_, err := loadDeviceInteropConfig(path)
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%t want=%t: %v", err == nil, tc.want, err)
			}
		})
	}
	if err := deviceWriteJSON(path, base); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeviceInteropConfig(path); err == nil {
		t.Fatal("accepted nonprivate fixture config")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(",\"unknown\":true}")...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeviceInteropConfig(path); err == nil {
		t.Fatal("accepted unknown config field")
	}
	data, err = json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:len(data)-1], []byte(",\"listen_ipv4\":\"127.0.0.2\"}")...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeviceInteropConfig(path); err == nil {
		t.Fatal("accepted duplicate config field")
	}
	httpConfig := deviceTestModeConfig(t, "provider", "http", "tcp")
	httpConfig.Domains = []string{"Board.fixture.invalid", "board.fixture.invalid"}
	if err := deviceWriteJSON(path, httpConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeviceInteropConfig(path); err == nil {
		t.Fatal("accepted case-folded duplicate domains")
	}
	httpConfig.Domains = []string{"bad_.fixture.invalid"}
	if err := deviceWriteJSON(path, httpConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDeviceInteropConfig(path); err == nil {
		t.Fatal("accepted invalid domain label")
	}
}
func TestDeviceInteropAdmission(t *testing.T) {
	c := deviceTestConfig(t)
	service, state := deviceAdmissionPlugin(c)
	defer service.Close()
	call := func(op string, content any) bool {
		data, err := json.Marshal(plugin.Request{Op: op, Content: content})
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.Post(service.URL, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result plugin.Response
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return !result.Reject
	}
	login := plugin.LoginContent{Login: msg.Login{User: c.User, ClientID: c.ClientID}, ClientAddress: "127.0.0.2:19400"}
	if call("Login", login) || state.loggedIn.Load() {
		t.Fatal("unexpected IP reached device admission")
	}
	login.ClientAddress = "127.0.0.1:19400"
	login.ClientID = "another-device"
	if call("Login", login) {
		t.Fatal("unexpected device identity admitted")
	}
	login.ClientID = c.ClientID
	if !call("Login", login) || !state.loggedIn.Load() {
		t.Fatal("exact device was not admitted")
	}
	registration := plugin.NewProxyContent{User: plugin.UserInfo{User: c.User}, NewProxy: msg.NewProxy{ProxyName: c.ProxyName, ProxyType: "udp", RemotePort: c.RemotePort}}
	if call("NewProxy", registration) || state.registered.Load() {
		t.Fatal("unexpected typed registration admitted")
	}
	registration.ProxyType = c.ProxyType
	if !call("NewProxy", registration) || !state.registered.Load() {
		t.Fatal("exact typed registration rejected")
	}
}

func TestDeviceInteropCPrivateRegistration(t *testing.T) {
	for _, kind := range []string{"stcp", "xtcp"} {
		c := deviceTestConfig(t)
		c.ProxyType, c.RemotePort, c.SecretKey = kind, 0, "public-secret"
		service, state := deviceAdmissionPlugin(c)
		call := func(users []string) bool {
			content := plugin.NewProxyContent{User: plugin.UserInfo{User: c.User}, NewProxy: msg.NewProxy{ProxyName: c.ProxyName, ProxyType: kind, Sk: c.SecretKey, AllowUsers: users}}
			data, _ := json.Marshal(plugin.Request{Op: "NewProxy", Content: content})
			response, err := http.Post(service.URL, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var result plugin.Response
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			return !result.Reject
		}
		if call([]string{c.User}) || state.registered.Load() {
			t.Fatal("device provider admitted an allow_users field absent from its C contract")
		}
		if !call(nil) || !state.registered.Load() {
			t.Fatal("exact C private provider registration was rejected")
		}
		service.Close()
	}
}
func TestDeviceInteropBinarySnapshot(t *testing.T) {
	dir := t.TempDir()
	original, destination := filepath.Join(dir, "peer"), filepath.Join(dir, "snapshot")
	data := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(original, data, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := deviceVerifiedBinary(original, strings.Repeat("0", 64), destination); err == nil {
		t.Fatal("accepted incorrect binary digest")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}
	if _, err := deviceVerifiedBinary(link, deviceDigest(data), destination); err == nil {
		t.Fatal("accepted symlink binary")
	}
	if _, err := deviceVerifiedBinary(original, deviceDigest(data), destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("binary snapshot bytes changed")
	}
}

// This checks the new driver, not the already qualified host C matrix. A Go
// client stands in for one device solely to exercise the explicit LAN wiring,
// private configuration, official FRPS admission and two byte/FIN probes.
func deviceTestDriver(t *testing.T, c deviceInteropConfig) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "device.json")
	if err := deviceWriteJSON(path, c); err != nil {
		t.Fatal(err)
	}
	backendPort := 0
	if c.Role == "provider" {
		switch c.ProxyType {
		case "tcp", "stcp", "xtcp":
			port, stop, err := deviceTCPBackend()
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			backendPort = port
		case "udp":
			socket := udpListener()
			defer socket.Close()
			go udpEcho(socket)
			backendPort = socket.LocalAddr().(*net.UDPAddr).Port
		case "http", "https":
			backendPort = c.BackendPort
		}
	}
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()
	originalInput := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = originalInput }()
	done := make(chan error, 1)
	go func() { done <- runDeviceInterop(path) }()
	// This only probes the newly started local FRPS process. Device Login is a
	// separate exact-IP/identity admission and business forwarding assertion.
	deadline := time.Now().Add(20 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.ListenPort)), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatal(err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("driver FRPS startup timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	common := &v1.ClientCommonConfig{ServerAddr: c.ListenIPv4, ServerPort: c.ListenPort, User: c.User, ClientID: c.ClientID}
	common.Auth.Token = c.Token
	common.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	common.Transport.WireProtocol = "v2"
	common.Transport.TLS.ServerName = c.ServerName
	common.Transport.TLS.TrustedCaFile = c.CAFile
	if c.Transport == "quic" {
		common.Transport.Protocol, common.ServerPort = "quic", c.QUICPort
	}
	name := strings.TrimPrefix(c.ProxyName, c.User+".")
	var proxies []v1.ProxyConfigurer
	var visitors []v1.VisitorConfigurer
	if c.Role == "provider" {
		base := v1.ProxyBaseConfig{Name: name, Type: c.ProxyType, ProxyBackend: v1.ProxyBackend{LocalIP: c.ListenIPv4, LocalPort: backendPort}}
		switch c.ProxyType {
		case "tcp":
			proxies = []v1.ProxyConfigurer{&v1.TCPProxyConfig{ProxyBaseConfig: base, RemotePort: c.RemotePort}}
		case "udp":
			proxies = []v1.ProxyConfigurer{&v1.UDPProxyConfig{ProxyBaseConfig: base, RemotePort: c.RemotePort}}
		case "stcp":
			proxies = []v1.ProxyConfigurer{&v1.STCPProxyConfig{ProxyBaseConfig: base, Secretkey: c.SecretKey}}
		case "xtcp":
			proxies = []v1.ProxyConfigurer{&v1.XTCPProxyConfig{ProxyBaseConfig: base, Secretkey: c.SecretKey}}
		case "http":
			proxies = []v1.ProxyConfigurer{&v1.HTTPProxyConfig{ProxyBaseConfig: base, DomainConfig: v1.DomainConfig{CustomDomains: c.Domains}}}
		case "https":
			proxies = []v1.ProxyConfigurer{&v1.HTTPSProxyConfig{ProxyBaseConfig: base, DomainConfig: v1.DomainConfig{CustomDomains: c.Domains}}}
		}
	} else {
		base := v1.VisitorBaseConfig{Name: "device-visitor", Type: c.ProxyType, ServerName: name, ServerUser: c.User, SecretKey: c.SecretKey, BindAddr: c.DeviceIPv4, BindPort: c.VisitorPort}
		if c.ProxyType == "stcp" {
			visitors = []v1.VisitorConfigurer{&v1.STCPVisitorConfig{VisitorBaseConfig: base}}
		} else {
			visitors = []v1.VisitorConfigurer{&v1.XTCPVisitorConfig{VisitorBaseConfig: base, Protocol: "quic"}}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if c.ProxyType == "xtcp" {
		common.NatHoleSTUNServer = net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.STUNPorts[0]))
	}
	common.Log.To, common.Log.Level = "console", "info"
	peerPath := filepath.Join(t.TempDir(), "device-peer.json")
	peerLog := filepath.Join(t.TempDir(), "device-peer.log")
	config := struct {
		*v1.ClientCommonConfig
		Proxies  []v1.ProxyConfigurer   `json:"proxies,omitempty"`
		Visitors []v1.VisitorConfigurer `json:"visitors,omitempty"`
	}{common, proxies, visitors}
	if err := deviceWriteJSON(peerPath, config); err != nil {
		t.Fatal(err)
	}
	binary := c.FRPCBinary
	if c.ProxyType != "xtcp" {
		binary = filepath.Join(c.EvidenceDirectory, "frpc")
	}
	stop, err := deviceProcess(ctx, binary, peerPath, peerLog, "login to server success")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for {
		logs, _ := os.ReadFile(peerLog)
		if (c.Role == "provider" && bytes.Contains(logs, []byte("start proxy success"))) || (c.Role == "visitor" && bytes.Contains(logs, []byte("start visitor success"))) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fixed CLI stand-in readiness timeout: %s", logs)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if c.Role == "visitor" {
		for {
			logs, _ := os.ReadFile(filepath.Join(c.EvidenceDirectory, "frpc.log"))
			if bytes.Contains(logs, []byte("start proxy success")) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("host provider readiness timeout: %s", logs)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if _, err := io.WriteString(output, "resume\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("driver probes/cleanup did not finish")
	}
	data, err := os.ReadFile(filepath.Join(c.EvidenceDirectory, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report deviceInteropReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.ConfigurationSHA256 == "" || report.FRPSSHA256 == "" || report.FRPCSHA256 == "" || len(report.PassedScope) == 0 {
		t.Fatalf("incomplete software driver result: %+v", report)
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.ListenPort)), 50*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("fixture FRPS remained after finished")
	}
}
func deviceTestModeConfig(t *testing.T, role, kind, transport string) deviceInteropConfig {
	t.Helper()
	c := deviceTestConfig(t)
	c.Role, c.ProxyType, c.Transport = role, kind, transport
	if transport == "quic" {
		c.QUICPort = visitorFreePort()
	}
	if kind != "tcp" && kind != "udp" {
		c.RemotePort = 0
	}
	if role == "visitor" {
		c.VisitorPort = visitorFreePort()
	}
	if kind == "stcp" || kind == "xtcp" {
		c.SecretKey = "public-device-interop-secret"
	}
	if kind == "http" || kind == "https" {
		c.Domains = []string{"board.fixture.invalid", "alternate.fixture.invalid"}
		c.VhostPort, c.BackendPort = visitorFreePort(), visitorFreePort()
		c.BackendToken = "public-device-backend-token"
	}
	if kind == "https" {
		cert, _ := proxyBusinessCertificate(c.Domains)
		key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		c.BackendCertificateFile, c.BackendPrivateKeyFile = filepath.Join(t.TempDir(), "business.pem"), filepath.Join(t.TempDir(), "business.key")
		c.BackendCAFile = c.BackendCertificateFile
		if err := os.WriteFile(c.BackendCertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.BackendPrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return c
}
func TestDeviceInteropOfficialDrivers(t *testing.T) {
	for _, tc := range []struct{ role, kind, transport string }{{"provider", "tcp", "tcp"}, {"provider", "udp", "tcp"}, {"provider", "stcp", "tcp"}, {"visitor", "stcp", "tcp"}, {"provider", "http", "tcp"}, {"provider", "https", "tcp"}, {"provider", "tcp", "quic"}} {
		t.Run(tc.role+"/"+tc.kind+"/"+tc.transport, func(t *testing.T) { deviceTestDriver(t, deviceTestModeConfig(t, tc.role, tc.kind, tc.transport)) })
	}
}
func TestDeviceInteropHTTPSCancellation(t *testing.T) {
	c := deviceTestModeConfig(t, "provider", "https", "tcp")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop, _, err := deviceHTTPBackend(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	// An active socket deliberately sends no TLS ClientHello. Stop must close
	// that socket and join the handshake worker, not wait its ten-second timer.
	raw, err := net.Dial("tcp4", net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.BackendPort)))
	if err != nil {
		stop()
		t.Fatal(err)
	}
	defer raw.Close()
	done := make(chan struct{})
	cancel()
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTPS cancellation did not close and join active handshake")
	}
}
func TestDeviceInteropCanceledDriver(t *testing.T) {
	c := deviceTestConfig(t)
	c.TimeoutMS = 2000
	path := filepath.Join(t.TempDir(), "device.json")
	if err := deviceWriteJSON(path, c); err != nil {
		t.Fatal(err)
	}
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()
	originalInput := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = originalInput }()
	if err := runDeviceInterop(path); err == nil {
		t.Fatal("fixture with no device/resume falsely passed")
	}
	data, err := os.ReadFile(filepath.Join(c.EvidenceDirectory, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report deviceInteropReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || len(report.PassedScope) != 0 {
		t.Fatalf("failed fixture claimed success: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(c.EvidenceDirectory, "input.json")); err != nil {
		t.Fatal("failed fixture removed original input")
	}
	if _, err := os.Stat(filepath.Join(c.EvidenceDirectory, "frps.log")); err != nil {
		t.Fatal("failed fixture removed original process log")
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.ListenPort)), 50*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("failed fixture retained FRPS process endpoint")
	}
	if err := runDeviceInterop(path); err == nil || !strings.Contains(err.Error(), "evidence directory must be new") {
		t.Fatal("existing evidence directory was overwritten")
	}
}
func TestDeviceInteropMaintainedDrivers(t *testing.T) {
	serverBinary, clientBinary := os.Getenv("EFRP_DEVICE_MAINTAINED_FRPS"), os.Getenv("EFRP_DEVICE_MAINTAINED_FRPC")
	if serverBinary == "" || clientBinary == "" {
		t.Skip("explicit maintained FRPS/FRPC test binaries were not supplied")
	}
	serverData, err := os.ReadFile(serverBinary)
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := os.ReadFile(clientBinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"provider", "visitor"} {
		t.Run(role, func(t *testing.T) {
			c := deviceTestModeConfig(t, role, "xtcp", "tcp")
			c.FRPSBinary, c.FRPCBinary = serverBinary, clientBinary
			c.FRPSSHA256, c.FRPCSHA256 = deviceDigest(serverData), deviceDigest(clientData)
			c.STUNPorts = []int{visitorFreePort(), visitorFreePort()}
			deviceTestDriver(t, c)
		})
	}
}

func TestDeviceResumeInput(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		eof, good   bool
	}{{"resume", "resume\n", false, true}, {"wrong-line", "continue\n", false, false}, {"bounded-line", strings.Repeat("r", 65) + "\n", false, false}, {"eof", "", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			input, output, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer output.Close()
			original := os.Stdin
			os.Stdin = input
			defer func() { os.Stdin = original }()
			if _, err := io.WriteString(output, tc.input); err != nil {
				t.Fatal(err)
			}
			if tc.eof {
				_ = output.Close()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := waitDeviceResume(ctx); (err == nil) != tc.good {
				t.Fatalf("accepted=%t expected=%t: %v", err == nil, tc.good, err)
			}
		})
	}
}
func TestDeviceInteropRejectsUnauthenticated200(t *testing.T) {
	c := deviceTestModeConfig(t, "provider", "http", "tcp")
	listener, err := net.Listen("tcp4", net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.VhostPort)))
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately incorrect business authorization: return the valid positive
		// body even when the driver omits its Bearer header.
		id, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 32)
		payload := workPattern(uint32(id), true)
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	_ = service.Listener.Close()
	service.Listener = listener
	service.Start()
	defer service.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := deviceHTTPProbe(ctx, c, &deviceHTTPStats{}); err == nil || !strings.Contains(err.Error(), "requires status 401") {
		t.Fatalf("false authorized 200 was not rejected: %v", err)
	}
}
func deviceTestForwardAll(t *testing.T, c deviceInteropConfig) func() {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(c.ListenIPv4), Port: c.VhostPort})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var connections sync.Map
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			frontend, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			connections.Store(frontend, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer frontend.Close()
				defer connections.Delete(frontend)
				backend, err := net.DialTimeout("tcp4", net.JoinHostPort(c.ListenIPv4, fmt.Sprint(c.BackendPort)), time.Second)
				if err != nil {
					return
				}
				defer backend.Close()
				connections.Store(backend, true)
				defer connections.Delete(backend)
				written := make(chan struct{})
				go func() { _, _ = io.Copy(backend, frontend); _ = backend.(*net.TCPConn).CloseWrite(); close(written) }()
				_, _ = io.Copy(frontend, backend)
				_ = frontend.CloseWrite()
				_ = backend.Close()
				_ = frontend.Close()
				<-written
			}()
		}
	}()
	return func() {
		_ = listener.Close()
		<-done
		connections.Range(func(key, value any) bool { _ = key.(net.Conn).Close(); return true })
		workers.Wait()
	}
}
func TestDeviceInteropRejectsUnregisteredBackendRoute(t *testing.T) {
	for _, kind := range []string{"http", "https"} {
		t.Run(kind, func(t *testing.T) {
			c := deviceTestModeConfig(t, "provider", kind, "tcp")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			closeBackend, stats, err := deviceHTTPBackend(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			defer closeBackend()
			closeVhost := deviceTestForwardAll(t, c)
			defer closeVhost()
			// This incorrect vhost sends every Host/SNI to the backend. HTTP returns
			// 400 and HTTPS fails normal SAN validation, but both must fail the route
			// assertion because a real backend socket was accepted.
			if err := deviceHTTPProbe(ctx, c, stats); err == nil || !strings.Contains(err.Error(), "unregistered route reached business backend") {
				t.Fatalf("false route was not rejected: %v", err)
			}
		})
	}
}
