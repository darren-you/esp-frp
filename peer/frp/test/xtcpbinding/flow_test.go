// SPDX-License-Identifier: Apache-2.0
package xtcpbinding_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatedier/frp/client"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
)

func port(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func certificates(t *testing.T) (string, string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public-loopback-ca"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(5 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(ca)
	if e != nil {
		t.Fatal(e)
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "frp.fixture.invalid"}, DNSNames: []string{"frp.fixture.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(5 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "key.pem")}
	for i, b := range [][]byte{ca, der, private} {
		name := "CERTIFICATE"
		if i == 2 {
			name = "PRIVATE KEY"
		}
		if e = os.WriteFile(paths[i], pem.EncodeToMemory(&pem.Block{Type: name, Bytes: b}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return paths[0], paths[1], paths[2]
}

// Two real local STUN sockets return source addresses and each other's address.
// This exercises discovery/coordination while making no claim about outer NAT.
func stunEndpoints(t *testing.T) []string {
	t.Helper()
	sockets := make([]*net.UDPConn, 2)
	var wg sync.WaitGroup
	for i := range sockets {
		c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		sockets[i] = c
	}
	for i, c := range sockets {
		other := sockets[1-i].LocalAddr().(*net.UDPAddr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			var packet [1024]byte
			for {
				n, from, e := c.ReadFromUDP(packet[:])
				if e != nil {
					return
				}
				if n < 20 || binary.BigEndian.Uint16(packet[:2]) != 1 || binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 {
					continue
				}
				resp := make([]byte, 44)
				binary.BigEndian.PutUint16(resp[:2], 0x0101)
				binary.BigEndian.PutUint16(resp[2:4], 24)
				copy(resp[4:20], packet[4:20])
				binary.BigEndian.PutUint16(resp[20:22], 0x0020)
				binary.BigEndian.PutUint16(resp[22:24], 8)
				resp[25] = 1
				binary.BigEndian.PutUint16(resp[26:28], uint16(from.Port)^0x2112)
				ip := from.IP.To4()
				cookie := []byte{0x21, 0x12, 0xa4, 0x42}
				for j := 0; j < 4; j++ {
					resp[28+j] = ip[j] ^ cookie[j]
				}
				binary.BigEndian.PutUint16(resp[32:34], 0x802c)
				binary.BigEndian.PutUint16(resp[34:36], 8)
				resp[37] = 1
				binary.BigEndian.PutUint16(resp[38:40], uint16(other.Port))
				copy(resp[40:44], other.IP.To4())
				_, _ = c.WriteToUDP(resp, from)
			}
		}()
	}
	t.Cleanup(func() {
		for _, c := range sockets {
			_ = c.Close()
		}
		wg.Wait()
	})
	return []string{sockets[0].LocalAddr().String(), sockets[1].LocalAddr().String()}
}
func stun(t *testing.T) string { return stunEndpoints(t)[0] }
func startClient(t *testing.T, p int, ca, stunAddr, user string, proxies []v1.ProxyConfigurer, visitors []v1.VisitorConfigurer) (*client.Service, func()) {
	t.Helper()
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: p, User: user, NatHoleSTUNServer: stunAddr}
	common.Auth.Token = "public-full-flow-token"
	common.Transport.WireProtocol = "v2"
	common.Transport.TLS.TrustedCaFile = ca
	common.Transport.TLS.ServerName = "frp.fixture.invalid"
	agg := source.NewConfigSource()
	if e := agg.ReplaceAll(proxies, visitors); e != nil {
		t.Fatal(e)
	}
	svc, e := client.NewService(client.ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(agg)})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(5 * time.Second):
				t.Error("desktop control did not release")
			}
		})
	}
	t.Cleanup(stop)
	return svc, stop
}

func TestPublicDesktopFullStrictSignalAndP2P(t *testing.T) {
	testDesktopFullStrictSignalAndP2P(t, "service-stop")
}
func TestProviderProxyRemovalClosesPeerWhileServicesLive(t *testing.T) {
	testDesktopFullStrictSignalAndP2P(t, "remove-readd")
}
func TestProviderControlReplacementClosesOldPeerWhileServicesLive(t *testing.T) {
	testDesktopFullStrictSignalAndP2P(t, "control-reconnect")
}
func TestOrdinaryControlAutomaticallyReloginsBeforeXTCPStarts(t *testing.T) {
	testDesktopFullStrictSignalAndP2P(t, "ordinary-add")
}

func testDesktopFullStrictSignalAndP2P(t *testing.T, action string) {
	ca, cert, key := certificates(t)
	serverPort := port(t)
	stunAddr := stun(t)
	cfg := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: serverPort, ProxyBindAddr: "127.0.0.1"}
	cfg.Auth.Token = "public-full-flow-token"
	cfg.Transport.TLS.Force = true
	cfg.Transport.TLS.CertFile = cert
	cfg.Transport.TLS.KeyFile = key
	if e := cfg.Complete(); e != nil {
		t.Fatal(e)
	}
	frps, e := server.NewService(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	frpsDone := make(chan struct{})
	go func() { frps.Run(ctx); close(frpsDone) }()
	t.Cleanup(func() { cancel(); _ = frps.Close(); <-frpsDone })
	backend, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var backendCount atomic.Uint32
	var backendActive atomic.Int32
	backendDone := make(chan struct{})
	var backendWorkers sync.WaitGroup
	go func() {
		defer close(backendDone)
		for {
			c, e := backend.Accept()
			if e != nil {
				return
			}
			backendCount.Add(1)
			backendActive.Add(1)
			backendWorkers.Add(1)
			go func() {
				defer backendWorkers.Done()
				defer backendActive.Add(-1)
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { _ = backend.Close(); <-backendDone; backendWorkers.Wait() })
	pconf := &v1.XTCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "private", Type: "xtcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: backend.Addr().(*net.TCPAddr).Port}}, Secretkey: "public-full-flow-secret", AllowUsers: []string{"visitor"}, NatTraversal: &v1.NatTraversalConfig{DisableAssistedAddrs: true}}
	providerPort := serverPort
	var relay *controlRelay
	if action == "control-reconnect" || action == "ordinary-add" {
		relay = newControlRelay(t, serverPort)
		providerPort = relay.listener.Addr().(*net.TCPAddr).Port
	}
	providerProxies := []v1.ProxyConfigurer{pconf}
	initialName := "private"
	if action == "ordinary-add" {
		providerProxies = []v1.ProxyConfigurer{&v1.TCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "ordinary", Type: "tcp"}, RemotePort: port(t)}}
		initialName = "ordinary"
	}
	provider, stopProvider := startClient(t, providerPort, ca, stunAddr, "provider", providerProxies, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, ok := provider.StatusExporter().GetProxyStatus(initialName)
		if ok && s.Phase == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("candidate provider did not register", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if action == "ordinary-add" {
		if relay.accepted.Load() != 1 {
			t.Fatal("ordinary initial control not unique")
		}
		if e := provider.UpdateAllConfigurer([]v1.ProxyConfigurer{pconf}, nil); e != nil {
			t.Fatal(e)
		}
		deadline = time.Now().Add(6 * time.Second)
		for {
			s, ok := provider.StatusExporter().GetProxyStatus("private")
			if ok && s.Phase == "running" && relay.accepted.Load() >= 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("XTCP did not register on a new real control", s, relay.accepted.Load())
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Log("ordinary configured Control was revoked; new actual TLS control registered XTCP")
	}

	visitorPort := port(t)
	vconf := &v1.XTCPVisitorConfig{VisitorBaseConfig: v1.VisitorBaseConfig{Name: "visit", Type: "xtcp", ServerUser: "provider", ServerName: "private", SecretKey: "public-full-flow-secret", BindAddr: "127.0.0.1", BindPort: visitorPort}, NatTraversal: &v1.NatTraversalConfig{DisableAssistedAddrs: true}}
	_, stopVisitor := startClient(t, serverPort, ca, stunAddr, "visitor", nil, []v1.VisitorConfigurer{vconf})
	dial := func() net.Conn {
		deadline := time.Now().Add(5 * time.Second)
		for {
			c, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(visitorPort)), 100*time.Millisecond)
			if e == nil {
				return c
			}
			if time.Now().After(deadline) {
				t.Fatal(e)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	flows := []net.Conn{dial(), dial()}
	for _, c := range flows {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	}
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for i, c := range flows {
		workers.Add(1)
		go func() {
			defer workers.Done()
			payload := bytes.Repeat([]byte{byte(i + 1)}, 300001)
			if _, e := c.Write(payload); e != nil {
				results <- e
				return
			}
			echo := make([]byte, len(payload))
			_, e := io.ReadFull(c, echo)
			if e == nil && !bytes.Equal(payload, echo) {
				e = io.ErrUnexpectedEOF
			}
			results <- e
		}()
	}
	workers.Wait()
	close(results)
	for e := range results {
		if e != nil {
			t.Fatal(e)
		}
	}
	if backendCount.Load() != 2 {
		t.Fatal("unexpected admitted backend count", backendCount.Load())
	}
	if action == "remove-readd" {
		if err := provider.UpdateAllConfigurer(nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, present := provider.StatusExporter().GetProxyStatus("private"); present {
			t.Fatal("removed provider proxy still registered locally")
		}
		t.Log("removed provider proxy through public UpdateAllConfigurer; both Service contexts stay live")
	} else if action == "control-reconnect" {
		if relay.accepted.Load() != 1 {
			t.Fatal("provider control transport not unique before revoke", relay.accepted.Load())
		}
		relay.dropFirst(t)
		t.Log("closed only provider control TCP transport; both Service contexts stay live")
	} else {
		stopProvider()
	}
	for _, c := range flows {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))

		var b [1]byte
		n, e := c.Read(b[:])
		var timeout net.Error
		if errors.As(e, &timeout) && timeout.Timeout() {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			probe := []byte("after-owner-remove")
			_, writeErr := c.Write(probe)
			got := make([]byte, len(probe))
			_, readErr := io.ReadFull(c, got)
			t.Fatalf("provider owner removal retained peer: operation read deadline expired; post-removal write=%v read=%v echo_equal=%t", writeErr, readErr, bytes.Equal(got, probe))
		}
		if n != 0 || e == nil {
			t.Fatal("provider owner removal retained peer flow", n, e)
		}
	}
	deadline = time.Now().Add(2 * time.Second)
	for backendActive.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle backend retained after owner removal", backendActive.Load())
		}
		time.Sleep(time.Millisecond)
	}
	t.Log("both actual idle backend sockets ended after peer owner removal")
	if action != "service-stop" && action != "ordinary-add" {
		if action == "remove-readd" {
			if e := provider.UpdateAllConfigurer([]v1.ProxyConfigurer{pconf}, nil); e != nil {
				t.Fatal(e)
			}
		}
		deadline = time.Now().Add(6 * time.Second)
		for {
			s, ok := provider.StatusExporter().GetProxyStatus("private")
			if ok && s.Phase == "running" && (relay == nil || relay.accepted.Load() >= 2) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("new owner did not register", s)
			}
			time.Sleep(10 * time.Millisecond)
		}
		// The existing visitor must re-establish a fresh authenticated peer.
		c := dial()
		defer c.Close()
		// The existing visitor openTunnel contract allows 20s (including its 10s retry pacing).
		_ = c.SetDeadline(time.Now().Add(22 * time.Second))
		payload := []byte("new-same-name-control-backend")
		if _, e := c.Write(payload); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(payload))
		if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(payload, got) {
			t.Fatal("new owner business failed", e)
		}
		if backendCount.Load() != 3 {
			t.Fatal("new owner did not admit a new backend", backendCount.Load())
		}
		t.Log("new owner with same proxy name admitted fresh authenticated business")
	}
	stopVisitor()
	t.Log("actual public FRPS/FRPC strict TLS+Token Login, control ownership, STUN, authenticated SID, mutual QUIC+manifest proof and two 300001-byte backend flows passed; provider control close released peer flows")
}
