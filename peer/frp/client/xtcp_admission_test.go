// SPDX-License-Identifier: Apache-2.0
package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/xtcpbinding"
)

const admissionToken = "public-admission-fixture-token"

type admissionLogin struct {
	login   msg.Login
	reply   chan []byte
	done    chan error
	proxies chan string
}

// The gate delays only LoginResp on an actual verified TLS connection. The
// default production Connector, v2 hello, Token verification and encrypted
// post-login messages all run; the fixture does not claim to be a full FRPS.
type admissionPeer struct {
	listener net.Listener
	logins   chan *admissionLogin
	stop     chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	conns    []net.Conn
	workers  sync.WaitGroup
	caPath   string
}

func newAdmissionPeer(t *testing.T) *admissionPeer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admission.fixture.invalid"},
		DNSNames: []string{"admission.fixture.invalid"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(5 * time.Minute),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	caPath := filepath.Join(t.TempDir(), "public_ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	require.NoError(t, err)
	p := &admissionPeer{listener: l, logins: make(chan *admissionLogin, 8), stop: make(chan struct{}), done: make(chan struct{}), caPath: caPath}
	go func() {
		defer close(p.done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			p.workers.Add(1)
			go func() { defer p.workers.Done(); p.serve(conn) }()
		}
	}()
	t.Cleanup(func() {
		close(p.stop)
		_ = l.Close()
		<-p.done
		p.mu.Lock()
		for _, conn := range p.conns {
			_ = conn.Close()
		}
		p.mu.Unlock()
		p.workers.Wait()
	})
	return p
}

func (p *admissionPeer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := &admissionLogin{reply: make(chan []byte, 1), done: make(chan error, 1), proxies: make(chan string, 8)}
	err := func() error {
		magic := make([]byte, len(wire.MagicV2))
		if _, err := io.ReadFull(conn, magic); err != nil {
			return err
		}
		if string(magic) != wire.MagicV2 {
			return fmt.Errorf("unexpected magic")
		}
		wc := wire.NewConn(conn)
		frame, err := wc.ReadFrame()
		if err != nil {
			return err
		}
		var hello wire.ClientHello
		if err = wc.UnmarshalFrame(frame, &hello); err != nil {
			return err
		}
		rw := msg.NewV2ReadWriterWithConn(wc)
		if err = rw.ReadMsgInto(&r.login); err != nil {
			return err
		}
		if err = auth.NewAuthVerifier(v1.AuthServerConfig{Method: v1.AuthMethodToken, Token: admissionToken}).VerifyLogin(&r.login); err != nil {
			return err
		}
		sh, err := wire.NewServerHello(hello)
		if err != nil {
			return err
		}
		out, err := wire.NewJSONFrame(wire.FrameTypeServerHello, sh)
		if err != nil {
			return err
		}
		if err = wc.WriteFrame(out); err != nil {
			return err
		}
		select {
		case p.logins <- r:
		case <-p.stop:
			return net.ErrClosed
		}
		var id []byte
		select {
		case id = <-r.reply:
		case <-p.stop:
			return net.ErrClosed
		}
		if err = rw.WriteMsg(&msg.LoginResp{RunID: "admission-run", XTCPControlID: id}); err != nil {
			return err
		}
		crypto := wire.NewCryptoContext(sh.Selected.Crypto.Algorithm, frame.Payload, out.Payload)
		controlRW, err := netpkg.NewAEADCryptoReadWriter(conn, []byte(admissionToken), netpkg.AEADCryptoRoleServer, crypto.Algorithm, crypto.TranscriptHash)
		if err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Time{})
		control := msg.NewReadWriter(controlRW, wire.ProtocolV2)
		for {
			m, err := control.ReadMsg()
			if err != nil {
				return err
			}
			if proxy, ok := m.(*msg.NewProxy); ok {
				select {
				case r.proxies <- proxy.ProxyName:
				case <-p.stop:
					return net.ErrClosed
				}
				if err = control.WriteMsg(&msg.NewProxyResp{ProxyName: proxy.ProxyName}); err != nil {
					return err
				}
			}
		}
	}()
	r.done <- err
}

func (p *admissionPeer) next(t *testing.T, binding bool) *admissionLogin {
	t.Helper()
	select {
	case r := <-p.logins:
		require.Equal(t, binding, r.login.XTCPBindingProtocol == xtcpbinding.ALPN)
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("actual TLS login did not reach LoginResp gate")
		return nil
	}
}

func admissionProxy(name string) *v1.XTCPProxyConfig {
	p := &v1.XTCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: name, Type: "xtcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: 12345}}, Secretkey: "public-admission-secret"}
	p.Complete()
	return p
}

func startAdmissionService(t *testing.T, peer *admissionPeer, proxies []v1.ProxyConfigurer) *Service {
	t.Helper()
	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1", ServerPort: peer.listener.Addr().(*net.TCPAddr).Port, LoginFailExit: lo.ToPtr(true)}
	common.Auth.Token = admissionToken
	common.Transport.WireProtocol = wire.ProtocolV2
	common.Transport.TCPMux = lo.ToPtr(false)
	common.Transport.HeartbeatInterval = -1
	common.Transport.TLS.TrustedCaFile = peer.caPath
	common.Transport.TLS.ServerName = "admission.fixture.invalid"
	common.Transport.TLS.DisableCustomTLSFirstByte = lo.ToPtr(true)
	cfg := source.NewConfigSource()
	require.NoError(t, cfg.ReplaceAll(proxies, nil))
	svr, err := NewService(ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(cfg)})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- svr.Run(context.Background()) }()
	t.Cleanup(func() {
		svr.Close()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("Service did not release after fixture close")
		}
	})
	return svr
}

func requireDiscardedAdmissionLogin(t *testing.T, r *admissionLogin) {
	t.Helper()
	select {
	case err := <-r.done:
		require.Error(t, err)
		var timeout net.Error
		require.False(t, errors.As(err, &timeout) && timeout.Timeout(), "read timeout is not connection revocation")
	case <-time.After(3 * time.Second):
		t.Fatal("obsolete login connection remained open")
	}
	select {
	case name := <-r.proxies:
		t.Fatalf("proxy %q started on obsolete negotiation", name)
	default:
	}
}

func TestXTCPInitialLoginRemovalDoesNotApplyObsoleteFailureOrSuccess(t *testing.T) {
	for _, validOldResponse := range []bool{false, true} {
		t.Run(fmt.Sprintf("old_response_valid_%t", validOldResponse), func(t *testing.T) {
			peer := newAdmissionPeer(t)
			svr := startAdmissionService(t, peer, []v1.ProxyConfigurer{admissionProxy("removed")})
			old := peer.next(t, true)
			require.NoError(t, svr.UpdateAllConfigurer(nil, nil))
			var id []byte
			if validOldResponse {
				id = append([]byte{1}, make([]byte, 31)...)
			}
			old.reply <- id
			requireDiscardedAdmissionLogin(t, old)
			current := peer.next(t, false)
			current.reply <- nil
			require.Eventually(t, func() bool { return svr.currentControl() != nil }, 3*time.Second, time.Millisecond)
			require.NoError(t, svr.ctx.Err())
			require.Empty(t, svr.currentControl().sessionCtx.Common.XTCPControlID)
		})
	}
}

func TestXTCPAddedWhileOrdinaryLoginWaitsStartsOnlyOnNewBoundControl(t *testing.T) {
	peer := newAdmissionPeer(t)
	svr := startAdmissionService(t, peer, nil)
	old := peer.next(t, false)
	require.NoError(t, svr.UpdateAllConfigurer([]v1.ProxyConfigurer{admissionProxy("latest")}, nil))
	old.reply <- nil
	requireDiscardedAdmissionLogin(t, old)
	current := peer.next(t, true)
	current.reply <- append([]byte{2}, make([]byte, 31)...)
	select {
	case name := <-current.proxies:
		require.Equal(t, "latest", name)
	case <-time.After(3 * time.Second):
		t.Fatal("new bound Control did not register latest XTCP")
	}
	require.Eventually(t, func() bool { status, ok := svr.getProxyStatus("latest"); return ok && status.Phase == "running" }, 3*time.Second, time.Millisecond)
	require.NoError(t, svr.ctx.Err())
}

func TestXTCPConcurrentUpdatesDuringLoginPublishOnlyLatestConfig(t *testing.T) {
	peer := newAdmissionPeer(t)
	svr := startAdmissionService(t, peer, nil)
	old := peer.next(t, false)
	var workers sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range 30 {
				var configs []v1.ProxyConfigurer
				if i%2 == 0 {
					configs = []v1.ProxyConfigurer{admissionProxy(fmt.Sprintf("pending_%d", i))}
				}
				if err := svr.UpdateAllConfigurer(configs, nil); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, svr.UpdateAllConfigurer([]v1.ProxyConfigurer{admissionProxy("latest")}, nil))
	old.reply <- nil
	requireDiscardedAdmissionLogin(t, old)
	current := peer.next(t, true)
	current.reply <- append([]byte{3}, make([]byte, 31)...)
	select {
	case name := <-current.proxies:
		require.Equal(t, "latest", name)
	case <-time.After(3 * time.Second):
		t.Fatal("latest config was not registered on new bound Control")
	}
}

func TestXTCPAdmissionRejectsSecurityBypassBeforeManagersRun(t *testing.T) {
	for _, invalid := range []string{"no_ca", "plaintext", "v1", "non_token", "empty_auth", "missing_id"} {
		t.Run(invalid, func(t *testing.T) {
			d := newTestControlSessionDialer(t, wire.ProtocolV2, nil, nil)
			d.common.Auth.Method = v1.AuthMethodToken
			d.common.Transport.TLS.Enable = lo.ToPtr(true)
			d.common.Transport.TLS.TrustedCaFile = "explicit_ca.pem"
			d.common.XTCPControlID = append([]byte{4}, make([]byte, 31)...)
			switch invalid {
			case "no_ca":
				d.common.Transport.TLS.TrustedCaFile = ""
			case "plaintext":
				d.common.Transport.TLS.Enable = lo.ToPtr(false)
			case "v1":
				d.common.Transport.WireProtocol = wire.ProtocolV1
			case "non_token":
				d.common.Auth.Method = v1.AuthMethodOIDC
			case "empty_auth":
				d.auth = &auth.ClientAuth{}
			case "missing_id":
				d.common.XTCPControlID = nil
			}
			front, back := net.Pipe()
			defer front.Close()
			defer back.Close()
			ctl, err := NewControl(context.Background(), &SessionContext{Common: d.common, Auth: d.auth, Conn: msg.NewConn(front, msg.NewV2ReadWriter(front))})
			require.NoError(t, err)
			defer ctl.cancel()
			proxies := []v1.ProxyConfigurer{admissionProxy("denied")}
			visitors := []v1.VisitorConfigurer{&v1.XTCPVisitorConfig{VisitorBaseConfig: v1.VisitorBaseConfig{Name: "denied", Type: "xtcp", BindPort: -1}}}
			for _, config := range []struct {
				proxies  []v1.ProxyConfigurer
				visitors []v1.VisitorConfigurer
			}{{proxies, nil}, {nil, visitors}} {
				require.Error(t, ctl.Run(config.proxies, config.visitors))
				require.Error(t, ctl.UpdateAllConfigurer(config.proxies, config.visitors))
			}
			_, exists := ctl.pm.GetProxyStatus("denied")
			require.False(t, exists)
			_, exists = ctl.vm.GetVisitorCfg("denied")
			require.False(t, exists)
		})
	}
}

func TestXTCPNewServiceRejectsUnsafeConfigurationBeforeOpeningAdmin(t *testing.T) {
	for _, invalid := range []string{"no_ca", "plaintext", "v1", "empty_token", "ssh_tunnel"} {
		t.Run(invalid, func(t *testing.T) {
			common := &v1.ClientCommonConfig{}
			common.Auth.Token = admissionToken
			common.Transport.WireProtocol = wire.ProtocolV2
			common.Transport.TLS.Enable = lo.ToPtr(true)
			common.Transport.TLS.TrustedCaFile = "explicit_ca.pem"
			common.WebServer.Addr = "127.0.0.1"
			common.WebServer.Port = getFreeTCPPort(t)
			var spec *msg.ClientSpec
			switch invalid {
			case "no_ca":
				common.Transport.TLS.TrustedCaFile = ""
			case "plaintext":
				common.Transport.TLS.Enable = lo.ToPtr(false)
			case "v1":
				common.Transport.WireProtocol = wire.ProtocolV1
			case "empty_token":
				common.Auth.Token = ""
			case "ssh_tunnel":
				spec = &msg.ClientSpec{Type: "ssh-tunnel"}
			}
			cfg := source.NewConfigSource()
			require.NoError(t, cfg.ReplaceAll([]v1.ProxyConfigurer{admissionProxy("denied")}, nil))
			svc, err := NewService(ServiceOptions{Common: common, ConfigSourceAggregator: source.NewAggregator(cfg), ClientSpec: spec})
			require.ErrorContains(t, err, "XTCP requires verified TLS")
			require.Nil(t, svc)
			listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", common.WebServer.Port))
			require.NoError(t, err)
			require.NoError(t, listener.Close())
		})
	}
}

func TestXTCPAdmissionConcurrentRunAndPublicUpdateRetainsLatestConfig(t *testing.T) {
	// Public Update may precede or overlap Run. A cancelled parent prevents any
	// network attempt while both real public methods execute their startup paths.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		svr, err := NewService(ServiceOptions{
			Common:                 &v1.ClientCommonConfig{LoginFailExit: lo.ToPtr(true)},
			ConfigSourceAggregator: source.NewAggregator(source.NewConfigSource()),
		})
		require.NoError(t, err)
		latest := &v1.TCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "latest", Type: "tcp", ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: 10081},
		}}
		latest.Complete()
		start := make(chan struct{})
		runResult, updateResult := make(chan error, 1), make(chan error, 1)
		go func() { <-start; runResult <- svr.Run(ctx) }()
		go func() { <-start; updateResult <- svr.UpdateAllConfigurer([]v1.ProxyConfigurer{latest}, nil) }()
		close(start)
		require.NoError(t, <-updateResult)
		require.Error(t, <-runResult)
		svr.cfgMu.RLock()
		require.Len(t, svr.proxyCfgs, 1)
		require.Equal(t, "latest", svr.proxyCfgs[0].GetBaseConfig().Name)
		require.Equal(t, 10081, svr.proxyCfgs[0].GetBaseConfig().LocalPort)
		svr.cfgMu.RUnlock()
		require.Nil(t, svr.currentControl())
	}
}
