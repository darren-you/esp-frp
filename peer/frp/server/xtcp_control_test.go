// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/proto/wire"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/xtcpbinding"
)

const xtcpControlTestToken = "public-control-fixture-token"

// 本测试走实际 TCP 监听器、证书验证、Token 登录、AEAD 与 dispatcher。
// 不向连接注入 TLS context，也不从调用方字段注册 control 身份。
func newXTCPControlEndpoint(t *testing.T) (*Service, string, *tls.Config) {
	t.Helper()
	svr := newControlTestService(t)
	svr.cfg.Auth.Token = xtcpControlTestToken
	require.NoError(t, svr.cfg.Complete())
	svr.cfg.Transport.TCPMux = lo.ToPtr(false)
	svr.cfg.Transport.TLS.Force = false // 负例允许进入真实明文分类路径。
	var err error
	svr.auth, err = auth.BuildServerAuth(&svr.cfg.Auth)
	require.NoError(t, err)
	svr.rc.NatHoleController, err = nathole.NewController(time.Hour)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "candidate.fixture.invalid"},
		DNSNames: []string{"candidate.fixture.invalid"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	svr.tlsConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	strictTLS := &tls.Config{RootCAs: roots, ServerName: "candidate.fixture.invalid", MinVersion: tls.VersionTLS13}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { svr.HandleListener(listener, false); close(done) }()
	t.Cleanup(func() {
		_ = listener.Close()
		require.NoError(t, svr.ctlManager.Close())
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("实际控制监听器未退出")
		}
	})
	return svr, listener.Addr().String(), strictTLS
}

func xtcpEndpointLogin(t *testing.T, address string, tlsConfig *tls.Config, protocol, token, binding, user, runID string) (*msg.Conn, *msg.LoginResp) {
	t.Helper()
	var conn net.Conn
	var err error
	if tlsConfig == nil {
		conn, err = net.DialTimeout("tcp4", address, 3*time.Second)
	} else {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp4", address, tlsConfig)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	login := &msg.Login{User: user, ClientID: "fixture-client-" + user, Timestamp: time.Now().Unix(), RunID: runID, XTCPBindingProtocol: binding}
	require.NoError(t, auth.NewTokenAuth(nil, token).SetLogin(login))
	if protocol != wire.ProtocolV2 {
		rw := msg.NewV1ReadWriter(conn)
		require.NoError(t, rw.WriteMsg(login))
		var reply msg.LoginResp
		require.NoError(t, rw.ReadMsgInto(&reply))
		return msg.NewConn(conn, rw), &reply
	}
	require.NoError(t, wire.WriteMagic(conn))
	wc := wire.NewConn(conn)
	// 即使明文负例自报 TLS=true，实际监听器仍必须拒绝。
	hello, err := wire.NewClientHello(wire.BootstrapInfo{Transport: "tcp", TLS: true, TCPMux: false})
	require.NoError(t, err)
	clientFrame, err := wire.NewJSONFrame(wire.FrameTypeClientHello, hello)
	require.NoError(t, err)
	require.NoError(t, wc.WriteFrame(clientFrame))
	rw := msg.NewV2ReadWriterWithConn(wc)
	require.NoError(t, rw.WriteMsg(login))
	serverFrame, err := wc.ReadFrame()
	require.NoError(t, err)
	require.Equal(t, wire.FrameTypeServerHello, serverFrame.Type)
	var serverHello wire.ServerHello
	require.NoError(t, wc.UnmarshalFrame(serverFrame, &serverHello))
	require.Empty(t, serverHello.Error)
	var reply msg.LoginResp
	require.NoError(t, rw.ReadMsgInto(&reply))
	if reply.Error != "" {
		return msg.NewConn(conn, rw), &reply
	}
	crypto, err := wire.NewClientCryptoContext(clientFrame.Payload, serverFrame.Payload)
	require.NoError(t, err)
	controlRW, err := netpkg.NewAEADCryptoReadWriter(conn, []byte(token), netpkg.AEADCryptoRoleClient, crypto.Algorithm, crypto.TranscriptHash)
	require.NoError(t, err)
	if tlsConn, ok := conn.(*tls.Conn); ok {
		require.True(t, tlsConn.ConnectionState().HandshakeComplete)
		require.NotEmpty(t, tlsConn.ConnectionState().VerifiedChains)
	}
	return msg.NewConn(conn, msg.NewV2ReadWriter(controlRW)), &reply
}

func xtcpEndpointProxy(t *testing.T, conn *msg.Conn, name string, wantError bool) {
	t.Helper()
	require.NoError(t, conn.WriteMsg(&msg.NewProxy{ProxyName: name, ProxyType: "xtcp", Sk: "public-proxy-secret", AllowUsers: []string{"provider"}}))
	var reply msg.NewProxyResp
	require.NoError(t, conn.ReadMsgInto(&reply))
	require.Equal(t, name, reply.ProxyName)
	if wantError {
		require.NotEmpty(t, reply.Error)
	} else {
		require.Empty(t, reply.Error)
	}
}

func xtcpEndpointVisitor(t *testing.T, conn *msg.Conn, request *msg.NatHoleVisitor) *msg.NatHoleResp {
	t.Helper()
	require.NoError(t, conn.WriteMsg(request))
	var reply msg.NatHoleResp
	require.NoError(t, conn.ReadMsgInto(&reply))
	require.Equal(t, request.TransactionID, reply.TransactionID)
	return &reply
}

func TestXTCPActualControlAdmission(t *testing.T) {
	_, address, strictTLS := newXTCPControlEndpoint(t)
	for _, tc := range []struct {
		name, wire, token, binding string
		tls                        bool
	}{
		{"bad-token", wire.ProtocolV2, "wrong-token", xtcpbinding.ALPN, true},
		{"physical-plaintext-despite-hello", wire.ProtocolV2, xtcpControlTestToken, xtcpbinding.ALPN, false},
		{"wire-v1", wire.ProtocolV1, xtcpControlTestToken, xtcpbinding.ALPN, true},
		{"unknown-binding", wire.ProtocolV2, xtcpControlTestToken, "unexpected-binding", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *tls.Config
			if tc.tls {
				cfg = strictTLS
			}
			conn, reply := xtcpEndpointLogin(t, address, cfg, tc.wire, tc.token, tc.binding, "provider", "")
			require.NotEmpty(t, reply.Error)
			require.Empty(t, reply.XTCPControlID)
			var extra [1]byte
			n, err := conn.Read(extra[:])
			require.Zero(t, n)
			require.Error(t, err)
		})
	}
	for _, tc := range []struct {
		name string
		cfg  *tls.Config
	}{
		{"no-trusted-ca", &tls.Config{ServerName: strictTLS.ServerName, MinVersion: tls.VersionTLS13}},
		{"wrong-host", func() *tls.Config { c := strictTLS.Clone(); c.ServerName = "wrong.fixture.invalid"; return c }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp4", address, tc.cfg)
			require.Error(t, err)
			if conn != nil {
				_ = conn.Close()
			}
		})
	}
	ordinary, reply := xtcpEndpointLogin(t, address, strictTLS, wire.ProtocolV2, xtcpControlTestToken, "", "ordinary", "")
	require.Empty(t, reply.Error)
	require.Empty(t, reply.XTCPControlID)
	xtcpEndpointProxy(t, ordinary, "ordinary.denied", true)
	r := xtcpEndpointVisitor(t, ordinary, &msg.NatHoleVisitor{TransactionID: "unnegotiated", ProxyName: "ordinary.denied", PreCheck: true})
	require.NotEmpty(t, r.Error)
	require.Empty(t, r.Sid)
}

func TestXTCPActualControlOwnerReplacementAndDispatch(t *testing.T) {
	svr, address, strictTLS := newXTCPControlEndpoint(t)
	first, login := xtcpEndpointLogin(t, address, strictTLS, wire.ProtocolV2, xtcpControlTestToken, xtcpbinding.ALPN, "provider", "")
	require.Empty(t, login.Error)
	_, err := xtcpbinding.ID(login.XTCPControlID)
	require.NoError(t, err)
	firstCtl := currentControlForTest(svr.ctlManager, login.RunID)
	require.NotNil(t, firstCtl)
	xtcpEndpointProxy(t, first, "provider.bound", false)
	firstCtl.mu.RLock()
	oldProxy := firstCtl.proxies["provider.bound"]
	firstCtl.mu.RUnlock()
	require.NotNil(t, oldProxy)
	precheck := func(conn *msg.Conn, tx string) *msg.NatHoleResp {
		return xtcpEndpointVisitor(t, conn, &msg.NatHoleVisitor{TransactionID: tx, ProxyName: "provider.bound", PreCheck: true})
	}
	require.Empty(t, precheck(first, "present-first").Error)
	intruder, intruderLogin := xtcpEndpointLogin(t, address, strictTLS, wire.ProtocolV2, xtcpControlTestToken, xtcpbinding.ALPN, "intruder", "")
	require.Empty(t, intruderLogin.Error)
	require.Contains(t, precheck(intruder, "wrong-user").Error, "not allowed")
	require.NotEmpty(t, xtcpEndpointVisitor(t, first, &msg.NatHoleVisitor{TransactionID: "wrong-target", ProxyName: "provider.other", PreCheck: true}).Error)
	identity, err := xtcpbinding.NewIdentity(xtcpbinding.Visitor)
	require.NoError(t, err)
	badKey := &msg.NatHoleVisitor{TransactionID: "wrong-key", ProxyName: "provider.bound", Protocol: "quic", Timestamp: time.Now().Unix(),
		ControlID: login.XTCPControlID, Nonce: identity.Nonce[:], SPKISHA256: identity.SPKI[:], Certificate: identity.DER}
	badKey.SignalProof, err = xtcpbinding.SignalProof("incorrect-proxy-secret", xtcpbinding.Visitor, badKey.ProxyName, badKey.ControlID, badKey.Nonce, badKey.SPKISHA256, badKey.Timestamp)
	require.NoError(t, err)
	r := xtcpEndpointVisitor(t, first, badKey)
	require.NotEmpty(t, r.Error)
	require.Empty(t, r.Sid)

	replacement, next := xtcpEndpointLogin(t, address, strictTLS, wire.ProtocolV2, xtcpControlTestToken, xtcpbinding.ALPN, "provider", login.RunID)
	require.Empty(t, next.Error)
	require.Equal(t, login.RunID, next.RunID)
	require.Len(t, next.XTCPControlID, 32)
	require.False(t, bytes.Equal(login.XTCPControlID, next.XTCPControlID))
	require.NoError(t, first.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = first.ReadMsg()
	require.Error(t, err)
	require.False(t, isNetTimeout(err), "旧实际控制连接应关闭，不能仅超时")
	waitForResult(t, firstCtl.doneCh, "旧实际控制退出")
	require.NotEmpty(t, precheck(replacement, "old-proxy-revoked").Error)
	xtcpEndpointProxy(t, replacement, "provider.bound", false)
	// 旧 owner 的延迟注销不能移除相同名字的新 owner。
	svr.rc.NatHoleController.CloseClient("provider.bound", login.XTCPControlID)
	oldProxy.Close()
	require.Empty(t, precheck(replacement, "new-proxy-still-present").Error)
	badKey.TransactionID = "old-control-replay"
	badKey.Timestamp = time.Now().Unix()
	badKey.SignalProof, err = xtcpbinding.SignalProof("public-proxy-secret", xtcpbinding.Visitor, badKey.ProxyName, badKey.ControlID, badKey.Nonce, badKey.SPKISHA256, badKey.Timestamp)
	require.NoError(t, err)
	r = xtcpEndpointVisitor(t, replacement, badKey)
	require.NotEmpty(t, r.Error)
	require.Empty(t, r.Sid)
	// 只声明另一个当前 control ID 也不能覆盖 actual caller 身份。
	badKey.TransactionID = "different-current-control"
	badKey.ControlID = intruderLogin.XTCPControlID
	badKey.SignalProof, err = xtcpbinding.SignalProof("public-proxy-secret", xtcpbinding.Visitor, badKey.ProxyName, badKey.ControlID, badKey.Nonce, badKey.SPKISHA256, badKey.Timestamp)
	require.NoError(t, err)
	require.NotEmpty(t, xtcpEndpointVisitor(t, replacement, badKey).Error)
	require.Empty(t, precheck(replacement, "rejections-keep-owner").Error)
}

func isNetTimeout(err error) bool { n, ok := err.(net.Error); return ok && n.Timeout() }
