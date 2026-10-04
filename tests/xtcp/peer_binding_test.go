// SPDX-License-Identifier: Apache-2.0
package xtcp_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/fatedier/frp/client/visitor"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/quic-go/quic-go"
)

func udp(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func quicOptions() v1.QUICOptions {
	return v1.QUICOptions{MaxIdleTimeout: 5, MaxIncomingStreams: 2, KeepalivePeriod: 1}
}

// This intentionally asserts the fixed official behavior, rather than treating
// an unrelated peer's successful handshake as a secure XTCP acceptance result.
func TestOfficialVisitorAcceptsUnboundSelfSignedPeer(t *testing.T) {
	serverSocket := udp(t)
	serverTLS, err := transport.NewServerTLSConfig("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.ClientAuth != tls.NoClientCert || len(serverTLS.Certificates) != 1 {
		t.Fatal("official empty-path server TLS no longer matches the fixed baseline")
	}
	serverTLS.NextProtos = []string{"frp"}
	listener, err := quic.Listen(serverSocket, serverTLS, &quic.Config{MaxIdleTimeout: 5 * time.Second, MaxIncomingStreams: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	result := make(chan error, 1)
	const message = "public-wrong-peer-no-sid-no-secret"
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			result <- err
			return
		}
		defer conn.CloseWithError(0, "fixture complete")
		stream, err := conn.AcceptStream(ctx)
		if err == nil {
			body := make([]byte, len(message))
			_, err = io.ReadFull(stream, body)
			if err == nil && !bytes.Equal(body, []byte(message)) {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				_, err = stream.Write([]byte("received"))
			}
			if err == nil {
				ack := make([]byte, len("done"))
				_, err = io.ReadFull(stream, ack)
				if err == nil && string(ack) != "done" {
					err = io.ErrUnexpectedEOF
				}
			}
		}
		result <- err
	}()
	common := &v1.ClientCommonConfig{}
	common.Transport.QUIC = quicOptions()
	session := visitor.NewQUICTunnelSession(common)
	t.Cleanup(session.Close)
	// No fixture disables verification: this is the actual official visitor's
	// Init implementation, whose signature carries neither SID nor peer key.
	if err = session.Init(udp(t), serverSocket.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	conn, err := session.OpenConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, len("received"))
	if _, err = io.ReadFull(conn, ack); err != nil || string(ack) != "received" {
		t.Fatalf("unrelated peer receipt: %q %v", ack, err)
	}
	if _, err = conn.Write([]byte("done")); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	t.Log("fixed official visitor established QUIC and exchanged bytes with an unrelated dynamic self-signed peer; no SID, proxy, role or peer key was supplied to its TLS session")
}

func makeHole(t *testing.T, packetSID string, packetKey []byte, accepted bool) {
	t.Helper()
	receiver, sender := udp(t), udp(t)
	key := []byte("public-nat-hole-secret")
	result := make(chan error, 1)
	returned := make(chan *net.UDPAddr, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		_, remote, err := nathole.MakeHole(ctx, receiver, &msg.NatHoleResp{Sid: "public-correct-sid", Protocol: "quic",
			DetectBehavior: msg.NatHoleDetectBehavior{Role: nathole.DetectRoleReceiver, ReadTimeoutMs: 100}}, key)
		returned <- remote
		result <- err
	}()
	packet, err := nathole.EncodeMessage(&msg.NatHoleSid{Sid: packetSID, TransactionID: "public-transaction", Response: true}, packetKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sender.WriteToUDP(packet, receiver.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("fixed official hole detection abandoned its socket")
	}
	remote := <-returned
	if accepted {
		if err != nil || remote == nil || remote.String() != sender.LocalAddr().String() {
			t.Fatalf("correct SID/key: peer=%v error=%v", remote, err)
		}
	} else if err == nil || remote != nil {
		t.Fatalf("wrong SID/key accepted: peer=%v error=%v", remote, err)
	}
}
func TestOfficialHoleDetectionChecksSIDAndSecret(t *testing.T) {
	makeHole(t, "public-correct-sid", []byte("public-nat-hole-secret"), true)
	makeHole(t, "public-wrong-sid", []byte("public-nat-hole-secret"), false)
	makeHole(t, "public-correct-sid", []byte("wrong-public-secret"), false)
	t.Log("UDP detection rejected wrong SID and wrong secret, and accepted correct SID/key from a source absent from candidate addresses; this proof is not bound to later QUIC TLS")
}
