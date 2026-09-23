// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	frpnet "github.com/fatedier/frp/pkg/util/net"
	"github.com/hashicorp/yamux"
)

// Only the fixture's output sink changes, allowing exact coalescing and damage
// to an official encrypted record without implementing the crypto protocol.
type sessionFixtureIO struct {
	io.Reader
	io.Writer
}

func serveSessionFixture(raw net.Conn, cert tls.Certificate, mode string, work func(*yamux.Session, *msg.V2ReadWriter, string) error) error {
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(18 * time.Second)); err != nil {
		return err
	}
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err := conn.Handshake(); err != nil {
		return err
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	mux, err := yamux.Server(conn, cfg)
	if err != nil {
		return err
	}
	defer mux.Close()
	stream, err := mux.AcceptStream()
	if err != nil {
		return err
	}
	checked, v2, err := wire.CheckMagic(stream)
	if err != nil {
		return err
	}
	if !v2 {
		return fmt.Errorf("missing v2 magic")
	}
	frames := wire.NewConn(checked)
	chFrame, err := frames.ReadFrame()
	if err != nil {
		return err
	}
	var ch wire.ClientHello
	if err = json.Unmarshal(chFrame.Payload, &ch); err != nil {
		return err
	}
	if err = wire.ValidateClientHello(ch); err != nil {
		return err
	}
	loginRW := msg.NewV2ReadWriterWithConn(frames)
	var login msg.Login
	if err = loginRW.ReadMsgInto(&login); err != nil {
		return err
	}
	token := "public-session-token"
	authenticator := auth.NewTokenAuth([]v1.AuthScope{v1.AuthScopeHeartBeats}, token)
	if err = authenticator.VerifyLogin(&login); err != nil {
		return err
	}
	if (work == nil && login.ClientID != "fixture-client-"+mode+"-0") ||
		(work != nil && !strings.HasPrefix(login.ClientID, "fixture-work-proxy-"+mode+"-")) {
		return fmt.Errorf("borrowed login configuration")
	}
	// Read until owner teardown so FIN/close_notify is actually observed before
	// this fixture closes its TCP connection.
	awaitStop := func() error { _, _ = io.Copy(io.Discard, stream); return nil }
	if mode == "fixture-login-fin" {
		if err = stream.Close(); err != nil {
			return err
		}
		return awaitStop()
	}
	sh, err := wire.NewServerHello(ch)
	if err != nil {
		return err
	}
	shBytes, err := json.Marshal(sh)
	if err != nil {
		return err
	}
	var prefix bytes.Buffer
	serverFrames := wire.NewConn(&prefix)
	if err = serverFrames.WriteFrame(&wire.Frame{Type: wire.FrameTypeServerHello, Payload: shBytes}); err != nil {
		return err
	}
	if err = msg.NewV2ReadWriterWithConn(serverFrames).WriteMsg(&msg.LoginResp{Version: "0.71.0", RunID: "fixture-run"}); err != nil {
		return err
	}
	duplex := &sessionFixtureIO{Reader: stream, Writer: &prefix}
	crypto, err := frpnet.NewAEADCryptoReadWriter(duplex, []byte(token), frpnet.AEADCryptoRoleServer,
		wire.AEADAlgorithmAES256GCM, wire.HashCryptoTranscript(chFrame.Payload, shBytes))
	if err != nil {
		return err
	}
	control := msg.NewV2ReadWriter(crypto)
	if mode == "fixture-tail" {
		if err = control.WriteMsg(&msg.ReqWorkConn{}); err != nil {
			return err
		}
	}
	// The first encrypted record can share one Yamux DATA frame with LoginResp.
	if _, err = stream.Write(prefix.Bytes()); err != nil {
		return err
	}
	duplex.Writer = stream
	var proxy msg.NewProxy
	if err = control.ReadMsgInto(&proxy); err != nil {
		return err
	}
	validName := proxy.ProxyName == "fixture-control-"+mode+"-0"
	if work != nil {
		validName = strings.HasPrefix(proxy.ProxyName, "fixture-work-proxy-"+mode+"-") && proxy.ProxyName == login.ClientID
	}
	if !validName || proxy.ProxyType != "tcp" || proxy.UseEncryption || proxy.UseCompression || proxy.RemotePort != 0 {
		return fmt.Errorf("incorrect or borrowed NewProxy configuration")
	}
	if mode == "fixture-register-timeout" {
		return awaitStop()
	}
	response := &msg.NewProxyResp{ProxyName: proxy.ProxyName, RemoteAddr: ":12345"}
	writeJSON := func(id byte, payload []byte) error {
		return wire.NewConn(crypto).WriteFrame(&wire.Frame{Type: wire.FrameTypeMessage, Payload: append([]byte{0, id}, payload...)})
	}
	switch mode {
	case "fixture-bad-name":
		response.ProxyName = "wrong-proxy"
	case "fixture-bad-type":
		p, _ := json.Marshal(proxy.ProxyName)
		if err = writeJSON(4, []byte(fmt.Sprintf(`{"proxy_name":%s,"remote_addr":123}`, p))); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-bad-duplicate":
		p, _ := json.Marshal(proxy.ProxyName)
		if err = writeJSON(4, []byte(fmt.Sprintf(`{"proxy_name":%s,"remote_addr":":12345","err\u006fr":"","error":""}`, p))); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-bad-unknown":
		if err = writeJSON(99, []byte(`{}`)); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-frame-truncated":
		// Authenticated plaintext contains an incomplete wire header.
		if _, err = crypto.Write([]byte{0, 0, 0}); err != nil {
			return err
		}
		if err = stream.Close(); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-fin":
		if err = stream.Close(); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-tls-fin":
		return conn.Close()
	case "fixture-aead-truncated", "fixture-aead-tamper":
		var captured bytes.Buffer
		duplex.Writer = &captured
		if err = control.WriteMsg(response); err != nil {
			return err
		}
		duplex.Writer = stream
		data := captured.Bytes()
		if mode == "fixture-aead-truncated" {
			data = data[:len(data)-1]
		} else {
			data[len(data)-1] ^= 1
		}
		if _, err = stream.Write(data); err != nil {
			return err
		}
		if err = stream.Close(); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-record":
		p, _ := json.Marshal(response)
		// A 4096-byte wire payload crosses every intermediate 1 KiB staging
		// boundary; add a second frame in the same authenticated record.
		p = append(p[:len(p)-1], []byte(strings.Repeat(" ", 4094-len(p)))...)
		p = append(p, '}')
		var plaintext bytes.Buffer
		if err = wire.NewConn(&plaintext).WriteFrame(&wire.Frame{Type: wire.FrameTypeMessage, Payload: append([]byte{0, 4}, p...)}); err != nil {
			return err
		}
		if err = msg.NewV2ReadWriter(&plaintext).WriteMsg(&msg.ReqWorkConn{}); err != nil {
			return err
		}
		if _, err = crypto.Write(plaintext.Bytes()); err != nil {
			return err
		}
	}
	if mode != "fixture-record" {
		if err = control.WriteMsg(response); err != nil {
			return err
		}
	}
	if mode == "fixture-bad-name" {
		return awaitStop()
	}
	var ping msg.Ping
	if err = control.ReadMsgInto(&ping); err != nil {
		return err
	}
	if err = authenticator.VerifyPing(&ping); err != nil {
		return err
	}
	switch mode {
	case "fixture-pong-timeout":
		return awaitStop()
	case "fixture-work-overflow":
		var requests bytes.Buffer
		for range 4 {
			if err = msg.NewV2ReadWriter(&requests).WriteMsg(&msg.ReqWorkConn{}); err != nil {
				return err
			}
		}
		if err = msg.NewV2ReadWriter(&requests).WriteMsg(&msg.Pong{}); err != nil {
			return err
		}
		if _, err = crypto.Write(requests.Bytes()); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-pong-error":
		if err = control.WriteMsg(&msg.Pong{Error: "fixture rejection"}); err != nil {
			return err
		}
		return awaitStop()
	case "fixture-bad-pong":
		var plaintext bytes.Buffer
		for range 2 {
			if err = msg.NewV2ReadWriter(&plaintext).WriteMsg(&msg.Pong{}); err != nil {
				return err
			}
		}
		if _, err = crypto.Write(plaintext.Bytes()); err != nil {
			return err
		}
		return awaitStop()
	}
	if err = control.WriteMsg(&msg.Pong{}); err != nil {
		return err
	}
	if work != nil {
		return work(mux, control, proxy.ProxyName)
	}
	return awaitStop()
}

func runSessionFixtures(path, dir string) {
	cert, ca := certificate("ok")
	caPath := filepath.Join(dir, "fixture-ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	modes := []string{"fixture-tail", "fixture-record", "fixture-login-fin", "fixture-bad-name", "fixture-bad-type",
		"fixture-bad-duplicate", "fixture-bad-unknown", "fixture-frame-truncated", "fixture-fin", "fixture-tls-fin",
		"fixture-aead-truncated", "fixture-aead-tamper", "fixture-pong-error", "fixture-bad-pong", "fixture-work-overflow",
		"fixture-register-timeout", "fixture-pong-timeout"}
	for _, mode := range modes {
		listener := localListener()
		result := make(chan error, 1)
		go func() {
			raw, err := listener.Accept()
			if err == nil {
				err = serveSessionFixture(raw, cert, mode, nil)
			}
			result <- err
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		cmd := exec.CommandContext(ctx, path, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), caPath, mode, "1", "0")
		output, err := cmd.CombinedOutput()
		cancel()
		_ = listener.Close()
		if err != nil {
			panic(fmt.Sprintf("session %s: %v\n%s", mode, err, output))
		}
		select {
		case err = <-result:
			must(err)
		case <-time.After(time.Second):
			panic("fixture did not stop")
		}
		fmt.Print(string(output))
	}
	fmt.Printf("Official protocol APIs: %d composed-session tail, framing, rejection and deadline fixtures passed\n", len(modes))
}
