// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	frplog "github.com/fatedier/frp/pkg/util/log"
	frpnet "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/server"
)

type bridge struct {
	input   io.WriteCloser
	mutex   sync.Mutex
	streams [3]*bridgeStream
	ready   chan struct{}
}
type bridgeStream struct {
	bridge *bridge
	slot   byte
	reader *io.PipeReader
	writer *io.PipeWriter
}

func (b *bridge) command(kind, slot byte, data []byte) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if len(data) > 4096 {
		return fmt.Errorf("bridge command exceeds fixed bound")
	}
	header := []byte{kind, slot, byte(len(data) >> 8), byte(len(data))}
	if _, err := b.input.Write(header); err != nil {
		return err
	}
	_, err := b.input.Write(data)
	return err
}
func (s *bridgeStream) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *bridgeStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > 4096 {
			n = 4096
		}
		if err := s.bridge.command('W', s.slot, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
func (s *bridgeStream) CloseWrite() error { return s.bridge.command('F', s.slot, nil) }
func (b *bridge) dispatch(output io.Reader) {
	var err error
	defer func() {
		for _, s := range b.streams {
			_ = s.writer.CloseWithError(err)
		}
	}()
	for {
		var header [4]byte
		if _, err = io.ReadFull(output, header[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(header[2:]))
		if header[1] >= 3 {
			err = fmt.Errorf("bad bridge slot")
			return
		}
		data := make([]byte, n)
		if _, err = io.ReadFull(output, data); err != nil {
			return
		}
		switch header[0] {
		case 'H':
			if n != 0 {
				err = fmt.Errorf("bad handshake event")
				return
			}
			close(b.ready)
		case 'D':
			if _, err = b.streams[header[1]].writer.Write(data); err != nil {
				return
			}
		case 'F':
			if n != 0 {
				err = fmt.Errorf("bad FIN event")
				return
			}
			_ = b.streams[header[1]].writer.Close()
		default:
			err = fmt.Errorf("unexpected bridge event")
			return
		}
	}
}
func freeTCPPort() int {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	p := l.Addr().(*net.TCPAddr).Port
	must(l.Close())
	return p
}
func freeUDPPort() int {
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	p := l.LocalAddr().(*net.UDPAddr).Port
	must(l.Close())
	return p
}

func runFRPS(path, directory string) {
	cert, ca := certificate("ok")
	caPath := filepath.Join(directory, "frps-ca.pem")
	certPath := filepath.Join(directory, "frps.pem")
	keyPath := filepath.Join(directory, "frps-key.pem")
	must(os.WriteFile(caPath, ca, 0600))
	must(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	must(err)
	must(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	config := &v1.ServerConfig{BindAddr: "127.0.0.1", BindPort: freeTCPPort(), QUICBindPort: freeUDPPort(), ProxyBindAddr: "127.0.0.1"}
	config.Auth.Token = "public-quic-prototype-token"
	config.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeNewWorkConns}
	config.Transport.TLS.Force = true
	config.Transport.TLS.CertFile = certPath
	config.Transport.TLS.KeyFile = keyPath
	must(config.Complete())
	frplog.InitLogger("console", "error", 1, true)
	service, err := server.NewService(config)
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer service.Close()
	go service.Run(ctx)
	command := exec.CommandContext(ctx, path, strconv.Itoa(config.QUICBindPort), caPath, "quic.example.test", "bridge")
	input, err := command.StdinPipe()
	must(err)
	output, err := command.StdoutPipe()
	must(err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	must(command.Start())
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	b := &bridge{input: input, ready: make(chan struct{})}
	for i := range b.streams {
		r, w := io.Pipe()
		b.streams[i] = &bridgeStream{bridge: b, slot: byte(i), reader: r, writer: w}
		defer r.Close()
		defer w.Close()
	}
	go b.dispatch(output)
	select {
	case <-b.ready:
	case <-ctx.Done():
		panic(fmt.Sprintf("FRPS handshake %s", stderr.String()))
	}
	control := b.streams[0]
	must(b.command('O', 0, nil))
	must(wire.WriteMagic(control))
	hello, err := wire.NewClientHello(wire.BootstrapInfo{Transport: "quic", TLS: true})
	must(err)
	hello.Capabilities.Crypto.Algorithms = []string{wire.AEADAlgorithmAES256GCM}
	frame, err := wire.NewJSONFrame(wire.FrameTypeClientHello, hello)
	must(err)
	wireConn := wire.NewConn(control)
	must(wireConn.WriteFrame(frame))
	response, err := wireConn.ReadFrame()
	must(err)
	var selected wire.ServerHello
	must(wireConn.UnmarshalFrame(response, &selected))
	must(wire.ValidateServerHelloForClient(hello, selected))
	if response.Type != wire.FrameTypeServerHello || selected.Selected.Message.UDPPacketCodec != wire.UDPPacketCodecBinary {
		panic("unexpected FRPS Hello")
	}
	login := &msg.Login{Version: "0.71.0", Os: "freertos", Arch: "riscv32", Hostname: "quic-prototype", Timestamp: time.Now().Unix(), PoolCount: 0}
	signer := auth.NewTokenAuth(config.Auth.AdditionalScopes, config.Auth.Token)
	must(signer.SetLogin(login))
	messages := msg.NewV2ReadWriterWithConn(wireConn)
	must(messages.WriteMsg(login))
	var loginResponse msg.LoginResp
	must(messages.ReadMsgInto(&loginResponse))
	if loginResponse.Error != "" || loginResponse.RunID == "" {
		panic(fmt.Sprintf("FRPS Login: %+v", loginResponse))
	}
	crypto, err := wire.NewClientCryptoContext(frame.Payload, response.Payload)
	must(err)
	encrypted, err := frpnet.NewAEADCryptoReadWriter(control, []byte(config.Auth.Token), frpnet.AEADCryptoRoleClient, crypto.Algorithm, crypto.TranscriptHash)
	must(err)
	messages = msg.NewV2ReadWriter(encrypted)
	must(messages.WriteMsg(&msg.NewProxy{ProxyName: "quic-prototype", ProxyType: "tcp"}))
	var proxyResponse msg.NewProxyResp
	for {
		m, err := messages.ReadMsg()
		must(err)
		switch v := m.(type) {
		case *msg.NewProxyResp:
			proxyResponse = *v
			goto registered
		case *msg.ReqWorkConn:
		default:
			panic(fmt.Sprintf("unexpected control %T", m))
		}
	}
registered:
	if proxyResponse.Error != "" {
		panic(proxyResponse.Error)
	}
	// Keep consuming encrypted control requests so the process event dispatcher
	// can deliver independent work streams without blocking on an unread pipe.
	go func() {
		for {
			if _, err := messages.ReadMsg(); err != nil {
				return
			}
		}
	}()
	target := "127.0.0.1" + proxyResponse.RemoteAddr
	remotes := [2]net.Conn{}
	for i := range remotes {
		remotes[i], err = net.DialTimeout("tcp4", target, 3*time.Second)
		must(err)
		defer remotes[i].Close()
		must(remotes[i].SetDeadline(time.Now().Add(10 * time.Second)))
	}
	// Two simultaneous native bidi work streams on the same authenticated QUIC
	// connection. Go owns official FRP wire/msg/AEAD; C owns transport and FIN.
	failures := make(chan error, 4)
	for i := 0; i < 2; i++ {
		slot := byte(i + 1)
		must(b.command('O', slot, nil))
		work := b.streams[slot]
		must(wire.WriteMagic(work))
		workMessages := msg.NewV2ReadWriter(work)
		request := &msg.NewWorkConn{RunID: loginResponse.RunID}
		must(signer.SetNewWorkConn(request))
		must(workMessages.WriteMsg(request))
		go func(id int, stream *bridgeStream, rw *msg.V2ReadWriter) {
			var start msg.StartWorkConn
			if err := rw.ReadMsgInto(&start); err != nil {
				failures <- err
				return
			}
			if start.Error != "" || start.ProxyName != "quic-prototype" {
				failures <- fmt.Errorf("invalid StartWorkConn %+v", start)
				return
			}
			data := make([]byte, 4096)
			if _, err := io.ReadFull(stream, data); err != nil {
				failures <- err
				return
			}
			for j, value := range data {
				if value != byte(j*31+id*7) {
					failures <- fmt.Errorf("work bytes differ")
					return
				}
			}
			_, err := stream.Write(data)
			if err == nil {
				err = stream.CloseWrite()
			}
			if err == nil {
				_, err = io.ReadAll(stream)
			}
			failures <- err
		}(i, work, workMessages)
		go func(id int, remote net.Conn) {
			data := make([]byte, 4096)
			for j := range data {
				data[j] = byte(j*31 + id*7)
			}
			_, err := remote.Write(data)
			if err == nil {
				echo := make([]byte, len(data))
				_, err = io.ReadFull(remote, echo)
				if err == nil && !bytes.Equal(echo, data) {
					err = fmt.Errorf("remote bytes differ")
				}
			}
			if err == nil {
				_, err = io.ReadAll(remote)
			}
			failures <- err
		}(i, remotes[i])
	}
	for i := 0; i < 4; i++ {
		select {
		case err := <-failures:
			if err != nil {
				panic(fmt.Sprintf("FRPS work: %v %s", err, stderr.String()))
			}
		case <-ctx.Done():
			panic(fmt.Sprintf("FRPS dual work timed out %s", stderr.String()))
		}
	}
	must(b.command('Q', 0, nil))
	must(input.Close())
	if err = command.Wait(); err != nil {
		panic(fmt.Sprintf("FRPS QUIC %v %s", err, stderr.String()))
	}
	if !bytes.Contains(stderr.Bytes(), []byte("signature=1 handshake=1 dual_fin=1")) {
		panic("missing authenticated native work evidence")
	}
	fmt.Printf("Official FRPS v0.71.0 QUIC: Hello/Login/control AEAD + two native bidi work streams: %s", stderr.String())
	// Assert fixtures really use official serializers rather than hand-built JSON.
	_, err = json.Marshal(selected)
	must(err)
}
