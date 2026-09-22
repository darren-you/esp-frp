// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os/exec"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	frpnet "github.com/fatedier/frp/pkg/util/net"
)

func handshakeRound(path string, step int, seconds int64, scenario string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, fmt.Sprint(step), fmt.Sprint(seconds))
	input, err := cmd.StdinPipe()
	must(err)
	output, err := cmd.StdoutPipe()
	must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var length uint32
	must(binary.Read(output, binary.BigEndian, &length))
	if length > 4096 {
		panic("unbounded client request")
	}
	request := make([]byte, length)
	_, err = io.ReadFull(output, request)
	must(err)
	var magic bytes.Buffer
	must(wire.WriteMagic(&magic))
	if !bytes.HasPrefix(request, magic.Bytes()) {
		panic("bad client magic")
	}
	reader := bytes.NewBuffer(request[magic.Len():])
	frames := wire.NewConn(reader)
	clientFrame, err := frames.ReadFrame()
	must(err)
	if clientFrame.Type != wire.FrameTypeClientHello {
		panic("missing ClientHello")
	}
	var ch wire.ClientHello
	must(json.Unmarshal(clientFrame.Payload, &ch))
	must(wire.ValidateClientHello(ch))
	if ch.Bootstrap.Transport != "tcp" || !ch.Bootstrap.TLS || !ch.Bootstrap.TCPMux ||
		len(ch.Capabilities.Crypto.Algorithms) != 1 || ch.Capabilities.Crypto.Algorithms[0] != wire.AEADAlgorithmAES256GCM ||
		len(ch.Capabilities.Message.UDPPacketCodecs) != 0 {
		panic("unexpected capabilities")
	}
	var login msg.Login
	must(msg.NewV2ReadWriterWithConn(frames).ReadMsgInto(&login))
	if reader.Len() != 0 || login.PoolCount != 0 || login.Timestamp != seconds || login.Version != "esp-frp/0.1.0" ||
		login.Hostname != "board\"\\\n" || login.User != "公开测试" || login.ClientID != "fixture" || login.RunID != "old-id" ||
		login.Os != "esp-idf" || login.Arch != "riscv32" {
		panic("login field mismatch")
	}
	token := []byte("public-handshake-token")
	must(auth.NewTokenAuth(nil, string(token)).VerifyLogin(&login))
	sh, err := wire.NewServerHello(ch)
	must(err)
	if scenario == "algorithm" {
		sh.Selected.Crypto.Algorithm = wire.AEADAlgorithmXChaCha20Poly1305
	}
	if scenario == "random" {
		sh.Selected.Crypto.ServerRandom = sh.Selected.Crypto.ServerRandom[:31]
	}
	serverPayload, err := json.MarshalIndent(sh, "", "  ")
	must(err)
	var response bytes.Buffer
	serverFrames := wire.NewConn(&response)
	must(serverFrames.WriteFrame(&wire.Frame{Type: wire.FrameTypeServerHello, Payload: serverPayload}))
	resp := msg.LoginResp{Version: "0.71.0", RunID: "0123456789abcdef"}
	if scenario == "login-error" {
		resp.Error = "token rejected"
	}
	must(msg.NewV2ReadWriterWithConn(serverFrames).WriteMsg(&resp))
	contextPayload := serverPayload
	if scenario == "transcript" {
		contextPayload = append(append([]byte(nil), serverPayload...), ' ')
	}
	transcript := wire.HashCryptoTranscript(clientFrame.Payload, contextPayload)
	serverKey := token
	if scenario == "wrong-key" {
		serverKey = []byte("different-public-fixture")
	}
	crypto, err := frpnet.NewAEADCryptoReadWriter(&response, serverKey, frpnet.AEADCryptoRoleServer,
		wire.AEADAlgorithmAES256GCM, transcript)
	must(err)
	// First encrypted control message is appended directly after LoginResp.
	must(msg.NewV2ReadWriter(crypto).WriteMsg(&msg.Pong{}))
	body := response.Bytes()
	if scenario == "truncated" {
		body = body[:len(body)-1]
	}
	must(binary.Write(input, binary.BigEndian, uint32(len(body))))
	_, err = input.Write(body)
	must(err)
	must(input.Close())
	echo, err := io.ReadAll(output)
	must(err)
	err = cmd.Wait()
	if scenario != "ok" {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 10 || len(echo) != 0 {
			panic(fmt.Sprintf("%s: peer failure %v, bytes=%d, stderr=%s", scenario, err, len(echo), stderr.String()))
		}
		return
	}
	if err != nil {
		panic(fmt.Sprintf("handshake peer: %v %s", err, stderr.String()))
	}
	back, err := frpnet.NewAEADCryptoReadWriter(bytes.NewBuffer(echo), token, frpnet.AEADCryptoRoleServer,
		wire.AEADAlgorithmAES256GCM, transcript)
	must(err)
	var pong msg.Pong
	must(msg.NewV2ReadWriter(back).ReadMsgInto(&pong))
	if pong.Error != "" {
		panic("unexpected echoed Pong error")
	}
	var remaining [1]byte
	n, err := back.Read(remaining[:])
	if n != 0 || err != io.EOF {
		panic("unexpected encrypted echo tail")
	}
}

func runHandshake(path string) {
	for _, step := range []int{1, 7, 8, 15, 17, 128, 4096, 100000} {
		handshakeRound(path, step, 1790000000, "ok")
	}
	handshakeRound(path, 100000, math.MaxInt64, "ok")
	for _, scenario := range []string{"algorithm", "random", "login-error", "transcript", "wrong-key", "truncated"} {
		handshakeRound(path, 100000, 1790000000, scenario)
	}
	fmt.Println("Official FRP handshake: 9 login/AEAD round trips, 6 rejection cases passed")
}
