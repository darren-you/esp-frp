// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"github.com/hashicorp/yamux"
)

func udpWorkRecovery(mux *yamux.Session, control *msg.V2ReadWriter, proxy string, phase chan<- string, resume <-chan struct{}) error {
	authenticator := auth.NewTokenAuth([]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, "public-session-token")
	controlDone := make(chan error, 1)
	go func() {
		for {
			var ping msg.Ping
			if err := control.ReadMsgInto(&ping); err != nil {
				controlDone <- nil
				return
			}
			if err := authenticator.VerifyPing(&ping); err != nil {
				controlDone <- err
				return
			}
			if err := control.WriteMsg(&msg.Pong{}); err != nil {
				controlDone <- nil
				return
			}
		}
	}()
	for round := byte(1); round <= 2; round++ {
		if err := control.WriteMsg(&msg.ReqWorkConn{}); err != nil {
			return err
		}
		stream, err := mux.AcceptStream()
		if err != nil {
			return err
		}
		checked, v2, err := wire.CheckMagic(stream)
		if err != nil {
			return err
		}
		if !v2 {
			return fmt.Errorf("UDP work missing v2 magic")
		}
		var work msg.NewWorkConn
		if err = msg.NewV2ReadWriter(checked).ReadMsgInto(&work); err != nil {
			return err
		}
		if work.RunID != "fixture-run" {
			return fmt.Errorf("UDP work run identity changed")
		}
		if err = authenticator.VerifyNewWorkConn(&work); err != nil {
			return err
		}
		remote := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 12345}
		packet := &msg.UDPPacket{RemoteAddr: remote, Content: []byte{0xda, round, 0, 0xff}}
		var tail bytes.Buffer
		if err = msg.NewV2ReadWriter(&tail).WriteMsg(&msg.StartWorkConn{ProxyName: proxy,
			SrcAddr: "203.0.113.8", SrcPort: 12345, DstAddr: "203.0.113.200", DstPort: 65000}); err != nil {
			return err
		}
		packets, err := msg.NewUDPPacketReadWriter(&tail, wire.ProtocolV2, wire.UDPPacketCodecBinary)
		if err != nil {
			return err
		}
		if err = packets.WriteMsg(packet); err != nil {
			return err
		}
		// Work admission and the first complete business datagram share a write.
		if _, err = stream.Write(tail.Bytes()); err != nil {
			return err
		}
		packets, err = msg.NewUDPPacketReadWriter(stream, wire.ProtocolV2, wire.UDPPacketCodecBinary)
		if err != nil {
			return err
		}
		if err = stream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		var response msg.UDPPacket
		if err = packets.ReadMsgInto(&response); err != nil {
			return err
		}
		if !bytes.Equal(response.Content, packet.Content) || response.RemoteAddr.String() != remote.String() {
			return fmt.Errorf("UDP work response crossed a stream/source boundary")
		}
		if round == 1 {
			// There is no public Reset in the pinned Go Yamux. An invalid packet
			// exercises the client's own RST, which the official peer observes.
			body, err := msg.EncodeUDPPacketBinary(packet)
			if err != nil {
				return err
			}
			body[0] |= 0x80
			payload := append([]byte{0, byte(msg.V2TypeUDPPacketBinary)}, body...)
			if err = wire.NewConn(stream).WriteFrame(&wire.Frame{Type: wire.FrameTypeMessage, Payload: payload}); err != nil {
				return err
			}
			_, err = packets.ReadMsg()
			if !errors.Is(err, yamux.ErrConnectionReset) {
				return fmt.Errorf("invalid UDP metadata did not trigger client RST: %v", err)
			}
			phase <- "RESET"
			select {
			case <-resume:
			case <-time.After(5 * time.Second):
				return fmt.Errorf("missing UDP cleanup barrier")
			}
		} else {
			phase <- "RECOVERED"
		}
	}
	return <-controlDone
}

func runUDPWorkRecovery(path string) {
	local := udpListener()
	defer local.Close()
	go udpEcho(local)
	listener := localListener()
	defer listener.Close()
	cert, ca := certificate("ok")
	dir, err := os.MkdirTemp("", "esp-frp-udp-work-")
	must(err)
	defer os.RemoveAll(dir)
	caPath := filepath.Join(dir, "ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	localPort := local.LocalAddr().(*net.UDPAddr).Port
	proxy := fmt.Sprintf("fixture-udp-proxy-%d-1500", localPort)
	phase, resume := make(chan string, 2), make(chan struct{})
	done := make(chan error, 1)
	var accepted net.Conn
	acceptedReady := make(chan struct{})
	go func() {
		raw, err := listener.Accept()
		accepted = raw
		close(acceptedReady)
		if err != nil {
			done <- err
			return
		}
		done <- serveSessionFixture(raw, cert, sessionFixtureOptions{mode: "udp-work-reset", token: "public-session-token",
			clientID: proxy, proxyName: proxy, proxyType: "udp", timeout: 25 * time.Second},
			func(mux *yamux.Session, control *msg.V2ReadWriter, proxy string) error {
				return udpWorkRecovery(mux, control, proxy, phase, resume)
			})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), caPath, strconv.Itoa(localPort), "1500")
	input, err := cmd.StdinPipe()
	must(err)
	output, err := cmd.StdoutPipe()
	must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = listener.Close()
		<-acceptedReady
		if accepted != nil {
			_ = accepted.Close()
		}
	}()
	scanner := bufio.NewScanner(output)
	scan := func(expected string) string {
		if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), expected) {
			panic("UDP recovery peer missing " + expected + ": " + stderr.String())
		}
		return scanner.Text()
	}
	scan("READY :")
	waitPhase := func(expected string) {
		select {
		case value := <-phase:
			if value != expected {
				panic("wrong UDP work phase: " + value)
			}
		case err := <-done:
			panic(fmt.Sprintf("UDP recovery fixture ended early: %v\n%s", err, stderr.String()))
		case <-time.After(8 * time.Second):
			panic("UDP recovery phase timeout")
		}
	}
	waitPhase("RESET")
	_, err = input.Write([]byte{'z'})
	must(err)
	scan("DRAINED")
	_, err = input.Write([]byte{'s'})
	must(err)
	var active, remotes int
	var requests, received, sent, dropped, expired uint64
	_, err = fmt.Sscanf(scan("STATE "), "STATE %d %d %d %d %d %d %d", &active, &remotes,
		&requests, &received, &sent, &dropped, &expired)
	must(err)
	if active != 0 || remotes != 0 || requests != 1 || received != 1 || sent != 1 || dropped != 0 {
		panic("UDP RST cleanup/counters were incomplete")
	}
	close(resume)
	waitPhase("RECOVERED")
	_, err = input.Write([]byte{'s'})
	must(err)
	_, err = fmt.Sscanf(scan("STATE "), "STATE %d %d %d %d %d %d %d", &active, &remotes,
		&requests, &received, &sent, &dropped, &expired)
	must(err)
	if active != 1 || remotes != 1 || requests != 2 || received != 2 || sent != 2 {
		panic("UDP source/stream was not recreated with preserved counters")
	}
	_, err = input.Write([]byte{'q'})
	must(err)
	must(input.Close())
	if err = cmd.Wait(); err != nil {
		panic(fmt.Sprintf("UDP recovery peer cleanup: %v\n%s", err, stderr.String()))
	}
	<-acceptedReady
	if accepted != nil {
		_ = accepted.Close()
	}
	select {
	case err := <-done:
		must(err)
	case <-time.After(5 * time.Second):
		panic("UDP fixture owner did not exit")
	}
	fmt.Print(stderr.String())
	fmt.Println("Official API UDP fixture: malformed metadata caused client RST, old local socket retired, same authenticated control rebuilt work, StartWorkConn tail and counters preserved")
}
