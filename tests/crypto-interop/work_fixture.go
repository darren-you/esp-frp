// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/hashicorp/yamux"
)

func workFixtureProtocol(mux *yamux.Session, control *msg.V2ReadWriter, proxy, mode string, resume <-chan struct{}, result chan<- error) error {
	if err := control.WriteMsg(&msg.ReqWorkConn{}); err != nil {
		return err
	}
	if mode == "work-stall" || mode == "work-shared" {
		if err := control.WriteMsg(&msg.ReqWorkConn{}); err != nil {
			return err
		}
	}
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
	run := func() error {
		stream, err := mux.AcceptStream()
		if err != nil {
			return err
		}
		conn, v2, err := wire.CheckMagic(stream)
		if err != nil {
			return err
		}
		if !v2 {
			return fmt.Errorf("work magic missing")
		}
		messages := msg.NewV2ReadWriter(conn)
		var work msg.NewWorkConn
		if err = messages.ReadMsgInto(&work); err != nil {
			return err
		}
		if work.RunID != "fixture-run" {
			return fmt.Errorf("wrong work run ID")
		}
		if err = authenticator.VerifyNewWorkConn(&work); err != nil {
			return err
		}
		if mode == "work-spare" {
			<-resume
		}
		start := &msg.StartWorkConn{ProxyName: proxy, SrcAddr: "203.0.113.19", DstAddr: "203.0.113.200", SrcPort: 1234, DstPort: 65000}
		var prefix bytes.Buffer
		switch mode {
		case "work-wrong-name":
			start.ProxyName = "unconfigured-proxy"
		case "work-error":
			start.Error = "fixture rejects work"
		case "work-oversized":
			if err = wire.NewConn(&prefix).WriteFrame(&wire.Frame{Type: wire.FrameTypeMessage, Payload: make([]byte, 4097)}); err != nil {
				return err
			}
		case "work-truncated":
			prefix.Write([]byte{0, 3, 0})
		case "work-frame-timeout":
			prefix.Write([]byte{0, 3, 0})
		case "work-bad-port", "work-duplicate":
			payload := fmt.Sprintf(`{"proxy_name":%q,"dst_port":65536}`, proxy)
			if mode == "work-duplicate" {
				payload = fmt.Sprintf(`{"proxy_name":%q,"proxy_name":%q}`, proxy, proxy)
			}
			if err = wire.NewConn(&prefix).WriteFrame(&wire.Frame{Type: wire.FrameTypeMessage, Payload: append([]byte{0, 8}, []byte(payload)...)}); err != nil {
				return err
			}
		default:
		}
		if prefix.Len() == 0 {
			if err = msg.NewV2ReadWriter(&prefix).WriteMsg(start); err != nil {
				return err
			}
		}
		bad := mode == "work-wrong-name" || mode == "work-error" || mode == "work-oversized" || mode == "work-truncated" || mode == "work-bad-port" || mode == "work-duplicate" || mode == "work-frame-timeout"
		if mode == "work-tail-fin" || mode == "work-spare" {
			prefix.Write(workPattern(41, false))
		}
		_, err = stream.Write(prefix.Bytes())
		if mode == "work-shared" {
			if err != nil {
				return err
			}
			second, err := mux.AcceptStream()
			if err != nil {
				return err
			}
			checked, v2, err := wire.CheckMagic(second)
			if err != nil {
				return err
			}
			if !v2 {
				return fmt.Errorf("shared handshake magic missing")
			}
			rw := msg.NewV2ReadWriter(checked)
			var next msg.NewWorkConn
			if err = rw.ReadMsgInto(&next); err != nil {
				return err
			}
			if next.RunID != "fixture-run" {
				return fmt.Errorf("shared handshake run ID mismatch")
			}
			if err = authenticator.VerifyNewWorkConn(&next); err != nil {
				return err
			}
			var frame bytes.Buffer
			if err = msg.NewV2ReadWriter(&frame).WriteMsg(start); err != nil {
				return err
			}
			payload := frame.Bytes()
			cut := len(payload) / 2
			if _, err = second.Write(payload[:cut]); err != nil {
				return err
			}
			// The driver resets the first active local socket while this
			// next StartWorkConn is only partially received.
			<-resume
			if _, err = second.Write(append(payload[cut:], workPattern(41, false)...)); err != nil {
				return err
			}
			if err = second.Close(); err != nil {
				return err
			}
			response, err := io.ReadAll(second)
			if err != nil {
				return err
			}
			if !bytes.Equal(response, workPattern(41, true)) {
				return fmt.Errorf("active cleanup corrupted waiting handshake or tail")
			}
			var one [1]byte
			if n, err := stream.Read(one[:]); n != 0 || err == nil {
				return fmt.Errorf("first stream was not reset")
			}
			return nil
		}
		if mode == "work-stall" {
			if err != nil {
				return err
			}
			stalled := make(chan error, 1)
			go func() { _, err := stream.Write(make([]byte, 32*1024*1024)); stalled <- err }()
			second, err := mux.AcceptStream()
			if err != nil {
				return err
			}
			checked, v2, err := wire.CheckMagic(second)
			if err != nil {
				return err
			}
			if !v2 {
				return fmt.Errorf("second work magic missing")
			}
			rw := msg.NewV2ReadWriter(checked)
			var next msg.NewWorkConn
			if err = rw.ReadMsgInto(&next); err != nil {
				return err
			}
			if next.RunID != "fixture-run" {
				return fmt.Errorf("second run ID mismatch")
			}
			if err = authenticator.VerifyNewWorkConn(&next); err != nil {
				return err
			}
			if err = rw.WriteMsg(start); err != nil {
				return err
			}
			payload := bytes.Repeat([]byte{0x7b}, 64)
			if _, err = second.Write(payload); err != nil {
				return err
			}
			echo, err := io.ReadAll(second)
			if err != nil {
				return err
			}
			if !bytes.Equal(echo, payload) {
				return fmt.Errorf("healthy stream lost behind stalled stream")
			}
			if err = second.Close(); err != nil {
				return err
			}
			if err = <-stalled; err == nil {
				return fmt.Errorf("stalled destination accepted entire payload")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if bad {
			if mode == "work-truncated" {
				if err = stream.Close(); err != nil {
					return err
				}
			}
			var p [1]byte
			n, err := stream.Read(p[:])
			if n != 0 || err == nil {
				return fmt.Errorf("invalid work was not reset")
			}
			return nil
		}
		if mode == "work-idle" {
			var p [1]byte
			_, err = stream.Read(p[:])
			if err == nil {
				return fmt.Errorf("idle work stayed open")
			}
			return nil
		}
		if mode == "work-tail-fin" || mode == "work-spare" {
			if err = stream.Close(); err != nil {
				return err
			}
			response, err := io.ReadAll(stream)
			if err != nil {
				return err
			}
			if !bytes.Equal(response, workPattern(41, true)) {
				return fmt.Errorf("response after work FIN mismatch: %d", len(response))
			}
			return nil
		}
		// The local endpoint sends FIN first. The reverse path must still carry
		// bytes sent only after the client has delivered that FIN to this peer.
		response, err := io.ReadAll(stream)
		if err != nil {
			return err
		}
		if !bytes.Equal(response, workPattern(42, true)) {
			return fmt.Errorf("local FIN payload mismatch")
		}
		if _, err = stream.Write(workPattern(42, false)); err != nil {
			return err
		}
		return stream.Close()
	}
	err := run()
	result <- err
	if err != nil {
		return err
	}
	return <-controlDone
}
func localWorkFixture(listener net.Listener, mode string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	if mode == "work-local-fin" {
		if _, err = conn.Write(workPattern(42, true)); err != nil {
			return err
		}
		if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
			return err
		}
		p, err := io.ReadAll(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(p, workPattern(42, false)) {
			return fmt.Errorf("request after local FIN mismatch")
		}
		return nil
	}
	p, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, workPattern(41, false)) {
		return fmt.Errorf("StartWorkConn tail mismatch: %d", len(p))
	}
	if _, err = conn.Write(workPattern(41, true)); err != nil {
		return err
	}
	return conn.(*net.TCPConn).CloseWrite()
}
func runWorkFixtures(path, dir string) {
	cert, ca := certificate("ok")
	caPath := filepath.Join(dir, "work-ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	modes := []string{"work-tail-fin", "work-local-fin", "work-spare", "work-wrong-name", "work-error", "work-oversized", "work-truncated", "work-bad-port", "work-duplicate", "work-frame-timeout", "work-idle", "work-stall", "work-shared"}
	for _, mode := range modes {
		listener := localListener()
		local := localListener()
		resume := make(chan struct{})
		protocolResult := make(chan error, 1)
		done := make(chan error, 1)
		accepted := make(chan net.Conn, 1)
		go func() {
			raw, err := listener.Accept()
			if err == nil {
				accepted <- raw
				err = serveSessionFixture(raw, cert, mode, func(m *yamux.Session, c *msg.V2ReadWriter, p string) error {
					return workFixtureProtocol(m, c, p, mode, resume, protocolResult)
				})
			}
			done <- err
		}()
		h := startWorkHarness(path, caPath, listener.Addr().(*net.TCPAddr).Port, local.Addr().(*net.TCPAddr).Port, mode)
		h.address()
		localResult := make(chan error, 1)
		bad := mode == "work-wrong-name" || mode == "work-error" || mode == "work-oversized" || mode == "work-truncated" || mode == "work-bad-port" || mode == "work-duplicate" || mode == "work-frame-timeout"
		var held net.Conn
		if mode == "work-idle" || mode == "work-stall" || mode == "work-shared" {
			must(local.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)))
			var err error
			held, err = local.Accept()
			must(err)
			if mode == "work-shared" {
				go func() { localResult <- localWorkFixture(local, mode) }()
			}
			if mode == "work-stall" {
				go func() {
					conn, err := local.Accept()
					if err != nil {
						localResult <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					p := make([]byte, 64)
					_, err = io.ReadFull(conn, p)
					if err == nil {
						_, err = conn.Write(p)
					}
					if err == nil {
						err = conn.(*net.TCPConn).CloseWrite()
					}
					localResult <- err
				}()
			}
		} else if !bad {
			go func() { localResult <- localWorkFixture(local, mode) }()
		}
		if mode == "work-spare" {
			h.await(func(s workState) bool { return s.waiting == 1 && s.active == 0 })
			_, err := h.input.Write([]byte{'t'})
			must(err)
			time.Sleep(200 * time.Millisecond)
			s := h.state()
			if s.waiting != 1 || s.active != 0 || s.failed != 0 {
				panic(fmt.Sprintf("spare expired: %+v", s))
			}
			close(resume)
		}
		if mode == "work-idle" {
			h.await(func(s workState) bool { return s.active == 1 })
			_, err := h.input.Write([]byte{'t'})
			must(err)
		}
		if mode == "work-frame-timeout" {
			h.await(func(s workState) bool { return s.waiting == 1 })
			_, err := h.input.Write([]byte{'t'})
			must(err)
		}
		if mode == "work-shared" {
			h.await(func(s workState) bool { return s.active == 1 && s.waiting == 1 })
			// Keep the partial frame pending across several owner turns.
			time.Sleep(200 * time.Millisecond)
			must(held.(*net.TCPConn).SetLinger(0))
			must(held.Close())
			h.await(func(s workState) bool { return s.active == 0 && s.waiting == 1 && s.failed == 1 })
			close(resume)
		}
		if bad || mode == "work-idle" || mode == "work-stall" || mode == "work-shared" {
			expected := -2
			switch mode {
			case "work-error":
				expected = -23
			case "work-oversized":
				expected = -3
			case "work-truncated":
				expected = -5
			case "work-idle":
				expected = -9
			case "work-frame-timeout":
				expected = -9
			case "work-stall":
				expected = -8
			case "work-shared":
				expected = -17
			}
			s := h.await(func(s workState) bool { return s.failed == 1 && s.active == 0 })
			if s.reason != expected && !(mode == "work-stall" && s.reason == -9) {
				panic(fmt.Sprintf("%s unexpected failure: %+v", mode, s))
			}
			if mode == "work-stall" || mode == "work-shared" {
				must(<-localResult)
				h.await(func(s workState) bool { return s.completed == 1 && s.failed == 1 && s.active == 0 })
			}
			if bad {
				must(local.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)))
				unexpected, err := local.Accept()
				if err == nil {
					unexpected.Close()
					panic("invalid work reached local target")
				}
			}
		} else {
			must(<-localResult)
			h.await(func(s workState) bool { return s.completed == 1 && s.active == 0 && s.failed == 0 })
		}
		select {
		case err := <-protocolResult:
			must(err)
		case <-time.After(10 * time.Second):
			panic("work protocol did not finish")
		}
		h.finish()
		// The peer has exited after checking its fd baseline. Closing the
		// fixture listener alone does not close its accepted TCP connection;
		// release that owned socket before joining its control reader.
		_ = (<-accepted).Close()
		h.cleanup()
		if held != nil {
			held.Close()
		}
		local.Close()
		listener.Close()
		select {
		case err := <-done:
			must(err)
		case <-time.After(time.Second):
			panic("work fixture did not stop")
		}
		fmt.Printf("Official work API fixture: %s passed\n", mode)
	}
}
