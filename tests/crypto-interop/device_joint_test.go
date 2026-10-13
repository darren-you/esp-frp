// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	frpnet "github.com/fatedier/frp/pkg/util/net"
	"github.com/hashicorp/yamux"
)

const jointTestRequestID = "44444444-4444-4444-8444-444444444444"

func jointTestConfig(t *testing.T) (deviceJointConfig, string, []byte) {
	t.Helper()
	d := deviceTestConfig(t)
	image := bytes.Repeat([]byte{0xe9, 13, 5, 67}, 16384)
	hash := sha256.Sum256(image)
	c := deviceJointConfig{ListenIPv4: d.ListenIPv4, ListenPort: d.ListenPort, AllowedPeerIPv4: d.DeviceIPv4,
		CertificateFile: d.CertificateFile, PrivateKeyFile: d.PrivateKeyFile, Token: d.Token,
		ClientID: "11111111-1111-4111-8111-111111111111", ProxyName: "joint-base", RemotePort: d.RemotePort,
		BootID: "22222222-2222-4222-8222-222222222222", OperationID: "33333333-3333-4333-8333-333333333333",
		ImageSHA256: hex.EncodeToString(hash[:]), ImageSizeBytes: int64(len(image)), TriggerPhase: "prepare", TimeoutMS: 10000, EvidenceDir: d.EvidenceDirectory}
	return c, d.CAFile, image
}

func jointTestPhase(c deviceJointConfig) string {
	return fmt.Sprintf("ESP_BASE_OTA_PHASE boot_id=%s operation_id=%s request_id=%s phase=prepare boundary=begin snapshot_started_us=100 snapshot_finished_us=101 result=pending stage_uncertain=0 ota_completed_claim_count=10 frp_completed_claim_count=1 config_completed_claim_count=3 ota_counters_valid=1 frp_counters_valid=1 config_counters_valid=1\n", c.BootID, c.OperationID, jointTestRequestID)
}

func TestJointRecordAndPhase(t *testing.T) {
	plain, err := jointMaximumRecord()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 65536 {
		t.Fatal(len(plain))
	}
	frames := wire.NewConn(bytes.NewBuffer(plain))
	count := 0
	for {
		frame, err := frames.ReadFrame()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != wire.FrameTypeMessage || len(frame.Payload) > 4096 || binary.BigEndian.Uint16(frame.Payload[:2]) != msg.V2TypeReqWorkConn {
			t.Fatal("not a legal bounded ReqWorkConn frame")
		}
		var fields map[string]any
		if json.Unmarshal(frame.Payload[2:], &fields) != nil || len(fields) != 0 {
			t.Fatal("nonempty request")
		}
		count++
	}
	if count != 16 {
		t.Fatal(count)
	}
	c, _, _ := jointTestConfig(t)
	line := jointTestPhase(c)
	if err = jointPhase(line, c, jointTestRequestID); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(line, c.BootID, c.ClientID, 1), strings.Replace(line, "boundary=begin", "boundary=end", 1), strings.Replace(line, "frp_counters_valid=1", "frp_counters_valid=0", 1), strings.Replace(line, "snapshot_finished_us=101", "snapshot_finished_us=99", 1), line + " extra=1"} {
		if jointPhase(bad, c, jointTestRequestID) == nil {
			t.Fatal("accepted invalid phase", bad)
		}
	}
}

func TestJointConfigAndSingleUse(t *testing.T) {
	c, _, _ := jointTestConfig(t)
	path := filepath.Join(t.TempDir(), "joint.json")
	data, _ := json.Marshal(c)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadDeviceJoint(path); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append([]byte(`{"remote_port":1234,`), data[1:]...), append(data, []byte("{}")...), bytes.Replace(data, []byte(`"listen_ipv4":"127.0.0.1"`), []byte(`"listen_ipv4":"0.0.0.0"`), 1), append([]byte(`{"unknown":true,`), data[1:]...), bytes.Replace(data, []byte(`"remote_port"`), []byte(`"REMOTE_PORT"`), 1)} {
		_ = os.WriteFile(path, bad, 0600)
		if _, _, err := loadDeviceJoint(path); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	_ = os.WriteFile(path, data, 0600)
	_ = os.Chmod(path, 0644)
	if _, _, err := loadDeviceJoint(path); err == nil {
		t.Fatal("accepted public permissions")
	}
	r := &jointRuntime{c: c, startSeen: true}
	req := &http.Request{Method: "PUT", RequestURI: "/api/v1/ota-images/" + c.OperationID, ContentLength: c.ImageSizeBytes}
	if kind, err := r.admit(req, nil); err != nil || kind != "put" {
		t.Fatal(kind, err)
	}
	if _, err := r.admit(req, nil); err == nil {
		t.Fatal("second PUT accepted")
	}
	query := jointTestCommand(c, "ota.result")
	request := &http.Request{Method: "POST", RequestURI: "/api/v1/commands/ota-result"}
	if _, err := r.admit(request, query); err != nil {
		t.Fatal(err)
	}
	if _, err := r.admit(request, bytes.ReplaceAll(query, []byte(c.OperationID), []byte(c.BootID))); err == nil {
		t.Fatal("foreign operation accepted")
	}
	request.RequestURI = "/api/v1/commands/restart"
	if _, err := r.admit(request, query); err == nil {
		t.Fatal("restart accepted")
	}
}

func TestJointTriggerSingleUseAndNoSignal(t *testing.T) {
	for _, repeat := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(repeat), func(t *testing.T) {
			c, _, _ := jointTestConfig(t)
			_ = os.Mkdir(c.EvidenceDir, 0700)
			f, err := os.CreateTemp(t.TempDir(), "events")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			calls := 0
			r := &jointRuntime{c: c, j: &jointJournal{file: f, started: time.Now()}, ctx: ctx, cancel: cancel, putActive: true, requestID: jointTestRequestID, record: func(p []byte) ([]byte, error) { calls++; return []byte("fixture ciphertext"), nil }}
			r.trigger(strings.NewReader(strings.Repeat(jointTestPhase(c), repeat)))
			if calls != min(1, repeat) {
				t.Fatal("record replay", calls)
			}
			if (repeat == 2) != (ctx.Err() != nil) {
				t.Fatal("duplicate/no-signal cancellation", context.Cause(ctx))
			}
		})
	}
}

func jointTestCommand(c deviceJointConfig, command string) []byte {
	value := map[string]any{"protocol_version": 1, "device_id": c.ClientID, "request_id": jointTestRequestID, "command": command}
	if command == "ota.start" {
		value["target_boot_id"] = c.BootID
		value["parameters"] = map[string]any{"operation_id": c.OperationID, "sha256": c.ImageSHA256, "image_size_bytes": c.ImageSizeBytes}
	}
	if command == "ota.result" {
		value["parameters"] = map[string]any{"operation_id": c.OperationID}
	}
	data, _ := json.Marshal(value)
	return data
}

func jointTestHTTP(c deviceJointConfig, method, path string, body []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", c.RemotePort), time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	header := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: fixture\r\nContent-Length: %d\r\nX-ESP-Management-Tag: %s\r\nConnection: close\r\n\r\n", method, path, len(body), strings.Repeat("a", 64))
	if _, err = conn.Write(append([]byte(header), body...)); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

// A software peer uses official TLS/Yamux/wire/AEAD/Token implementations.
// Its local HTTP handler is explicitly fake; no MCU or Base qualification.
func jointTestPeer(c deviceJointConfig, caPath string, handler func(*http.Request) error) (*yamux.Session, *atomic.Int32, error) {
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp4", fmt.Sprintf("%s:%d", c.ListenIPv4, c.ListenPort), &tls.Config{RootCAs: pool, ServerName: "frp.fixture.invalid", MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, nil, err
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	mux, err := yamux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	failed := func(err error) (*yamux.Session, *atomic.Int32, error) { mux.Close(); return nil, nil, err }
	s, err := mux.OpenStream()
	if err != nil {
		return failed(err)
	}
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	if err = wire.WriteMagic(s); err != nil {
		return failed(err)
	}
	hello, err := wire.NewClientHello(wire.BootstrapInfo{Transport: "tcp", TLS: true, TCPMux: true})
	if err != nil {
		return failed(err)
	}
	hello.Capabilities.Crypto.Algorithms = []string{wire.AEADAlgorithmAES256GCM}
	ch, _ := json.Marshal(hello)
	frames := wire.NewConn(s)
	if err = frames.WriteFrame(&wire.Frame{Type: wire.FrameTypeClientHello, Payload: ch}); err != nil {
		return failed(err)
	}
	authenticator := auth.NewTokenAuth([]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, c.Token)
	login := msg.Login{ClientID: c.ClientID, Timestamp: time.Now().Unix()}
	_ = authenticator.SetLogin(&login)
	if err = msg.NewV2ReadWriterWithConn(frames).WriteMsg(&login); err != nil {
		return failed(err)
	}
	sh, err := frames.ReadFrame()
	if err != nil {
		return failed(err)
	}
	var response msg.LoginResp
	if err = msg.NewV2ReadWriterWithConn(frames).ReadMsgInto(&response); err != nil {
		return failed(err)
	}
	if response.Version != "esp-frp-joint-fixture" {
		return failed(fmt.Errorf("fixture impersonated official FRPS"))
	}
	crypto, err := frpnet.NewAEADCryptoReadWriter(s, []byte(c.Token), frpnet.AEADCryptoRoleClient, wire.AEADAlgorithmAES256GCM, wire.HashCryptoTranscript(ch, sh.Payload))
	if err != nil {
		return failed(err)
	}
	control := msg.NewV2ReadWriter(crypto)
	if err = control.WriteMsg(&msg.NewProxy{ProxyName: c.ProxyName, ProxyType: "tcp", RemotePort: c.RemotePort}); err != nil {
		return failed(err)
	}
	var proxy msg.NewProxyResp
	if err = control.ReadMsgInto(&proxy); err != nil {
		return failed(err)
	}
	if proxy.RemoteAddr != fmt.Sprintf(":%d", c.RemotePort) {
		return failed(fmt.Errorf("wrong RemotePort"))
	}
	ping := msg.Ping{}
	_ = authenticator.SetPing(&ping)
	if err = control.WriteMsg(&ping); err != nil {
		return failed(err)
	}
	var pong msg.Pong
	if err = control.ReadMsgInto(&pong); err != nil {
		return failed(err)
	}
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	requests := make(chan struct{}, 3)
	counter := new(atomic.Int32)
	go func() {
		defer close(requests)
		for {
			message, err := control.ReadMsg()
			if err != nil {
				return
			}
			if _, ok := message.(*msg.Pong); ok {
				continue
			}
			if _, ok := message.(*msg.ReqWorkConn); !ok {
				return
			}
			counter.Add(1)
			select {
			case requests <- struct{}{}:
			default:
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-mux.CloseChan():
				return
			case <-ticker.C:
				ping := msg.Ping{}
				_ = authenticator.SetPing(&ping)
				if control.WriteMsg(&ping) != nil {
					return
				}
			}
		}
	}()
	go func() {
		slots := make(chan struct{}, 3)
		var wg sync.WaitGroup
		defer wg.Wait()
		for range requests {
			select {
			case slots <- struct{}{}:
			case <-mux.CloseChan():
				return
			}
			stream, err := mux.OpenStream()
			if err != nil {
				return
			}
			_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
			if err = wire.WriteMagic(stream); err != nil {
				stream.Close()
				return
			}
			work := msg.NewWorkConn{RunID: response.RunID}
			_ = authenticator.SetNewWorkConn(&work)
			messages := msg.NewV2ReadWriter(stream)
			if err = messages.WriteMsg(&work); err != nil {
				stream.Close()
				return
			}
			var start msg.StartWorkConn
			if err = messages.ReadMsgInto(&start); err != nil {
				stream.Close()
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer stream.Close()
				defer func() { <-slots }()
				req, err := http.ReadRequest(bufio.NewReader(stream))
				if err != nil {
					return
				}
				if err = handler(req); err != nil {
					return
				}
				_, _ = io.WriteString(stream, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
			}()
		}
	}()
	return mux, counter, nil
}

func jointTestWait(t *testing.T, fn func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for !fn() {
		if time.Now().After(end) {
			t.Fatal("bounded software observation timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestJointTLSHTTPRecordOverlap(t *testing.T) {
	for _, trigger := range []bool{false, true} {
		t.Run(fmt.Sprintf("trigger=%t", trigger), func(t *testing.T) { jointTestHTTPOverlap(t, trigger) })
	}
}

func jointTestHTTPOverlap(t *testing.T, trigger bool) {
	c, ca, image := jointTestConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(c)
	_ = os.WriteFile(path, data, 0600)
	input, signal := io.Pipe()
	defer signal.Close()
	if !trigger {
		_ = signal.Close() // Forwarding-only: no signal, not an implicit trigger.
	}
	done := make(chan error, 1)
	go func() { done <- runDeviceJoint(path, input) }()
	eventsPath := filepath.Join(c.EvidenceDir, "events.jsonl")
	eventSeen := func(event string) bool {
		data, _ := os.ReadFile(eventsPath)
		return bytes.Contains(data, []byte(`"event":"`+event+`"`))
	}
	jointTestWait(t, func() bool { return eventSeen("listener_ready") })
	putArrived, queryArrived := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var putDigest string
	mux, counter, err := jointTestPeer(c, ca, func(req *http.Request) error {
		if req.Header.Get("X-ESP-Management-Tag") != strings.Repeat("a", 64) {
			return fmt.Errorf("modified auth header")
		}
		if req.Method == "PUT" {
			close(putArrived)
			<-release
		}
		if req.URL.Path == "/api/v1/commands/ota-result" {
			close(queryArrived)
			<-release
		}
		body, err := io.ReadAll(req.Body)
		if req.URL.Path == "/api/v1/commands/ota-start" && !bytes.Equal(body, jointTestCommand(c, "ota.start")) {
			return fmt.Errorf("modified start body")
		}
		if req.URL.Path == "/api/v1/commands/ota-result" && !bytes.Equal(body, jointTestCommand(c, "ota.result")) {
			return fmt.Errorf("modified original-operation query body")
		}
		if req.Method == "PUT" {
			hash := sha256.Sum256(body)
			putDigest = hex.EncodeToString(hash[:])
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	jointTestWait(t, func() bool { return eventSeen("joint_proxy_ready") })
	if response, err := jointTestHTTP(c, "POST", "/api/v1/commands/ota-start", jointTestCommand(c, "ota.start")); err != nil || !bytes.Contains(response, []byte("200 OK")) {
		t.Fatal(string(response), err)
	}
	putDone, queryDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := jointTestHTTP(c, "PUT", "/api/v1/ota-images/"+c.OperationID, image); putDone <- err }()
	jointTestWait(t, func() bool {
		select {
		case <-putArrived:
			return true
		default:
			return false
		}
	})
	go func() {
		_, err := jointTestHTTP(c, "POST", "/api/v1/commands/ota-result", jointTestCommand(c, "ota.result"))
		queryDone <- err
	}()
	jointTestWait(t, func() bool {
		select {
		case <-queryArrived:
			return true
		default:
			return false
		}
	})
	jointTestWait(t, func() bool {
		data, _ := os.ReadFile(eventsPath)
		return bytes.Count(data, []byte(`"event":"spare_authenticated"`)) >= 4
	})
	if trigger {
		if _, err = io.WriteString(signal, jointTestPhase(c)); err != nil {
			t.Fatal(err)
		}
		jointTestWait(t, func() bool { return eventSeen("record_write_end") && counter.Load() >= 20 })
	} else if counter.Load() != 4 || eventSeen("record_write_begin") {
		t.Fatal("forwarding-only injected a record")
	}
	close(release)
	if err = <-putDone; err != nil {
		t.Fatal(err)
	}
	if err = <-queryDone; err != nil {
		t.Fatal(err)
	}
	if putDigest != c.ImageSHA256 {
		t.Fatal("body changed", putDigest)
	}
	encoded, err := os.ReadFile(filepath.Join(c.EvidenceDir, "control-ciphertext.bin"))
	if trigger {
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) != 65556 || binary.BigEndian.Uint32(encoded[:4]) != 65552 {
			t.Fatal("not exactly one maximum AEAD record", len(encoded))
		}
	} else if !os.IsNotExist(err) {
		t.Fatal("forwarding-only manufactured ciphertext")
	}
	_ = mux.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("peer disconnect incorrectly qualified as device success")
		}
	case <-time.After(time.Second):
		t.Fatal("fixture did not clean up")
	}
	var report map[string]any
	result, _ := os.ReadFile(filepath.Join(c.EvidenceDir, "result.json"))
	if json.Unmarshal(result, &report) != nil {
		t.Fatal(string(result))
	}
	if report["record_written"] != trigger || report["peak_fixture_active"] != float64(2) || report["put_bytes_forwarded"] != float64(len(image)) || report["query_responses_forwarded"] != float64(1) || report["official_frps"] != false || report["r5_qualified"] != false {
		t.Fatal(report)
	}
	for _, port := range []int{c.ListenPort, c.RemotePort} {
		l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal("listener leaked", err)
		}
		l.Close()
	}
}

func TestJointRejectsBorrowedAuthentication(t *testing.T) {
	for _, field := range []string{"token", "client_id", "remote_port"} {
		t.Run(field, func(t *testing.T) {
			c, ca, _ := jointTestConfig(t)
			data, _ := json.Marshal(c)
			path := filepath.Join(t.TempDir(), "config.json")
			_ = os.WriteFile(path, data, 0600)
			done := make(chan error, 1)
			go func() { done <- runDeviceJoint(path, io.NopCloser(strings.NewReader(""))) }()
			jointTestWait(t, func() bool {
				data, _ := os.ReadFile(filepath.Join(c.EvidenceDir, "events.jsonl"))
				return bytes.Contains(data, []byte(`"event":"listener_ready"`))
			})
			peerConfig := c
			switch field {
			case "token":
				peerConfig.Token = "wrong-fixture-token"
			case "client_id":
				peerConfig.ClientID = c.BootID
			case "remote_port":
				peerConfig.RemotePort++
			}
			if mux, _, err := jointTestPeer(peerConfig, ca, func(*http.Request) error { return nil }); err == nil {
				mux.Close()
				t.Fatal("accepted borrowed identity")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("auth rejection reported success")
				}
			case <-time.After(time.Second):
				t.Fatal("auth failure did not clean up")
			}
			events, _ := os.ReadFile(filepath.Join(c.EvidenceDir, "events.jsonl"))
			if bytes.Contains(events, []byte(`"event":"joint_proxy_ready"`)) {
				t.Fatal("unauthenticated proxy opened")
			}
		})
	}
}

func TestJointPartialPUTEvidence(t *testing.T) {
	c, ca, image := jointTestConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(c)
	_ = os.WriteFile(path, data, 0600)
	done := make(chan error, 1)
	go func() { done <- runDeviceJoint(path, io.NopCloser(strings.NewReader(""))) }()
	eventSeen := func(event string) bool {
		data, _ := os.ReadFile(filepath.Join(c.EvidenceDir, "events.jsonl"))
		return bytes.Contains(data, []byte(`"event":"`+event+`"`))
	}
	jointTestWait(t, func() bool { return eventSeen("listener_ready") })
	mux, _, err := jointTestPeer(c, ca, func(req *http.Request) error { _, err := io.Copy(io.Discard, req.Body); return err })
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	jointTestWait(t, func() bool { return eventSeen("joint_proxy_ready") })
	if _, err = jointTestHTTP(c, "POST", "/api/v1/commands/ota-start", jointTestCommand(c, "ota.start")); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: c.RemotePort})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "PUT /api/v1/ota-images/%s HTTP/1.1\r\nHost: fixture\r\nContent-Length: %d\r\nX-ESP-Management-Tag: %s\r\nConnection: close\r\n\r\n", c.OperationID, len(image), strings.Repeat("a", 64))
	_, _ = conn.Write(image[:1024])
	_ = conn.CloseWrite()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("partial PUT succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("truncated upload did not close fixture")
	}
	var report map[string]any
	data, _ = os.ReadFile(filepath.Join(c.EvidenceDir, "result.json"))
	if json.Unmarshal(data, &report) != nil || report["put_bytes_forwarded"] != float64(1024) || report["record_written"] != false {
		t.Fatal(string(data))
	}
	first, ok := report["first_cancellation"].(map[string]any)
	if !ok || first["stage"] != "put_body_read" || !strings.Contains(first["reason"].(string), "EOF") {
		t.Fatal("first upload failure lost during teardown", first)
	}
	events, _ := os.ReadFile(filepath.Join(c.EvidenceDir, "events.jsonl"))
	prefix := sha256.Sum256(image[:1024])
	if !bytes.Contains(events, []byte(hex.EncodeToString(prefix[:]))) || !bytes.Contains(events, []byte(`"complete":false`)) {
		t.Fatal("missing forwarded prefix evidence")
	}
}

func TestJointDeadlineNoDevice(t *testing.T) {
	c, _, _ := jointTestConfig(t)
	c.TimeoutMS = 1000
	data, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(path, data, 0600)
	started := time.Now()
	if err := runDeviceJoint(path, io.NopCloser(strings.NewReader(""))); err == nil {
		t.Fatal("deadline incorrectly succeeded")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("unbounded listener")
	}
	if _, err := os.Stat(filepath.Join(c.EvidenceDir, "result.json")); err != nil {
		t.Fatal("missing interrupted evidence", err)
	}
}
