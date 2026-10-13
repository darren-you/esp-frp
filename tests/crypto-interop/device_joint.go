// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/hashicorp/yamux"
)

// This is an isolated protocol fixture, NOT an official FRPS or a deployment.
// The board's fixed local HTTP target, HMAC, signed image and deadlines remain
// owned by Base. The fixture neither opens a serial device nor owns an HMAC key.
type deviceJointConfig struct {
	ListenIPv4      string `json:"listen_ipv4"`
	ListenPort      int    `json:"listen_port"`
	AllowedPeerIPv4 string `json:"allowed_peer_ipv4"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
	Token           string `json:"token"`
	ClientID        string `json:"client_id"`
	ProxyName       string `json:"proxy_name"`
	RemotePort      int    `json:"remote_port"`
	BootID          string `json:"boot_id"`
	OperationID     string `json:"operation_id"`
	ImageSHA256     string `json:"image_sha256"`
	ImageSizeBytes  int64  `json:"image_size_bytes"`
	TriggerPhase    string `json:"trigger_phase"`
	TimeoutMS       uint32 `json:"timeout_ms"`
	EvidenceDir     string `json:"evidence_directory"`
}

var jointUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Reject duplicate top-level keys as well as unknown fields. Configuration is
// flat; nested request metadata is independently authenticated by the device.
func jointDecodeConfig(data []byte, c *deviceJointConfig) error {
	allowed := map[string]bool{}
	t := reflect.TypeFor[deviceJointConfig]()
	for i := 0; i < t.NumField(); i++ {
		allowed[t.Field(i).Tag.Get("json")] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return fmt.Errorf("joint config must be an object")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return fmt.Errorf("unknown, duplicate or noncanonical joint config field")
		}
		seen[name] = true
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(c); err != nil {
		return err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing joint config data")
	}
	return nil
}

func loadDeviceJoint(path string) (deviceJointConfig, []byte, error) {
	var c deviceJointConfig
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return c, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return c, nil, fmt.Errorf("joint config must be private regular JSON, at most 16384 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return c, nil, err
	}
	if len(data) > 16384 {
		return c, nil, fmt.Errorf("joint config grew beyond limit")
	}
	if err = jointDecodeConfig(data, &c); err != nil {
		return c, nil, err
	}
	if !deviceIPv4(c.ListenIPv4) || !deviceIPv4(c.AllowedPeerIPv4) ||
		!devicePort(c.ListenPort) || !devicePort(c.RemotePort) || c.ListenPort == c.RemotePort ||
		!jointUUID.MatchString(c.ClientID) || !jointUUID.MatchString(c.BootID) || !jointUUID.MatchString(c.OperationID) ||
		c.Token == "" || len(c.Token) > 1024 || c.ProxyName == "" || len(c.ProxyName) > 128 ||
		c.TimeoutMS < 1000 || c.TimeoutMS > 300000 || c.ImageSizeBytes < 288 || c.ImageSizeBytes > 0x1e0000 ||
		!filepath.IsAbs(c.CertificateFile) || !filepath.IsAbs(c.PrivateKeyFile) || !filepath.IsAbs(c.EvidenceDir) {
		return c, nil, fmt.Errorf("invalid joint identity, address, files or finite budget")
	}
	digest, err := hex.DecodeString(c.ImageSHA256)
	if err != nil || len(digest) != 32 || strings.ToLower(c.ImageSHA256) != c.ImageSHA256 {
		return c, nil, fmt.Errorf("joint image digest must be complete lowercase SHA256")
	}
	if c.TriggerPhase != "retire_inactive" && c.TriggerPhase != "prepare" && c.TriggerPhase != "select" {
		return c, nil, fmt.Errorf("unsupported OTA trigger phase")
	}
	return c, data, nil
}

type jointJournal struct {
	mu      sync.Mutex
	file    *os.File
	started time.Time
}

func (j *jointJournal) event(kind string, fields map[string]any) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"], fields["elapsed_us"] = kind, time.Since(j.started).Microseconds()
	fields["observed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	if err := json.NewEncoder(j.file).Encode(fields); err != nil {
		return err
	}
	return j.file.Sync()
}

func jointFile(dir, name string, data []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

// Exactly sixteen legal <=4096-byte control payloads in ONE 65536-byte AEAD
// plaintext record. Excess ReqWorkConn admissions use the client's existing
// bounded pending/rejection policy; this does not mean sixteen live sockets.
func jointMaximumRecord() ([]byte, error) {
	var plain bytes.Buffer
	for plain.Len() < 65536 {
		n := min(4104, 65536-plain.Len())
		if n < 12 {
			return nil, fmt.Errorf("invalid joint record tail")
		}
		payload := binary.BigEndian.AppendUint16(nil, msg.V2TypeReqWorkConn)
		payload = append(payload, '{')
		payload = append(payload, bytes.Repeat([]byte{' '}, n-12)...)
		payload = append(payload, '}')
		if err := wire.NewConn(&plain).WriteFrame(&wire.Frame{Type: wire.FrameTypeMessage, Payload: payload}); err != nil {
			return nil, err
		}
	}
	return plain.Bytes(), nil
}

// Accept ONE complete original observer line, supplied by the external UART
// owner. Host receipt is not a calibrated MCU timestamp or proof of peak load.
func jointPhase(line string, c deviceJointConfig, requestID string) error {
	parts := strings.Fields(line)
	if len(parts) != 16 || parts[0] != "ESP_BASE_OTA_PHASE" {
		return fmt.Errorf("expected one complete OTA phase line")
	}
	fields := map[string]string{}
	for _, part := range parts[1:] {
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 || fields[pair[0]] != "" {
			return fmt.Errorf("invalid or duplicate OTA phase field")
		}
		fields[pair[0]] = pair[1]
	}
	want := map[string]string{"boot_id": c.BootID, "operation_id": c.OperationID, "request_id": requestID,
		"phase": c.TriggerPhase, "boundary": "begin", "result": "pending", "stage_uncertain": "0",
		"ota_counters_valid": "1", "frp_counters_valid": "1", "config_counters_valid": "1"}
	for k, v := range want {
		if fields[k] != v {
			return fmt.Errorf("OTA phase identity or boundary mismatch: %s", k)
		}
	}
	var times [2]uint64
	for i, k := range []string{"snapshot_started_us", "snapshot_finished_us"} {
		n, err := strconv.ParseUint(fields[k], 10, 63)
		if err != nil {
			return fmt.Errorf("invalid phase time")
		}
		times[i] = n
	}
	if times[1] < times[0] {
		return fmt.Errorf("reversed phase time")
	}
	for _, k := range []string{"ota_completed_claim_count", "frp_completed_claim_count", "config_completed_claim_count"} {
		if _, err := strconv.ParseUint(fields[k], 10, 32); err != nil {
			return fmt.Errorf("invalid phase counter")
		}
	}
	return nil
}

type jointRuntime struct {
	c                                                       deviceJointConfig
	j                                                       *jointJournal
	ctx                                                     context.Context
	cancel                                                  context.CancelCauseFunc
	deadline                                                time.Time
	mux                                                     *yamux.Session
	control                                                 *msg.V2ReadWriter
	record                                                  func([]byte) ([]byte, error)
	writeMu                                                 sync.Mutex
	mu                                                      sync.Mutex
	startSeen, putSeen, putActive, triggered, recordWritten bool
	requestID                                               string
	putBytes                                                int64
	queryCount, queryCompleted, active, peakActive          int
	pool                                                    chan *yamux.Stream
	wg                                                      sync.WaitGroup
}

type jointFailure struct {
	stage string
	err   error
}

func (e *jointFailure) Error() string { return e.stage + ": " + e.err.Error() }
func (e *jointFailure) Unwrap() error { return e.err }

func (r *jointRuntime) fail(stage string, err error) {
	r.cancel(&jointFailure{stage: stage, err: err})
}

func jointFailureFields(err error) map[string]any {
	// All fixture-originated cancellations go through fail. An unwrapped
	// cause comes from the parent deadline/signal context (including Go's
	// signal-specific cause, which need not wrap context.Canceled).
	stage := "context"
	var failure *jointFailure
	if errors.As(err, &failure) {
		stage = failure.stage
	}
	root := err
	for errors.Unwrap(root) != nil {
		root = errors.Unwrap(root)
	}
	return map[string]any{"stage": stage, "reason": fmt.Sprint(err), "error_type": fmt.Sprintf("%T", root)}
}

func (r *jointRuntime) log(kind string, fields map[string]any) {
	if err := r.j.event(kind, fields); err != nil {
		r.fail("evidence_write", err)
	}
}

// A query's original deadline belongs to its HTTP/work connection. It must
// not cancel another stream's PUT or the authenticated control session.
// Evidence failures, protocol faults and control errors remain session-wide.
func (r *jointRuntime) workError(kind, stage string, streamID uint32, err error) {
	var timeout net.Error
	if kind == "query" && errors.As(err, &timeout) && timeout.Timeout() {
		r.log("query_timeout", map[string]any{"stream_id": streamID, "stage": stage, "reason": err.Error(), "error_type": fmt.Sprintf("%T", timeout), "scope": "work_connection"})
		return
	}
	r.fail(kind+"."+stage, err)
}

func (r *jointRuntime) message(value any) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return r.control.WriteMsg(value)
}

func (r *jointRuntime) controls() {
	for {
		var ping msg.Ping
		if err := r.control.ReadMsgInto(&ping); err != nil {
			r.fail("control_read", err)
			return
		}
		verifier := auth.NewTokenAuth([]v1.AuthScope{v1.AuthScopeHeartBeats}, r.c.Token)
		if err := verifier.VerifyPing(&ping); err != nil {
			r.fail("heartbeat_authentication", err)
			return
		}
		if err := r.message(&msg.Pong{}); err != nil {
			r.fail("control_write", err)
			return
		}
		r.log("authenticated_pong", nil)
	}
}

func (r *jointRuntime) workStreams() {
	for {
		s, err := r.mux.AcceptStream()
		if err != nil {
			r.fail("work_accept", err)
			return
		}
		err = func() error {
			_ = s.SetDeadline(minTime(r.deadline, time.Now().Add(5*time.Second)))
			conn, v2, err := wire.CheckMagic(s)
			if err != nil || !v2 {
				return fmt.Errorf("work v2 magic required")
			}
			var work msg.NewWorkConn
			if err = msg.NewV2ReadWriter(conn).ReadMsgInto(&work); err != nil {
				return err
			}
			verifier := auth.NewTokenAuth([]v1.AuthScope{v1.AuthScopeNewWorkConns}, r.c.Token)
			if work.RunID != "fixture-run" || verifier.VerifyNewWorkConn(&work) != nil {
				return fmt.Errorf("work identity/authentication failed")
			}
			_ = s.SetDeadline(r.deadline)
			select {
			case r.pool <- s:
				r.log("spare_authenticated", map[string]any{"stream_id": s.StreamID()})
			default:
				_ = s.Close()
				r.log("excess_spare_closed", map[string]any{"stream_id": s.StreamID()})
			}
			return nil
		}()
		if err != nil {
			_ = s.Close()
			r.fail("work_authentication", err)
			return
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *jointRuntime) trigger(input io.Reader) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 2048), 2048)
	for scanner.Scan() {
		line := scanner.Text()
		r.mu.Lock()
		err := jointPhase(line, r.c, r.requestID)
		if err == nil && (!r.putActive || r.triggered) {
			err = fmt.Errorf("trigger requires the single active PUT and is single-use")
		}
		if err == nil {
			r.triggered = true
		}
		r.mu.Unlock()
		if err != nil {
			r.fail("phase_input", err)
			return
		}
		if err = jointFile(r.c.EvidenceDir, "trigger.uart", []byte(line+"\n")); err != nil {
			r.fail("trigger_evidence", err)
			return
		}
		r.log("phase_signal_received", map[string]any{"phase": r.c.TriggerPhase, "source": "external_read_only_uart_owner"})
		plain, err := jointMaximumRecord()
		if err != nil {
			r.fail("maximum_record_build", err)
			return
		}
		if err = jointFile(r.c.EvidenceDir, "control-plaintext.bin", plain); err != nil {
			r.fail("record_plaintext_evidence", err)
			return
		}
		r.writeMu.Lock()
		r.mu.Lock()
		active := r.putActive
		r.mu.Unlock()
		if !active || r.ctx.Err() != nil {
			r.writeMu.Unlock()
			r.fail("maximum_record_admission", fmt.Errorf("PUT ended before maximum record write"))
			return
		}
		r.log("record_write_begin", map[string]any{"plaintext_bytes": len(plain), "req_work_conn_frames": 16})
		encoded, err := r.record(plain)
		r.writeMu.Unlock()
		if saveErr := jointFile(r.c.EvidenceDir, "control-ciphertext.bin", encoded); saveErr != nil {
			r.fail("record_ciphertext_evidence", saveErr)
			return
		}
		r.mu.Lock()
		r.recordWritten = err == nil
		r.mu.Unlock()
		r.log("record_write_end", map[string]any{"ciphertext_bytes": len(encoded), "transport_write_completed": err == nil, "device_authenticated": false})
		if err != nil {
			r.fail("maximum_record_write", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		r.fail("phase_input_read", err)
		return
	}
	r.mu.Lock()
	triggered := r.triggered
	r.mu.Unlock()
	// Zero signals is the explicit forwarding-only use of the same fixture.
	// EOF never manufactures a record or an overlap observation.
	r.log("phase_input_closed", map[string]any{"triggered": triggered})
}

// Read exact HTTP bytes; never normalize a signed request or manufacture a
// management response. Only one request per connection, with explicit length.
func jointHeader(reader *bufio.Reader) ([]byte, *http.Request, error) {
	var header []byte
	for len(header) < 1024 {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		header = append(header, b)
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
			if err != nil {
				return nil, nil, err
			}
			if req.Proto != "HTTP/1.1" || req.ContentLength <= 0 || len(req.TransferEncoding) != 0 || req.URL.RawQuery != "" || req.URL.IsAbs() || req.Header.Get("Expect") != "" || len(req.Header.Values("X-ESP-Management-Tag")) != 1 {
				return nil, nil, fmt.Errorf("joint request requires exact HTTP/1.1 length and management tag")
			}
			return header, req, nil
		}
	}
	return nil, nil, fmt.Errorf("joint HTTP header exceeds 1024 bytes")
}

func (r *jointRuntime) admit(req *http.Request, body []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if req.Method == "PUT" && req.RequestURI == "/api/v1/ota-images/"+r.c.OperationID {
		if !r.startSeen || r.putSeen || req.ContentLength != r.c.ImageSizeBytes {
			return "", fmt.Errorf("PUT identity, length or single-use admission failed")
		}
		r.putSeen, r.putActive = true, true
		return "put", nil
	}
	if req.Method != "POST" {
		return "", fmt.Errorf("unsupported joint request")
	}
	var command struct {
		ProtocolVersion int    `json:"protocol_version"`
		DeviceID        string `json:"device_id"`
		RequestID       string `json:"request_id"`
		TargetBootID    string `json:"target_boot_id"`
		Command         string `json:"command"`
		Parameters      struct {
			OperationID string `json:"operation_id"`
			SHA256      string `json:"sha256"`
			Size        int64  `json:"image_size_bytes"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(body, &command); err != nil {
		return "", err
	}
	if command.ProtocolVersion != 1 || command.DeviceID != r.c.ClientID || !jointUUID.MatchString(command.RequestID) {
		return "", fmt.Errorf("command identity mismatch")
	}
	if req.RequestURI == "/api/v1/commands/ota-start" && command.Command == "ota.start" {
		if r.startSeen || command.TargetBootID != r.c.BootID || command.Parameters.OperationID != r.c.OperationID || command.Parameters.SHA256 != r.c.ImageSHA256 || command.Parameters.Size != r.c.ImageSizeBytes {
			return "", fmt.Errorf("start intent or single-use admission failed")
		}
		r.startSeen = true
		r.requestID = command.RequestID
		return "start", nil
	}
	paths := map[string]string{"/api/v1/commands/status": "status", "/api/v1/commands/firmware-status": "firmware.status", "/api/v1/commands/ota-result": "ota.result"}
	if paths[req.RequestURI] != command.Command || command.Command == "" || r.queryCount >= 128 || (command.Command == "ota.result" && command.Parameters.OperationID != r.c.OperationID) {
		return "", fmt.Errorf("read-only query path, original operation or finite count mismatch")
	}
	r.queryCount++
	return "query", nil
}

func (r *jointRuntime) proxy(conn net.Conn) {
	defer conn.Close()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-r.ctx.Done():
			_ = conn.Close()
		case <-closed:
		}
	}()
	requestStarted := time.Now()
	requestDeadline := minTime(r.deadline, requestStarted.Add(5*time.Second))
	_ = conn.SetDeadline(requestDeadline)
	reader := bufio.NewReaderSize(conn, 1024)
	header, req, err := jointHeader(reader)
	if err != nil {
		r.log("request_rejected", map[string]any{"reason": err.Error()})
		return
	}
	var body []byte
	if req.Method == "POST" {
		if req.ContentLength > 1024 {
			r.log("request_rejected", map[string]any{"reason": "command too large"})
			return
		}
		body = make([]byte, req.ContentLength)
		if _, err = io.ReadFull(reader, body); err != nil {
			r.log("request_rejected", map[string]any{"reason": "truncated command"})
			return
		}
	}
	kind, err := r.admit(req, body)
	if err != nil {
		r.log("request_rejected", map[string]any{"reason": err.Error()})
		return
	}
	if kind == "put" {
		defer func() { r.mu.Lock(); r.putActive = false; r.mu.Unlock() }()
	}
	var stream *yamux.Stream
	select {
	case stream = <-r.pool:
	case <-r.ctx.Done():
		return
	case <-time.After(max(time.Duration(0), time.Until(requestDeadline))):
		r.workError(kind, "wait_work", 0, os.ErrDeadlineExceeded)
		return
	}
	defer stream.Close()
	_ = stream.SetDeadline(requestDeadline)
	r.mu.Lock()
	r.active++
	r.peakActive = max(r.peakActive, r.active)
	active := r.active
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.active--; r.mu.Unlock() }()
	r.log("work_started", map[string]any{"stream_id": stream.StreamID(), "kind": kind, "active": active, "path": req.RequestURI, "request_started_elapsed_us": requestStarted.Sub(r.j.started).Microseconds(), "request_deadline_elapsed_us": requestDeadline.Sub(r.j.started).Microseconds()})
	requestBytes := append(append([]byte(nil), header...), body...)
	if err = jointFile(r.c.EvidenceDir, fmt.Sprintf("request-%d.http", stream.StreamID()), requestBytes); err != nil {
		r.fail("request_evidence", err)
		return
	}
	if err = r.message(&msg.ReqWorkConn{}); err != nil {
		r.fail("control_request_work", err)
		return
	}
	peer := conn.RemoteAddr().(*net.TCPAddr)
	start := msg.StartWorkConn{ProxyName: r.c.ProxyName, SrcAddr: peer.IP.String(), DstAddr: "127.0.0.1", SrcPort: uint16(peer.Port), DstPort: uint16(r.c.RemotePort)}
	if err = msg.NewV2ReadWriter(stream).WriteMsg(&start); err != nil {
		r.workError(kind, "start_work", stream.StreamID(), err)
		return
	}
	deadline := requestDeadline
	if kind == "put" {
		deadline = r.deadline
	}
	_ = conn.SetDeadline(deadline)
	_ = stream.SetDeadline(deadline)
	// POST was already read as one bounded, exact request. Do not introduce
	// a separate Yamux/TLS write between its header and body. PUT stays streamed.
	n, err := stream.Write(requestBytes)
	if err == nil && n != len(requestBytes) {
		err = io.ErrShortWrite
	}
	if err != nil {
		r.workError(kind, "request_write", stream.StreamID(), err)
		return
	}
	if kind == "put" {
		hash := sha256.New()
		remaining := req.ContentLength
		defer func() {
			r.log("put_body_forwarding_ended", map[string]any{"bytes": req.ContentLength - remaining, "sha256_of_forwarded_prefix": hex.EncodeToString(hash.Sum(nil)), "complete": remaining == 0, "device_consumed": false})
		}()
		buffer := make([]byte, 4096)
		for remaining > 0 {
			until := minTime(deadline, time.Now().Add(30*time.Second))
			_ = conn.SetReadDeadline(until)
			_ = stream.SetWriteDeadline(until)
			n, readErr := reader.Read(buffer[:min(int64(len(buffer)), remaining)])
			if n > 0 {
				written, writeErr := stream.Write(buffer[:n])
				hash.Write(buffer[:written])
				remaining -= int64(written)
				r.mu.Lock()
				r.putBytes += int64(written)
				r.mu.Unlock()
				if writeErr != nil {
					r.fail("put_body_write", writeErr)
					return
				}
				if written != n {
					r.fail("put_body_write", io.ErrShortWrite)
					return
				}
			}
			if readErr != nil && remaining > 0 {
				r.fail("put_body_read", readErr)
				return
			}
		}
		digest := hex.EncodeToString(hash.Sum(nil))
		r.log("put_body_forwarded", map[string]any{"bytes": req.ContentLength, "sha256": digest, "device_consumed": false})
		if digest != r.c.ImageSHA256 {
			r.fail("put_body_digest", fmt.Errorf("forwarded body digest differs from intent"))
			return
		}
		_ = conn.SetDeadline(minTime(r.deadline, time.Now().Add(30*time.Second)))
		_ = stream.SetDeadline(minTime(r.deadline, time.Now().Add(30*time.Second)))
	}
	response, err := io.ReadAll(io.LimitReader(stream, 8193))
	if saveErr := jointFile(r.c.EvidenceDir, fmt.Sprintf("response-%d.http", stream.StreamID()), response); saveErr != nil {
		r.fail("response_evidence", saveErr)
		return
	}
	if err != nil || len(response) == 0 || len(response) > 8192 {
		if err == nil {
			err = fmt.Errorf("empty response or response exceeds 8192 bytes")
		}
		r.workError(kind, "response_read", stream.StreamID(), err)
		return
	}
	if _, err = conn.Write(response); err != nil {
		r.workError(kind, "response_write", stream.StreamID(), err)
		return
	}
	r.mu.Lock()
	if kind == "query" {
		r.queryCompleted++
	}
	r.mu.Unlock()
	r.log("work_response_forwarded", map[string]any{"stream_id": stream.StreamID(), "kind": kind, "response_bytes": len(response), "device_result_verified": false})
}

func (r *jointRuntime) run(input io.ReadCloser) error {
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.c.RemotePort)))
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-r.ctx.Done(); _ = listener.Close(); _ = input.Close(); _ = r.mux.Close() }()
	start := func(fn func()) { r.wg.Add(1); go func() { defer r.wg.Done(); fn() }() }
	start(r.controls)
	start(r.workStreams)
	start(func() { r.trigger(input) })
	if err = r.message(&msg.ReqWorkConn{}); err != nil {
		r.fail("control_initial_work", err)
	}
	r.log("joint_proxy_ready", map[string]any{"address": listener.Addr().String(), "official_frps": false})
	fmt.Printf("esp-frp joint proxy\n  status  ready\n  http_endpoint  http://%s\n  official_frps  false\n", listener.Addr())
	slots := make(chan struct{}, 2)
	for accepted := 0; accepted < 132; accepted++ {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		select {
		case slots <- struct{}{}:
			start(func() { defer func() { <-slots }(); r.proxy(conn) })
		default:
			_ = conn.Close()
			r.log("third_connection_rejected", nil)
		}
		if accepted == 131 {
			r.fail("connection_allowance", fmt.Errorf("finite connection allowance exhausted"))
		}
	}
	if r.ctx.Err() == nil {
		r.fail("http_listener", fmt.Errorf("joint listener ended"))
	}
	r.wg.Wait()
	return context.Cause(r.ctx)
}

// An inherited stdin pipe is a blocking NewFile, unlike os.Pipe/io.Pipe.
// Rewrap a nonblocking duplicate in Go's poller so Close interrupts Scan.
// Keep the original owner out of the read path; never leak a blocked goroutine.
func jointPollableInput(input io.ReadCloser) (io.ReadCloser, error) {
	f, ok := input.(*os.File)
	if !ok {
		return input, nil
	}
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return input, err
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return input, err
	}
	fd := -1
	var fdErr error
	err = raw.Control(func(original uintptr) {
		fd, fdErr = syscall.Dup(int(original))
		if fdErr == nil {
			syscall.CloseOnExec(fd)
			fdErr = syscall.SetNonblock(fd, true)
		}
	})
	if err = errors.Join(err, fdErr); err != nil {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
		return input, err
	}
	pollable := os.NewFile(uintptr(fd), "joint-phase-input")
	if err = pollable.SetReadDeadline(time.Time{}); err != nil {
		_ = pollable.Close()
		return input, fmt.Errorf("phase pipe must support cancellation: %w", err)
	}
	if err = input.Close(); err != nil {
		_ = pollable.Close()
		return input, err
	}
	return pollable, nil
}

func runDeviceJoint(path string, input io.ReadCloser) (resultErr error) {
	pollable, err := jointPollableInput(input)
	if err != nil {
		_ = input.Close()
		return err
	}
	input = pollable
	defer input.Close()
	c, data, err := loadDeviceJoint(path)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(c.CertificateFile, c.PrivateKeyFile)
	if err != nil {
		return err
	}
	if err = os.Mkdir(c.EvidenceDir, 0700); err != nil {
		return err
	}
	if err = jointFile(c.EvidenceDir, "input.json", data); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(c.EvidenceDir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	j := &jointJournal{file: f, started: time.Now()}
	base, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	deadline := time.Now().Add(time.Duration(c.TimeoutMS) * time.Millisecond)
	bounded, cancelDeadline := context.WithDeadline(base, deadline)
	defer cancelDeadline()
	ctx, cancel := context.WithCancelCause(bounded)
	defer cancel(nil)
	r := &jointRuntime{c: c, j: j, ctx: ctx, cancel: cancel, deadline: deadline, pool: make(chan *yamux.Stream, 1)}
	cancellationLogged := make(chan error, 1)
	go func() {
		<-ctx.Done()
		// context.Cause owns the first cancellation; later teardown errors
		// cannot replace it. This host observation is not MCU causality.
		fields := jointFailureFields(context.Cause(ctx))
		fields["cancellation_observed_us"] = time.Since(j.started).Microseconds()
		cancellationLogged <- j.event("session_canceled", fields)
	}()
	defer func() {
		if ctx.Err() == nil {
			if resultErr != nil {
				r.fail("session_setup", resultErr)
			} else {
				cancel(nil)
			}
		}
		resultErr = errors.Join(resultErr, <-cancellationLogged)
		r.mu.Lock()
		summary := map[string]any{"official_frps": false, "r5_qualified": false, "device_result_verified": false, "operation_id": c.OperationID, "boot_id": c.BootID, "record_written": r.recordWritten, "put_bytes_forwarded": r.putBytes, "query_responses_forwarded": r.queryCompleted, "peak_fixture_active": r.peakActive, "error": fmt.Sprint(resultErr), "first_cancellation": jointFailureFields(context.Cause(ctx))}
		r.mu.Unlock()
		encoded, _ := json.MarshalIndent(summary, "", "  ")
		resultErr = errors.Join(resultErr, jointFile(c.EvidenceDir, "result.json", append(encoded, '\n')))
	}()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(c.ListenIPv4), Port: c.ListenPort})
	if err != nil {
		return err
	}
	defer listener.Close()
	_ = listener.SetDeadline(deadline)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	if err = j.event("listener_ready", map[string]any{"official_frps": false}); err != nil {
		return err
	}
	fmt.Printf("esp-frp joint listener\n  status  ready\n  official_frps  false\n  evidence_directory  %s\n", c.EvidenceDir)
	raw, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer raw.Close()
	if !raw.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(c.AllowedPeerIPv4)) {
		return fmt.Errorf("unexpected joint device source IP")
	}
	go func() { <-ctx.Done(); _ = raw.Close() }()
	return serveSessionFixture(raw, cert, sessionFixtureOptions{mode: "joint", token: c.Token, clientID: c.ClientID, proxyName: c.ProxyName, remotePort: c.RemotePort, serverVersion: "esp-frp-joint-fixture", timeout: time.Until(deadline), joint: func(m *yamux.Session, control *msg.V2ReadWriter, record func([]byte) ([]byte, error)) error {
		r.mux, r.control, r.record = m, control, record
		return r.run(input)
	}}, nil)
}
