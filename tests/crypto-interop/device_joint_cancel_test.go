// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func jointTestEventCount(c deviceJointConfig, event string) int {
	data, _ := os.ReadFile(filepath.Join(c.EvidenceDir, "events.jsonl"))
	return bytes.Count(data, []byte(`"event":"`+event+`"`))
}

func jointTestPutPrefix(t *testing.T, c deviceJointConfig, prefix []byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", c.RemotePort), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	header := fmt.Sprintf("PUT /api/v1/ota-images/%s HTTP/1.1\r\nHost: fixture\r\nContent-Length: %d\r\nX-ESP-Management-Tag: %s\r\nConnection: close\r\n\r\n", c.OperationID, c.ImageSizeBytes, strings.Repeat("a", 64))
	if _, err = conn.Write(append([]byte(header), prefix...)); err != nil {
		t.Fatal(err)
	}
	return conn
}

// Exercise the real five-second query deadline while a partially sent PUT
// stays active. Only after the timeout do we send the rest of the image.
func TestJointQueryTimeoutPreservesPUT(t *testing.T) {
	c, ca, image := jointTestConfig(t)
	c.TimeoutMS = 15000
	data, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(path, data, 0600)
	done := make(chan error, 1)
	go func() { done <- runDeviceJoint(path, io.NopCloser(strings.NewReader(""))) }()
	jointTestWait(t, func() bool { return jointTestEventCount(c, "listener_ready") == 1 })
	release := make(chan struct{})
	defer close(release)
	var queries atomic.Int32
	digest := make(chan string, 1)
	mux, _, err := jointTestPeer(c, ca, func(req *http.Request) error {
		if req.URL.Path == "/api/v1/commands/ota-result" && queries.Add(1) == 1 {
			<-release
		}
		body, err := io.ReadAll(req.Body)
		if req.Method == "PUT" {
			hash := sha256.Sum256(body)
			digest <- hex.EncodeToString(hash[:])
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	jointTestWait(t, func() bool { return jointTestEventCount(c, "joint_proxy_ready") == 1 })
	if _, err = jointTestHTTP(c, "POST", "/api/v1/commands/ota-start", jointTestCommand(c, "ota.start")); err != nil {
		t.Fatal(err)
	}
	put := jointTestPutPrefix(t, c, image[:1024])
	jointTestWait(t, func() bool { return jointTestEventCount(c, "work_started") == 2 })
	started := time.Now()
	response, _ := jointTestHTTP(c, "POST", "/api/v1/commands/ota-result", jointTestCommand(c, "ota.result"))
	if len(response) != 0 || time.Since(started) < 4500*time.Millisecond || time.Since(started) > 6*time.Second {
		t.Fatal("query did not keep its original five-second deadline", time.Since(started), len(response))
	}
	jointTestWait(t, func() bool { return jointTestEventCount(c, "query_timeout") == 1 })
	select {
	case err := <-done:
		t.Fatal("query timeout canceled PUT/control", err)
	default:
	}
	before := jointTestEventCount(c, "authenticated_pong")
	jointTestWait(t, func() bool { return jointTestEventCount(c, "authenticated_pong") > before })
	if _, err = put.Write(image[1024:]); err != nil {
		t.Fatal("PUT did not remain writable", err)
	}
	response, err = io.ReadAll(put)
	if err != nil || !bytes.Contains(response, []byte("200 OK")) {
		t.Fatal("PUT did not complete after query timeout", err, string(response))
	}
	if <-digest != c.ImageSHA256 {
		t.Fatal("upload changed")
	}
	if response, err = jointTestHTTP(c, "POST", "/api/v1/commands/ota-result", jointTestCommand(c, "ota.result")); err != nil || !bytes.Contains(response, []byte("200 OK")) {
		t.Fatal("same-session original operation query did not recover", err, string(response))
	}
	_ = mux.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not close")
	}
	var result map[string]any
	data, _ = os.ReadFile(filepath.Join(c.EvidenceDir, "result.json"))
	if json.Unmarshal(data, &result) != nil || result["put_bytes_forwarded"] != float64(len(image)) || result["query_responses_forwarded"] != float64(1) {
		t.Fatal(string(data))
	}
	partial, err := os.ReadFile(filepath.Join(c.EvidenceDir, "response-7.http"))
	if err != nil || len(partial) != 0 {
		t.Fatal("timed-out response prefix not preserved", err, len(partial))
	}
}

// Use the actual CLI and exec.StdinPipe: io.Pipe/os.Pipe in the same process
// would miss the blocking os.Stdin created for an inherited descriptor.
func TestJointProcessPipeCancellation(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "joint-fixture")
	build := exec.Command("go", "build", "-mod=readonly", "-race", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for _, stop := range []string{"control_close", "sigterm", "deadline", "empty_response", "eof_then_control_close"} {
		t.Run(stop, func(t *testing.T) {
			c, ca, image := jointTestConfig(t)
			if stop == "deadline" {
				c.TimeoutMS = 4000
			}
			path := filepath.Join(t.TempDir(), "config.json")
			data, _ := json.Marshal(c)
			_ = os.WriteFile(path, data, 0600)
			cmd := exec.Command(binary, "-device-joint-config", path)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close() // Deliberately keep writer open until after Wait.
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			processStarted := time.Now()
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					<-done
				}
			}()
			jointTestWait(t, func() bool { return jointTestEventCount(c, "listener_ready") == 1 })
			mux, counter, err := jointTestPeer(c, ca, func(req *http.Request) error {
				if stop == "empty_response" && req.URL.Path == "/api/v1/commands/ota-result" {
					return fmt.Errorf("intentional protocol fault: no HTTP response")
				}
				_, err := io.Copy(io.Discard, req.Body)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			jointTestWait(t, func() bool { return jointTestEventCount(c, "joint_proxy_ready") == 1 })
			if _, err = jointTestHTTP(c, "POST", "/api/v1/commands/ota-start", jointTestCommand(c, "ota.start")); err != nil {
				t.Fatal(err)
			}
			_ = jointTestPutPrefix(t, c, image[:1024])
			jointTestWait(t, func() bool { return jointTestEventCount(c, "work_started") == 2 })
			if _, err = io.WriteString(input, jointTestPhase(c)); err != nil {
				t.Fatal(err)
			}
			jointTestWait(t, func() bool { return jointTestEventCount(c, "record_write_end") == 1 && counter.Load() >= 19 })
			if jointTestEventCount(c, "phase_input_closed") != 0 {
				t.Fatal("stdin unexpectedly reached EOF")
			}
			started := time.Now()
			switch stop {
			case "control_close":
				_ = mux.Close()
			case "sigterm":
				if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			case "empty_response":
				_, _ = jointTestHTTP(c, "POST", "/api/v1/commands/ota-result", jointTestCommand(c, "ota.result"))
			case "eof_then_control_close":
				_ = input.Close()
				jointTestWait(t, func() bool { return jointTestEventCount(c, "phase_input_closed") == 1 })
				before := jointTestEventCount(c, "authenticated_pong")
				jointTestWait(t, func() bool { return jointTestEventCount(c, "authenticated_pong") > before })
				_ = mux.Close()
			}
			select {
			case err = <-done:
				waited = true
				if err == nil {
					t.Fatal("interrupted fixture claimed success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("OS stdin pipe blocked cancellation/result emission")
			}
			if bytes.Contains(output.Bytes(), []byte("DATA RACE")) {
				t.Fatal(output.String())
			}
			var result map[string]any
			data, err = os.ReadFile(filepath.Join(c.EvidenceDir, "result.json"))
			if err != nil || json.Unmarshal(data, &result) != nil || result["record_written"] != true || result["put_bytes_forwarded"] != float64(1024) || result["r5_qualified"] != false {
				t.Fatal("missing or incorrect cancellation evidence", err, string(data), output.String())
			}
			first, ok := result["first_cancellation"].(map[string]any)
			if !ok || first["reason"] == "" || first["error_type"] == "" || jointTestEventCount(c, "session_canceled") != 1 {
				t.Fatal("first cancellation missing", first)
			}
			if stop == "sigterm" && first["stage"] != "context" {
				t.Fatal("global cancellation replaced by teardown error", first)
			}
			// I/O and context share the same absolute deadline. Either can
			// report first; preserve that fact instead of forcing a label.
			if stop == "deadline" && time.Since(processStarted) < time.Duration(c.TimeoutMS)*time.Millisecond {
				t.Fatal("fixture ended before the configured total deadline", first)
			}
			if stop == "empty_response" && first["stage"] != "query.response_read" {
				t.Fatal("protocol error was incorrectly isolated as timeout", first)
			}
			for _, port := range []int{c.ListenPort, c.RemotePort} {
				listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
				if err != nil {
					t.Fatal("listener leaked", err)
				}
				listener.Close()
			}
			t.Logf("stop=%s writer_open=%t result_saved=true elapsed=%s first_stage=%s first_type=%s", stop, stop != "eof_then_control_close", time.Since(started), first["stage"], first["error_type"])
		})
	}
}
