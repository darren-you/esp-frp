// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func runQUICClient(path string) {
	withControlledQUICServer(func(ports sessionServerPorts, caPath, _ string, stop, start func()) {
		clientCase(path, caPath, "lifecycle", ports.quic, 1, stop, start)
		// The same public client and worker drive native QUIC streams through
		// Hello/Login/AEAD/NewProxy; the shared body test checks exact receipts
		// before FIN and leaves two real local sockets active for cancellation.
		workDuplexRounds(path, caPath, ports.quic, 3, true)
		clientActiveRestartCase(path, caPath, ports.quic, stop, start)
		for _, mode := range []string{"wrong-host", "wrong-token", "untrusted"} {
			clientCase(path, caPath, mode, ports.quic, 1, stop, start)
		}
		fmt.Println("Official FRPS QUIC public client: Hello/Login/AEAD, concurrent exact 300001-byte TCP bodies/FIN, waiting stream and two active sockets, active cancellation/Flash/fd cleanup, same-worker FRPS recovery/run identity and strict trust/authentication passed")
	})
}

func runQUICUDP(path string) {
	withControlledQUICServer(func(ports sessionServerPorts, caPath, _ string, stop, start func()) {
		udpClientCase(path, ports.quic, caPath, stop, start)
		fmt.Println("Official FRPS QUIC UDP public client: two exact binary datagram sources including empty payload, active-source interruption, cumulative counters, same-worker/run identity, same-instance restart and clean gauges/Flash/fd passed")
	})
}

func runQUICVisitor(path string) {
	withControlledQUICServer(func(ports sessionServerPorts, caPath, _ string, _, _ func()) {
		local := localListener()
		defer local.Close()
		// A real official TCP provider and the C QUIC visitor share one FRPS
		// registration. Business bytes use native QUIC streams at the visitor.
		provider := startSTCPProvider(ports.tcp, local.Addr().(*net.TCPAddr).Port, caPath)
		defer provider.close()
		visitorRejection(path, caPath, ports.quic, local, "provider", "provider.private", "wrong-public-secret")
		h := startSTCPVisitorHarness(path, caPath, ports.quic, visitorFreePort(),
			"serve", "provider", "provider.private", "public-visitor-secret", 0)
		defer h.cleanup()
		defer func() {
			if failure := recover(); failure != nil {
				panic(fmt.Sprintf("%v\n%s", failure, h.stderr.String()))
			}
		}()
		address, runID := visitorReady(h, "READY")
		visitorDual(h, address, local, 600, 2, 0)
		active := []visitorHeldPair{visitorHeld(address, local, 0xb1), visitorHeld(address, local, 0xb2)}
		defer func() {
			for _, pair := range active {
				pair.close()
			}
		}()
		if state := h.state(); state.active != 2 || state.waiting != 0 || state.failed != 0 || state.completed != 2 {
			panic(fmt.Sprintf("QUIC visitor live pair: %+v", state))
		}
		visitorCommand(h, 'z', "STOPPED")
		for _, pair := range active {
			visitorClosed(pair.frontend)
			visitorClosed(pair.backend)
		}
		visitorListenerClosed(address)
		visitorAwait(h, 2, 0)
		_, err := h.input.Write([]byte{'g'})
		must(err)
		recovered, recoveredRunID := visitorReady(h, "RECOVERED")
		if recovered != address || recoveredRunID != runID {
			panic("QUIC visitor stop/start changed the owned target/session/listener")
		}
		visitorDual(h, recovered, local, 700, 4, 0)
		h.finish()
		fmt.Println("Official FRPS/frpc TCP provider → QUIC public STCP visitor: secret rejection, dual exact 300001-byte admissions/FIN, two active sockets, listener/business cancellation, same-instance/run identity restart and Flash/fd cleanup passed")
	})
}

// Listener.Close in quic-go retains accepted connections and their UDP socket.
// A real process exit is required to test FRPS restart and old endpoint closure.
func withControlledQUICProcess(config *v1.ServerConfig, dir string, run func(stop, start func())) {
	binary := filepath.Join(dir, "official-frps")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"),
		"build", "-mod=readonly", "-tags=noweb", "-o", binary, "github.com/fatedier/frp/cmd/frps")
	if output, err := build.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build fixed official FRPS: %v\n%s", err, output))
	}
	config.Log.To, config.Log.Level, config.Log.DisablePrintColor = "console", "info", true
	configPath, logPath := filepath.Join(dir, "frps.json"), filepath.Join(dir, "frps.log")
	encoded, err := json.Marshal(config)
	must(err)
	must(os.WriteFile(configPath, encoded, 0600))
	var process *exec.Cmd
	var done chan error
	start := func() {
		if process != nil {
			panic("QUIC FRPS process already started")
		}
		output, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		must(err)
		current := exec.Command(binary, "-c", configPath)
		current.Stdout, current.Stderr = output, output
		if err := current.Start(); err != nil {
			_ = output.Close()
			panic(err)
		}
		process, done = current, make(chan error, 1)
		currentDone := done
		go func() {
			err := current.Wait()
			_ = output.Close()
			currentDone <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			select {
			case err := <-done:
				logs, _ := os.ReadFile(logPath)
				process = nil
				panic(fmt.Sprintf("official QUIC FRPS startup: %v\n%s", err, logs))
			default:
			}
			logs, err := os.ReadFile(logPath)
			must(err)
			if strings.Contains(string(logs), "frps started successfully") {
				return
			}
			if time.Now().After(deadline) {
				_ = current.Process.Kill()
				<-done
				process = nil
				panic("official QUIC FRPS startup timeout: " + string(logs))
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	stop := func() {
		if process == nil {
			return
		}
		must(process.Process.Kill())
		select {
		case err := <-done:
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				panic(fmt.Sprintf("official QUIC FRPS kill result: %v", err))
			}
		case <-time.After(5 * time.Second):
			panic("official QUIC FRPS process did not stop")
		}
		process = nil
	}
	start()
	defer stop()
	run(stop, start)
}
