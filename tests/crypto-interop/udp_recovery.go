// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type udpClientState struct {
	phase, active, remotes                            int
	ready, attempts, received, sent, dropped, expired uint64
}

func runUDPClient(path string) {
	withControlledSessionServer(func(port int, caPath, _ string, stop, start func()) {
		udpClientCase(path, port, caPath, stop, start)
	})
	fmt.Println("Official FRPS UDP worker: active-source interruption, same-worker reconnect/run identity, cumulative counters, clean gauges/fd and same-instance restart passed")
}
func udpClientCase(path string, port int, caPath string, stop, start func()) {
	local := udpListener()
	defer local.Close()
	go udpEcho(local)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, strconv.Itoa(local.LocalAddr().(*net.UDPAddr).Port))
	input, err := cmd.StdinPipe()
	must(err)
	output, err := cmd.StdoutPipe()
	must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(output)
	line := func(prefix string) string {
		if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), prefix) {
			panic(fmt.Sprintf("UDP worker missing %q: line=%q stderr=%s", prefix, scanner.Text(), stderr.String()))
		}
		return scanner.Text()
	}
	readState := func(prefix string) udpClientState {
		var state udpClientState
		count, err := fmt.Sscanf(line(prefix), prefix+" %d %d %d %d %d %d %d %d %d", &state.phase,
			&state.ready, &state.attempts, &state.active, &state.remotes, &state.received,
			&state.sent, &state.dropped, &state.expired)
		must(err)
		if count != 9 {
			panic("invalid UDP worker state")
		}
		return state
	}
	state := func() udpClientState { _, err := input.Write([]byte{'s'}); must(err); return readState("STATE") }
	connect := func() (*net.UDPConn, *net.UDPConn) {
		address := "127.0.0.1" + strings.TrimPrefix(line("READY :"), "READY ")
		return udpRemote(address), udpRemote(address)
	}
	first, second := connect()
	udpExchange(first, []byte{1, 2, 3})
	udpExchange(second, []byte{4, 5, 6})
	before := state()
	if before.ready != 1 || before.remotes != 2 || before.received < 2 || before.sent < 2 {
		panic(fmt.Sprintf("UDP initial worker state: %+v", before))
	}
	stop()
	drained := readState("BACKOFF")
	if drained.active != 0 || drained.remotes != 0 || drained.received < before.received || drained.sent < before.sent {
		panic(fmt.Sprintf("UDP disconnect lost cumulative counters or retained sources: before=%+v drained=%+v", before, drained))
	}
	must(first.Close())
	must(second.Close())
	start()
	first, second = connect()
	udpExchange(first, []byte{7, 8, 9})
	udpExchange(second, nil)
	recovered := state()
	if recovered.ready != 2 || recovered.attempts < 2 || recovered.remotes != 2 || recovered.received < before.received+2 || recovered.sent < before.sent+2 {
		panic(fmt.Sprintf("UDP worker did not recover independently: before=%+v recovered=%+v", before, recovered))
	}
	_, err = input.Write([]byte{'c'})
	must(err)
	stopped := readState("STOPPED")
	if stopped.active != 0 || stopped.remotes != 0 || stopped.received < recovered.received || stopped.sent < recovered.sent {
		panic("UDP stop retained sources or reset counters")
	}
	must(first.Close())
	must(second.Close())
	_, err = input.Write([]byte{'r'})
	must(err)
	first, second = connect()
	udpExchange(first, []byte{10, 11, 12})
	udpExchange(second, []byte{13, 14, 15})
	restarted := state()
	if restarted.ready != 3 || restarted.received < recovered.received+2 || restarted.sent < recovered.sent+2 {
		panic("UDP same-instance start lost cumulative counters")
	}
	_, err = input.Write([]byte{'q'})
	must(err)
	must(input.Close())
	if err = cmd.Wait(); err != nil {
		panic(fmt.Sprintf("UDP worker cleanup: %v\n%s", err, stderr.String()))
	}
	must(first.Close())
	must(second.Close())
	fmt.Print(stderr.String())
}
