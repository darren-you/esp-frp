// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func clientCase(path, caPath, mode string, port, rounds int, stop, start func()) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, mode, strconv.Itoa(rounds))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	must(err)
	stdin, err := cmd.StdinPipe()
	must(err)
	must(cmd.Start())
	scanner := bufio.NewScanner(stdout)
	stage := 0
	for scanner.Scan() {
		line := scanner.Text()
		if mode != "restart" {
			panic("unexpected client output: " + line)
		}
		switch stage {
		case 0:
			if !strings.HasPrefix(line, "READY ") {
				panic(line)
			}
			stop()
			_, err = io.WriteString(stdin, "r")
		case 1:
			if line != "BACKOFF" {
				panic(line)
			}
			start()
			_, err = io.WriteString(stdin, "c")
		case 2:
			if !strings.HasPrefix(line, "RECOVERED ") {
				panic(line)
			}
		default:
			panic("extra recovery event")
		}
		must(err)
		stage++
	}
	must(scanner.Err())
	if err := cmd.Wait(); err != nil {
		panic(fmt.Sprintf("client %s: %v\n%s", mode, err, stderr.String()))
	}
	if mode == "restart" && stage != 3 {
		panic("missing recovery")
	}
	fmt.Print(stderr.String())
}
func clientActiveRestartCase(path, caPath string, port int, stop, start func()) {
	local := localListener()
	defer local.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, "restart-active", "1",
		strconv.Itoa(local.Addr().(*net.TCPAddr).Port))
	stdout, err := cmd.StdoutPipe()
	must(err)
	stdin, err := cmd.StdinPipe()
	must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(stdout)
	stage := func(prefix string) string {
		if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), prefix) {
			panic(fmt.Sprintf("active restart: expected %s, got %q\n%s", prefix, scanner.Text(), stderr.String()))
		}
		return strings.TrimPrefix(scanner.Text(), prefix)
	}
	address := "127.0.0.1" + stage("READY ")
	oldRemote := make([]net.Conn, 0, 2)
	oldLocal := make([]net.Conn, 0, 2)
	defer func() {
		for _, c := range oldRemote {
			_ = c.Close()
		}
		for _, c := range oldLocal {
			_ = c.Close()
		}
	}()
	for i := range 2 {
		remote, err := net.DialTimeout("tcp4", address, 2*time.Second)
		must(err)
		oldRemote = append(oldRemote, remote)
		must(remote.SetDeadline(time.Now().Add(5 * time.Second)))
		_, err = remote.Write([]byte{byte(i + 1)})
		must(err)
		must(local.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)))
		backend, err := local.Accept()
		must(err)
		oldLocal = append(oldLocal, backend)
		must(backend.SetDeadline(time.Now().Add(5 * time.Second)))
		var received [1]byte
		_, err = io.ReadFull(backend, received[:])
		must(err)
		if received[0] != byte(i+1) {
			panic("old stream sent bytes to the wrong target")
		}
	}
	_, err = io.WriteString(stdin, "a")
	must(err)
	stage("ACTIVE")
	stop()
	_, err = io.WriteString(stdin, "r")
	must(err)
	stage("BACKOFF")
	for _, c := range append(oldLocal, oldRemote...) {
		var b [1]byte
		n, readErr := c.Read(b[:])
		var netErr net.Error
		if n != 0 || readErr == nil || (errors.As(readErr, &netErr) && netErr.Timeout()) {
			panic(fmt.Sprintf("old stream survived FRPS restart: n=%d error=%v", n, readErr))
		}
	}
	start()
	_, err = io.WriteString(stdin, "c")
	must(err)
	address = "127.0.0.1" + stage("RECOVERED ")
	must(local.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)))
	results := make(chan error, 2)
	go func() {
		for i := range 2 {
			backend, acceptErr := local.Accept()
			if acceptErr != nil {
				for remaining := i; remaining < 2; remaining++ {
					results <- acceptErr
				}
				return
			}
			go func() { results <- localWork(backend) }()
		}
	}()
	remote := make(chan error, 2)
	for i := range 2 {
		go func(id uint32) { remote <- remoteWork(address, id) }(uint32(i + 1000))
	}
	for range 2 {
		if err := <-remote; err != nil {
			panic(fmt.Sprintf("recovered remote: %v\n%s", err, stderr.String()))
		}
	}
	for range 2 {
		if err := <-results; err != nil {
			panic(fmt.Sprintf("recovered local: %v\n%s", err, stderr.String()))
		}
	}
	_, err = io.WriteString(stdin, "v")
	must(err)
	must(stdin.Close())
	if err = cmd.Wait(); err != nil {
		panic(fmt.Sprintf("active restart peer: %v\n%s", err, stderr.String()))
	}
	must(scanner.Err())
	fmt.Print(stderr.String())
	fmt.Println("Official FRPS: two active streams interrupted, local sockets retired, same worker recovered and two new full-duplex streams passed")
}
func runClient(path string) {
	withControlledSessionServer(func(port int, caPath, dir string, stop, start func()) {
		clientCase(path, caPath, "lifecycle", port, 100, stop, start)
		workDuplexRounds(path, caPath, port, 3, true)
		clientActiveRestartCase(path, caPath, port, stop, start)
		for _, mode := range []string{"replacement", "concurrent-stop", "pause-stopped", "backoff-matrix", "reuse", "dns-pending", "dns-retry", "no-memory", "untrusted", "wrong-token", "wrong-host", "pause-tls", "pause-login", "pause-register", "pause-ready", "stop-backoff", "trust-lost", "restart"} {
			clientCase(path, caPath, mode, port, 1, stop, start)
		}
		fmt.Println("Single worker: official FRPS lifecycle, restart/reconnect, trust/auth failure, stop deadlines and callback drain passed")
	})
}
