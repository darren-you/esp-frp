// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
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
func runClient(path string) {
	withControlledSessionServer(func(port int, caPath, dir string, stop, start func()) {
		clientCase(path, caPath, "lifecycle", port, 100, stop, start)
		workDuplexRounds(path, caPath, port, 3, true)
		for _, mode := range []string{"reuse", "dns-pending", "dns-retry", "no-memory", "untrusted", "wrong-token", "wrong-host", "pause-tls", "pause-login", "pause-register", "pause-ready", "stop-backoff", "trust-lost", "restart"} {
			clientCase(path, caPath, mode, port, 1, stop, start)
		}
		fmt.Println("Single worker: official FRPS lifecycle, restart/reconnect, trust/auth failure, stop deadlines and callback drain passed")
	})
}
