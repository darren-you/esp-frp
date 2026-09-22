// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func workPattern(id uint32, reverse bool) []byte {
	p := make([]byte, 300001)
	for i := range p {
		p[i] = byte(uint32(i)*31 + id*17)
		if reverse {
			p[i] ^= 0xa7
		}
	}
	return p
}
func localWork(conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var id uint32
	if err := binary.Read(conn, binary.BigEndian, &id); err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() { _, err := conn.Write(workPattern(id, true)); written <- err }()
	p := make([]byte, 300001)
	_, err := io.ReadFull(conn, p)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, workPattern(id, false)) {
		return fmt.Errorf("local payload mismatch %d", id)
	}
	if err = <-written; err != nil {
		return err
	}
	var ack [1]byte
	if _, err = io.ReadFull(conn, ack[:]); err != nil {
		return err
	}
	if ack[0] != 0x5a {
		return fmt.Errorf("bad receipt")
	}
	if _, err = conn.Write([]byte{0xa5}); err != nil {
		return err
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	_, err = io.ReadAll(conn)
	return err
}
func remoteWork(address string, id uint32) error {
	conn, err := net.DialTimeout("tcp4", address, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	written := make(chan error, 1)
	go func() {
		err := binary.Write(conn, binary.BigEndian, id)
		if err == nil {
			_, err = conn.Write(workPattern(id, false))
		}
		written <- err
	}()
	p := make([]byte, 300001)
	if _, err = io.ReadFull(conn, p); err != nil {
		return err
	}
	if !bytes.Equal(p, workPattern(id, true)) {
		return fmt.Errorf("remote payload mismatch %d", id)
	}
	if err = <-written; err != nil {
		return err
	}
	// Official FRPS Join closes both connections on either EOF. Receipt precedes
	// EOF; independent protocol fixtures cover data after a one-sided FIN.
	if _, err = conn.Write([]byte{0x5a}); err != nil {
		return err
	}
	var ack [1]byte
	if _, err = io.ReadFull(conn, ack[:]); err != nil {
		return err
	}
	if ack[0] != 0xa5 {
		return fmt.Errorf("bad final receipt")
	}
	tail, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if len(tail) != 0 {
		return fmt.Errorf("unexpected tail")
	}
	return nil
}
func workDuplex(path, caPath string, port int) {
	local := localListener()
	defer local.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, strconv.Itoa(local.Addr().(*net.TCPAddr).Port), "duplex", "200")
	input, err := cmd.StdinPipe()
	must(err)
	output, err := cmd.StdoutPipe()
	must(err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	must(cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "READY :") {
		panic("work peer missing READY: " + stderr.String())
	}
	address := "127.0.0.1" + strings.TrimPrefix(scanner.Text(), "READY ")
	results := make(chan error, 200)
	go func() {
		for range 200 {
			conn, err := local.Accept()
			if err != nil {
				results <- err
				return
			}
			go func() { results <- localWork(conn) }()
		}
	}()
	for round := uint32(0); round < 100; round++ {
		remote := make(chan error, 2)
		for index := uint32(0); index < 2; index++ {
			go func(id uint32) { remote <- remoteWork(address, id) }(round*2 + index)
		}
		for range 2 {
			if err := <-remote; err != nil {
				panic(fmt.Sprintf("remote work round=%d: %v\n%s", round, err, stderr.String()))
			}
		}
		for range 2 {
			if err := <-results; err != nil {
				panic(fmt.Sprintf("local work round=%d: %v\n%s", round, err, stderr.String()))
			}
		}
		if (round+1)%20 == 0 {
			fmt.Printf("Official FRPS work: %d/100 dual-flow rounds passed\n", round+1)
		}
	}
	_, err = input.Write([]byte{'q'})
	must(err)
	must(input.Close())
	if err = cmd.Wait(); err != nil {
		panic(fmt.Sprintf("work peer: %v\n%s", err, stderr.String()))
	}
	fmt.Print(stderr.String())
	fmt.Println("Official FRPS: 100 dual-flow rounds, 200 fixed-target TCP sockets, 300001 bytes each direction and fd cleanup passed")
}
func runWork(path string, faults bool) {
	withSessionServer(func(port int, caPath, dir string) {
		if !faults {
			workDuplex(path, caPath, port)
			return
		}
		for _, mode := range []string{"refused", "capacity", "local-rst", "cancel-active"} {
			workFault(path, caPath, port, mode)
		}
		runWorkFixtures(path, dir)
	})
}

type workState struct {
	active, waiting   uint
	completed, failed uint64
	reason            int
}
type workHarness struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Scanner
	stderr bytes.Buffer
	cancel context.CancelFunc
}

func startWorkHarness(path, caPath string, port, localPort int, mode string) *workHarness {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	h := &workHarness{cancel: cancel}
	h.cmd = exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, strconv.Itoa(localPort), mode, "0")
	var err error
	h.input, err = h.cmd.StdinPipe()
	must(err)
	output, err := h.cmd.StdoutPipe()
	must(err)
	h.output = bufio.NewScanner(output)
	h.cmd.Stderr = &h.stderr
	must(h.cmd.Start())
	return h
}
func (h *workHarness) line() string {
	if !h.output.Scan() {
		panic("work peer lost output: " + h.stderr.String())
	}
	return h.output.Text()
}
func (h *workHarness) address() string {
	line := h.line()
	if !strings.HasPrefix(line, "READY :") {
		panic(line)
	}
	return "127.0.0.1" + strings.TrimPrefix(line, "READY ")
}
func (h *workHarness) state() workState {
	_, err := h.input.Write([]byte{'s'})
	must(err)
	var state workState
	n, err := fmt.Sscanf(h.line(), "STATE %d %d %d %d %d", &state.active, &state.waiting, &state.completed, &state.failed, &state.reason)
	must(err)
	if n != 5 {
		panic("incomplete work status")
	}
	return state
}
func (h *workHarness) await(want func(workState) bool) workState {
	deadline := time.Now().Add(5 * time.Second)
	for {
		state := h.state()
		if want(state) {
			return state
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("work status deadline: %+v", state))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (h *workHarness) finish() {
	_, err := h.input.Write([]byte{'q'})
	must(err)
	must(h.input.Close())
	if err = h.cmd.Wait(); err != nil {
		panic(fmt.Sprintf("work exit: %v\n%s", err, h.stderr.String()))
	}
	fmt.Print(h.stderr.String())
}
func (h *workHarness) cleanup() { h.cancel(); _ = h.cmd.Process.Kill(); _ = h.cmd.Wait() }
func workFault(path, caPath string, port int, mode string) {
	local := localListener()
	defer local.Close()
	localPort := local.Addr().(*net.TCPAddr).Port
	if mode == "refused" {
		must(local.Close())
	}
	h := startWorkHarness(path, caPath, port, localPort, mode)
	defer h.cleanup()
	address := h.address()
	var clients, backends []net.Conn
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
		for _, c := range backends {
			_ = c.Close()
		}
	}()
	count := 1
	if mode == "capacity" || mode == "cancel-active" {
		count = 2
	}
	for range count {
		client, err := net.DialTimeout("tcp4", address, 2*time.Second)
		must(err)
		clients = append(clients, client)
		must(client.SetDeadline(time.Now().Add(5 * time.Second)))
		_, err = client.Write([]byte{0x42})
		must(err)
		if mode != "refused" {
			must(local.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)))
			backend, err := local.Accept()
			must(err)
			backends = append(backends, backend)
			must(backend.SetDeadline(time.Now().Add(5 * time.Second)))
			var byteIn [1]byte
			_, err = io.ReadFull(backend, byteIn[:])
			must(err)
			if byteIn[0] != 0x42 {
				panic("wrong local target bytes")
			}
		}
	}
	switch mode {
	case "refused":
		h.await(func(s workState) bool { return s.failed == 1 && s.active == 0 && s.reason == -17 })
	case "local-rst":
		must(backends[0].(*net.TCPConn).SetLinger(0))
		must(backends[0].Close())
		h.await(func(s workState) bool { return s.failed == 1 && s.active == 0 && s.reason == -17 })
	case "capacity":
		h.await(func(s workState) bool { return s.active == 2 && s.waiting == 1 })
		third, err := net.DialTimeout("tcp4", address, 2*time.Second)
		must(err)
		defer third.Close()
		must(third.SetDeadline(time.Now().Add(5 * time.Second)))
		_, err = third.Write([]byte{0x43})
		must(err)
		h.await(func(s workState) bool { return s.failed == 1 && s.active == 2 && s.reason == -3 })
		var b [1]byte
		n, err := third.Read(b[:])
		if n != 0 || err == nil {
			panic("third flow was not rejected")
		}
		must(local.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)))
		unexpected, err := local.Accept()
		if err == nil {
			unexpected.Close()
			panic("third local socket escaped capacity")
		}
	case "cancel-active":
		h.await(func(s workState) bool { return s.active == 2 && s.waiting == 1 })
	}
	h.finish()
	for _, backend := range backends {
		var b [1]byte
		_, err := backend.Read(b[:])
		if err == nil {
			panic("local socket remained after cancel")
		}
	}
	fmt.Printf("Official FRPS work fault: %s passed\n", mode)
}
