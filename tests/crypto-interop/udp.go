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

func udpListener() *net.UDPConn {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	return conn
}
func udpEcho(local *net.UDPConn) {
	buffer := make([]byte, 65507)
	held := make(map[string][]byte)
	for {
		length, source, err := local.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		if length > 0 {
			switch packet[0] {
			case 0xdd: // Deliberate loss of this complete application datagram.
				continue
			case 0xfe: // Return a pair in reverse order to the same source.
				if first, ok := held[source.String()]; ok {
					_, _ = local.WriteToUDP(packet, source)
					_, _ = local.WriteToUDP(first, source)
					delete(held, source.String())
				} else {
					held[source.String()] = packet
				}
				continue
			case 0xfc: // Oversized local response must be discarded whole.
				_, _ = local.WriteToUDP(bytes.Repeat([]byte{0xa7}, 1501), source)
				_, _ = local.WriteToUDP([]byte{0xfb, 1, 2, 3}, source)
				continue
			}
		}
		_, _ = local.WriteToUDP(packet, source)
	}
}
func udpRemote(address string) *net.UDPConn {
	target, err := net.ResolveUDPAddr("udp4", address)
	must(err)
	conn, err := net.DialUDP("udp4", nil, target)
	must(err)
	return conn
}
func udpRead(conn *net.UDPConn) []byte {
	must(conn.SetReadDeadline(time.Now().Add(3 * time.Second)))
	buffer := make([]byte, 65508)
	length, err := conn.Read(buffer)
	must(err)
	return append([]byte(nil), buffer[:length]...)
}
func udpExchange(conn *net.UDPConn, payload []byte) {
	length, err := conn.Write(payload)
	must(err)
	if length != len(payload) {
		panic("partial UDP write")
	}
	if response := udpRead(conn); !bytes.Equal(response, payload) {
		panic(fmt.Sprintf("UDP datagram boundary/content mismatch got=%d expected=%d", len(response), len(payload)))
	}
}
func udpLost(conn *net.UDPConn, payload []byte) {
	_, err := conn.Write(payload)
	must(err)
	must(conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)))
	_, err = conn.Read(make([]byte, 65508))
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		panic("discarded UDP datagram unexpectedly delivered")
	}
}

type udpState struct {
	active, remotes                            int
	requests, received, sent, dropped, expired uint64
}

func udpCase(path, caPath string, port int, local *net.UDPConn, capacity int, idle bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath,
		strconv.Itoa(local.LocalAddr().(*net.UDPAddr).Port), strconv.Itoa(capacity))
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
		panic("UDP peer missing READY: " + stderr.String())
	}
	address := "127.0.0.1" + strings.TrimPrefix(scanner.Text(), "READY ")
	state := func() udpState {
		_, err := input.Write([]byte{'s'})
		must(err)
		if !scanner.Scan() {
			panic("UDP peer missing state: " + stderr.String())
		}
		var status udpState
		count, err := fmt.Sscanf(scanner.Text(), "STATE %d %d %d %d %d %d %d", &status.active,
			&status.remotes, &status.requests, &status.received, &status.sent, &status.dropped, &status.expired)
		must(err)
		if count != 7 {
			panic("invalid UDP peer state")
		}
		return status
	}
	first, second := udpRemote(address), udpRemote(address)
	defer first.Close()
	defer second.Close()
	sizes := []int{0, 1, 16}
	rounds := 3
	if capacity == 1500 {
		sizes = []int{0, 1, 127, 1024, 1500}
		rounds = 100
	}
	for round := 0; round < rounds; round++ {
		for _, size := range sizes {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte((round*17 + i*31) & 0xff)
			}
			if len(payload) > 0 {
				payload[0] = byte(round)
			}
			udpExchange(first, payload)
			if len(payload) > 0 {
				payload[0] = byte(128 + round%80)
			}
			udpExchange(second, payload)
		}
	}
	if capacity == 16 {
		udpLost(first, bytes.Repeat([]byte{0xa7}, 32))
		udpExchange(first, bytes.Repeat([]byte{0xa7}, 16))
		if status := state(); status.dropped < 1 || status.remotes != 2 || status.active != 1 {
			panic(fmt.Sprintf("UDP configured limit did not discard a whole valid frame: %+v", status))
		}
	} else {
		// Same-source response ordering belongs to UDP, rather than stream reads.
		a, b := []byte{0xfe, 1, 2, 3}, []byte{0xfe, 4, 5, 6}
		_, err = first.Write(a)
		must(err)
		_, err = first.Write(b)
		must(err)
		if !bytes.Equal(udpRead(first), b) || !bytes.Equal(udpRead(first), a) {
			panic("UDP reordering was lost")
		}
		udpLost(first, []byte{0xdd, 1, 2, 3})
		udpExchange(first, []byte{0xda, 1, 2, 3})
		_, err = first.Write([]byte{0xfc})
		must(err)
		if !bytes.Equal(udpRead(first), []byte{0xfb, 1, 2, 3}) {
			panic("oversize local reply was truncated or merged")
		}
		// A bounded burst on one source preserves every complete frame.
		for i := 0; i < 64; i++ {
			_, err = second.Write([]byte{0x80, byte(i)})
			must(err)
		}
		seen := make(map[byte]bool)
		for range 64 {
			packet := udpRead(second)
			if len(packet) != 2 || packet[0] != 0x80 || packet[1] >= 64 || seen[packet[1]] {
				panic("burst datagram corrupted/duplicated")
			}
			seen[packet[1]] = true
		}
		third, fourth, fifth := udpRemote(address), udpRemote(address), udpRemote(address)
		defer third.Close()
		defer fourth.Close()
		defer fifth.Close()
		udpExchange(third, []byte{3})
		udpExchange(fourth, []byte{4})
		udpLost(fifth, []byte{5})
		before := state()
		if before.remotes != 4 || before.active != 1 || before.dropped < 2 {
			panic(fmt.Sprintf("unbounded UDP remote table: %+v", before))
		}
		if idle {
			// Real time proves per-source expiry and the separate work Ping.
			time.Sleep(31 * time.Second)
			expired := state()
			if expired.remotes != 0 || expired.expired < 4 {
				panic(fmt.Sprintf("UDP sources did not expire: %+v", expired))
			}
			time.Sleep(35 * time.Second)
			udpExchange(first, []byte{0xda, 7, 8, 9})
			after := state()
			if after.requests != before.requests || after.active != 1 {
				panic(fmt.Sprintf("UDP idle work connection was replaced: before=%+v after=%+v", before, after))
			}
		}
	}
	_, err = input.Write([]byte{'q'})
	must(err)
	must(input.Close())
	if err = cmd.Wait(); err != nil {
		panic(fmt.Sprintf("UDP peer failed: %v\n%s", err, stderr.String()))
	}
	fmt.Print(stderr.String())
}
func runUDP(path string) {
	local := udpListener()
	defer local.Close()
	go udpEcho(local)
	withSessionServer(func(port int, caPath, dir string) {
		udpCase(path, caPath, port, local, 16, false)
		udpCase(path, caPath, port, local, 1500, true)
	})
	fmt.Println("Official FRPS UDP: binary negotiation, empty/maximum configured packets, two sources/100 rounds, loss/reorder/burst, bounded sources/expiry, 66-second idle Ping and fd recovery passed")
}
