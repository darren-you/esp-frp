// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/hashicorp/yamux"
)

func serve(conn net.Conn, round int) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	config := yamux.DefaultConfig()
	config.MaxStreamWindowSize = 6 * 1024 * 1024
	config.KeepAliveInterval = 100 * time.Millisecond
	session, err := yamux.Server(conn, config)
	if err != nil {
		return err
	}
	defer session.Close()
	done := make(chan error, 2)
	for index := 0; index < 2; index++ {
		stream, err := session.AcceptStream()
		if err != nil {
			return err
		}
		go func(index int) {
			payload := make([]byte, 300001)
			for offset := range payload {
				payload[offset] = byte(offset*17 + round*13 + index*29)
			}
			written := make(chan error, 1)
			go func() {
				n, err := stream.Write(payload)
				if err == nil && n != len(payload) {
					err = io.ErrShortWrite
				}
				written <- err
			}()
			echo := make([]byte, len(payload))
			_, err := io.ReadFull(stream, echo)
			if err == nil && !bytes.Equal(payload, echo) {
				err = fmt.Errorf("round %d stream %d payload mismatch", round, index)
			}
			if writeErr := <-written; err == nil {
				err = writeErr
			}
			if closeErr := stream.Close(); err == nil {
				err = closeErr
			}
			if err == nil {
				var tail [1]byte
				n, readErr := stream.Read(tail[:])
				if n != 0 || readErr != io.EOF {
					err = fmt.Errorf("round %d stream %d missing peer FIN: n=%d error=%v", round, index, n, readErr)
				}
			}
			done <- err
		}(index)
	}
	for range 2 {
		if err := <-done; err != nil {
			return err
		}
	}
	return nil
}

func run() error {
	client := flag.String("client", "", "本仓构建的 C Yamux peer 绝对路径")
	rounds := flag.Int("rounds", 100, "TCP 会话重建次数（1–100）")
	flag.Parse()
	if *client == "" || *rounds < 1 || *rounds > 100 {
		return fmt.Errorf("必须提供 client，rounds 必须为 1–100")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, *client, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), strconv.Itoa(*rounds))
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		return err
	}
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- command.Wait()
		listener.Close() // A crashed client must not strand the accept loop.
	}()
	for round := 0; round < *rounds; round++ {
		conn, err := listener.Accept()
		if err == nil {
			err = serve(conn, round)
		}
		if err != nil {
			cancel()
			<-clientDone
			return fmt.Errorf("互操作 round %d: %w", round, err)
		}
	}
	if err := <-clientDone; err != nil {
		return fmt.Errorf("C peer: %w", err)
	}
	fmt.Printf("固定上游 Yamux：%d 次双流、双向字节与 FIN 验证通过。\n", *rounds)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
