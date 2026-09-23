// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"syscall"
)

// The established official TLS connection transports deliberately invalid
// fixed Yamux headers. This is not a second Yamux implementation: no streams,
// flow control, framing loop or valid business transport are implemented here.
func serveYamuxFault(conn *tls.Conn, mode string) error {
	var syn [12]byte
	if _, err := io.ReadFull(conn, syn[:]); err != nil {
		return err
	}
	if syn[0] != 0 || syn[1] != 1 || binary.BigEndian.Uint16(syn[2:4]) != 1 ||
		binary.BigEndian.Uint32(syn[4:8]) != 1 || binary.BigEndian.Uint32(syn[8:]) != 0 {
		return fmt.Errorf("missing initial control stream SYN")
	}
	header := []byte{0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0}
	switch mode {
	case "fixture-bad-yamux-version":
		header[0] = 1
	case "fixture-bad-yamux-type":
		header[1] = 4
	case "fixture-bad-yamux-flags":
		header[3] = 3
	case "fixture-bad-yamux-credit":
		header[1] = 0
		binary.BigEndian.PutUint32(header[8:], 262145)
	case "fixture-bad-yamux-window":
		binary.BigEndian.PutUint32(header[8:], 0xffffffff)
	case "fixture-bad-yamux-stream":
		binary.BigEndian.PutUint32(header[4:8], 2)
	case "fixture-yamux-reset":
		header[3] = 8
	case "fixture-yamux-truncated":
		header = header[:5]
	default:
		return fmt.Errorf("unknown Yamux fault fixture")
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if mode == "fixture-yamux-truncated" {
		return conn.Close()
	}
	_, err := io.Copy(io.Discard, conn)
	// The client's bounded cancellation uses an abortive socket close, which
	// can arrive as EOF, bare TLS EOF or RST after the injected invalid header.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return nil
	}
	return err
}
