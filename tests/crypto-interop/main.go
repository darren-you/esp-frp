// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/fatedier/frp/pkg/proto/wire"
	frpnet "github.com/fatedier/frp/pkg/util/net"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func peer(path string, capacity int, token, client, server, encrypted []byte, reject bool) []byte {
	var input bytes.Buffer
	must(binary.Write(&input, binary.BigEndian, uint32(capacity)))
	for _, b := range [][]byte{token, client, server, encrypted} {
		must(binary.Write(&input, binary.BigEndian, uint32(len(b))))
		_, err := input.Write(b)
		must(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = &input
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if reject {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 10 || len(out) != 0 {
			panic(fmt.Sprintf("negative peer: err=%v output=%d stderr=%s", err, len(out), stderr.String()))
		}
	} else if err != nil {
		panic(fmt.Sprintf("peer: %v %s", err, stderr.String()))
	}
	return out
}

func official(rw io.ReadWriter, token, client, server []byte, role frpnet.AEADCryptoRole) io.ReadWriter {
	crypto, err := wire.NewClientCryptoContext(client, server)
	must(err)
	stream, err := frpnet.NewAEADCryptoReadWriter(rw, token, role, crypto.Algorithm, crypto.TranscriptHash)
	must(err)
	return stream
}

func run(path string) {
	// Only public generated fixtures; no socket, server configuration or credentials.
	token := []byte("esp-frp-public-interop-token")
	lengths := []int{0, 1, 15, 16, 17, 511, 512, 513, 65535, 65536, 65537, 300001}
	negative := 0
	for round, length := range lengths {
		ch, err := wire.NewClientHello(wire.BootstrapInfo{Transport: "tcp", TLS: true, TCPMux: true})
		must(err)
		ch.Capabilities.Crypto.Algorithms = []string{wire.AEADAlgorithmAES256GCM}
		sh, err := wire.NewServerHello(ch)
		must(err)
		client, err := json.MarshalIndent(ch, "", " ")
		must(err)
		server, err := json.Marshal(sh)
		must(err)
		// Deliberate legal JSON whitespace must be retained in the transcript.
		client = append([]byte(" \n"), client...)
		plain := make([]byte, length)
		for i := range plain {
			plain[i] = byte(i*31 + round)
		}
		var outbound bytes.Buffer
		stream := official(&outbound, token, client, server, frpnet.AEADCryptoRoleServer)
		n, err := stream.Write(plain)
		must(err)
		if n != len(plain) {
			panic("official short write")
		}
		ciphertext := append([]byte(nil), outbound.Bytes()...)
		capacity := 4128
		if length <= 513 {
			capacity = 33
		} else if round%2 == 0 {
			capacity = 65568
		}
		out := peer(path, capacity, token, client, server, ciphertext, false)
		if len(out) < 32 || !bytes.Equal(out[:32], wire.HashCryptoTranscript(client, server)) {
			panic("transcript mismatch")
		}
		received := bytes.NewBuffer(out[32:])
		decoded, err := io.ReadAll(official(received, token, client, server, frpnet.AEADCryptoRoleServer))
		must(err)
		if !bytes.Equal(decoded, plain) {
			panic("bidirectional plaintext mismatch")
		}
		if length == 65536 {
			for _, index := range []int{0, 11, 16, len(ciphertext) - 1} {
				bad := append([]byte(nil), ciphertext...)
				bad[index] ^= 1
				peer(path, capacity, token, client, server, bad, true)
				negative++
			}
			peer(path, capacity, append(token, '!'), client, server, ciphertext, true)
			negative++
			peer(path, capacity, token, append(client, ' '), server, ciphertext, true)
			negative++
			peer(path, capacity, token, client, append(server, ' '), ciphertext, true)
			negative++
			peer(path, capacity, token, client, server, ciphertext[:len(ciphertext)-1], true)
			negative++
			// Reflection: outgoing client-to-server records cannot enter the client's reader.
			peer(path, capacity, token, client, server, out[32:], true)
			negative++
		}
		if length == 300001 {
			firstEnd := 16 + int(binary.BigEndian.Uint32(ciphertext[12:16]))
			secondEnd := firstEnd + 4 + int(binary.BigEndian.Uint32(ciphertext[firstEnd:firstEnd+4]))
			bad := append([]byte(nil), ciphertext[:12]...)
			bad = append(bad, ciphertext[firstEnd:secondEnd]...)
			bad = append(bad, ciphertext[12:firstEnd]...)
			bad = append(bad, ciphertext[secondEnd:]...)
			peer(path, capacity, token, client, server, bad, true)
			negative++
		}
	}
	fmt.Printf("Official FRP v0.71.0 AEAD: %d bidirectional cases, %d rejection cases passed\n", len(lengths), negative)
}

func main() {
	path := flag.String("peer", "", "C AEAD peer executable")
	handshake := flag.String("handshake-peer", "", "C Hello/Login peer executable")
	handshakeArch := flag.String("handshake-arch", "riscv32", "expected FRP Login arch for the handshake peer")
	tlsPeer := flag.String("tls-peer", "", "C Mbed TLS peer executable")
	sessionPeer := flag.String("session-peer", "", "C composed control session peer")
	clientPeer := flag.String("client-peer", "", "C single-worker lifecycle peer")
	workPeer := flag.String("work-peer", "", "C composed local TCP forwarding peer")
	workFaults := flag.Bool("work-faults", false, "Run work rejection/half-close fixtures instead of the 100 dual-flow rounds")
	deviceConfig := flag.String("device-config", "", "仓外 0600 JSON：单次真实设备协议 fixture，不执行刷写")
	flag.Parse()
	if *deviceConfig != "" {
		must(runDeviceFixture(*deviceConfig))
		return
	}
	if *clientPeer != "" {
		runClient(*clientPeer)
		return
	}
	if *workPeer != "" {
		runWork(*workPeer, *workFaults)
		return
	}
	if *sessionPeer != "" {
		runSession(*sessionPeer)
		return
	}
	if *tlsPeer != "" {
		runTLS(*tlsPeer)
		return
	}
	if *handshake != "" {
		runHandshake(*handshake, *handshakeArch)
		return
	}
	if *path == "" {
		fmt.Fprintln(os.Stderr, "-peer is required")
		os.Exit(2)
	}
	run(*path)
}
