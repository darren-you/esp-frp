// SPDX-License-Identifier: Apache-2.0
// Run from ../crypto-interop to consume its existing exact public Go lock.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type wrongSigner struct{ key, other *ecdsa.PrivateKey }

// Deterministic whole-datagram loss/reordering on the real Go peer socket.
// Never edit plaintext, weaken TLS, or mock ngtcp2 ACK callbacks.
type lossyPackets struct {
	net.PacketConn
	mutex                        sync.Mutex
	sequence, dropped, reordered int
	pending                      []byte
	address                      net.Addr
}

func (packets *lossyPackets) WriteTo(data []byte, address net.Addr) (int, error) {
	packets.mutex.Lock()
	defer packets.mutex.Unlock()
	packets.sequence++
	if packets.sequence%17 == 0 {
		packets.dropped++
		return len(data), nil
	}
	if packets.pending == nil && packets.sequence%13 == 0 {
		packets.pending = append([]byte(nil), data...)
		packets.address = address
		return len(data), nil
	}
	n, err := packets.PacketConn.WriteTo(data, address)
	if err == nil && packets.pending != nil {
		_, err = packets.PacketConn.WriteTo(packets.pending, packets.address)
		packets.pending = nil
		packets.reordered++
	}
	return n, err
}

func (signer wrongSigner) Public() crypto.PublicKey { return &signer.key.PublicKey }
func (signer wrongSigner) Sign(random io.Reader, digest []byte, options crypto.SignerOpts) ([]byte, error) {
	return signer.other.Sign(random, digest, options)
}

func certificate(mode string) (tls.Certificate, []byte) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public QUIC fixture CA"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	must(err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"quic.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if mode == "expired" {
		leaf.NotBefore, leaf.NotAfter = now.Add(-3*time.Hour), now.Add(-2*time.Hour)
	}
	if mode == "future" {
		leaf.NotBefore, leaf.NotAfter = now.Add(2*time.Hour), now.Add(3*time.Hour)
	}
	if mode == "client-usage" {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if mode == "no-signature-usage" {
		leaf.KeyUsage = x509.KeyUsageKeyEncipherment
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	must(err)
	var signer crypto.PrivateKey = key
	if mode == "bad-certificate-verify" {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		signer = wrongSigner{key, other}
	}
	if mode == "untrusted-ca" {
		otherCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		ca.Subject.CommonName = "different public fixture CA"
		caDER, err = x509.CreateCertificate(rand.Reader, ca, ca, &otherCAKey.PublicKey, otherCAKey)
		must(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: signer}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func runCase(path, directory, mode string, transport bool) {
	cert, ca := certificate(mode)
	caPath := filepath.Join(directory, mode+"-ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	alpn := "frp"
	if mode == "wrong-alpn" {
		alpn = "other"
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	must(err)
	defer socket.Close()
	var packets net.PacketConn = socket
	var lossy *lossyPackets
	if mode == "loss-reorder" {
		lossy = &lossyPackets{PacketConn: socket}
		packets = lossy
	}
	listener, err := quic.Listen(packets, &tls.Config{Certificates: []tls.Certificate{cert},
		MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}}, &quic.Config{MaxIncomingStreams: 2, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 4096, InitialConnectionReceiveWindow: 8192,
		MaxConnectionReceiveWindow: 8192, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 10 * time.Second})
	must(err)
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	done := make(chan error, 1)
	size := 4096
	if mode == "long" || mode == "loss-reorder" {
		size = 257031
	}
	go func() {
		connection, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		state := connection.ConnectionState().TLS
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "frp" {
			done <- fmt.Errorf("server TLS/ALPN differs")
			return
		}
		if mode == "oversized" {
			time.Sleep(20 * time.Millisecond)
			_, err := socket.WriteTo(make([]byte, 2001), connection.RemoteAddr())
			done <- err
			return
		}
		if mode == "cancel-eagain" || mode == "cancel-fail" || mode == "cancel-timeout" {
			wait := time.Second
			if mode == "cancel-eagain" {
				wait = 3 * time.Second
			}
			attempt, stop := context.WithTimeout(ctx, wait)
			defer stop()
			stream, err := connection.AcceptStream(attempt)
			if stream != nil {
				done <- fmt.Errorf("cancel leaked a pre-cancel business stream")
				return
			}
			if mode == "cancel-eagain" {
				var closed *quic.ApplicationError
				if !errors.As(err, &closed) || closed.ErrorCode != 0 {
					done <- fmt.Errorf("cancel did not send authenticated CONNECTION_CLOSE: %v", err)
					return
				}
			}
			done <- nil
			return
		}
		if mode == "reset" || mode == "late-stop-error" || mode == "late-stop-no-fin" {
			stream, err := connection.AcceptStream(ctx)
			if err == nil {
				if mode == "reset" {
					_, err = io.ReadFull(stream, make([]byte, 257))
					stream.CancelRead(42)
					stream.CancelWrite(43)
				} else {
					data := make([]byte, 512)
					_, err = io.ReadFull(stream, data)
					if mode == "late-stop-error" {
						if err == nil {
							_, err = stream.Write(data)
						}
						if err == nil {
							err = stream.Close()
						}
						stream.CancelRead(45)
					} else {
						stream.CancelRead(0)
						stream.CancelWrite(0)
					}
				}
			}
			done <- err
			return
		}
		var workers sync.WaitGroup
		failures := make(chan error, 2)
		for id := 0; id < 2; id++ {
			stream, err := connection.AcceptStream(ctx)
			if err != nil {
				done <- err
				return
			}
			workers.Add(1)
			go func(id int, stream *quic.Stream) {
				defer workers.Done()
				var data []byte
				var err error
				if mode == "late-stop-zero" {
					data = make([]byte, size)
					_, err = io.ReadFull(stream, data)
				} else {
					data, err = io.ReadAll(io.LimitReader(stream, int64(size+1)))
				}
				if err == nil && len(data) != size {
					err = fmt.Errorf("stream %d size %d", id, len(data))
				}
				for index, value := range data {
					if value != byte(index*31+id*7) {
						err = fmt.Errorf("stream %d byte mismatch", id)
						break
					}
				}
				if err == nil {
					_, err = stream.Write(data)
				}
				if err == nil {
					err = stream.Close()
				}
				if mode == "late-stop-zero" {
					stream.CancelRead(0)
				}
				failures <- err
			}(id, stream)
		}
		workers.Wait()
		for i := 0; i < 2; i++ {
			if err := <-failures; err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	hostname := "quic.example.test"
	if mode == "wrong-hostname" {
		hostname = "different.example.test"
	}
	command := exec.CommandContext(ctx, path, strconv.Itoa(listener.Addr().(*net.UDPAddr).Port), caPath, hostname, mode)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	err = command.Run()
	if mode == "ok" || mode == "long" || mode == "loss-reorder" || mode == "reset" ||
		mode == "late-stop-zero" || mode == "late-stop-error" || mode == "late-stop-no-fin" ||
		mode == "cancel-eagain" || mode == "cancel-fail" || mode == "cancel-timeout" {
		if err != nil {
			panic(fmt.Sprintf("QUIC %s: %v %s", mode, err, output.String()))
		}
		must(<-done)
		evidence := "signature=1 handshake=1 dual_fin=1"
		if transport {
			evidence = "verify_flags=0 handshake=1 dual_fin=1"
		}
		if mode == "reset" || mode == "late-stop-error" || mode == "late-stop-no-fin" {
			evidence = "reset_released=1"
		}
		if mode == "cancel-eagain" || mode == "cancel-fail" || mode == "cancel-timeout" {
			evidence = "cancel_drained=1"
		}
		if !bytes.Contains(output.Bytes(), []byte(evidence)) {
			panic("success lacked authenticated stream evidence")
		}
		if lossy != nil {
			lossy.mutex.Lock()
			if lossy.dropped == 0 || lossy.reordered == 0 {
				panic("loss/reordering fixture made no actual packet changes")
			}
			fmt.Printf("real whole UDP loss=%d reorder=%d\n", lossy.dropped, lossy.reordered)
			lossy.mutex.Unlock()
		}
	} else if mode == "oversized" {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 10 || !bytes.Contains(output.Bytes(), []byte("handshake=1")) ||
			!bytes.Contains(output.Bytes(), []byte("transport result=-2")) {
			panic(fmt.Sprintf("oversized whole UDP: %v %s", err, output.String()))
		}
		must(<-done)
	} else {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 10 || bytes.Contains(output.Bytes(), []byte("handshake=1")) {
			panic(fmt.Sprintf("negative QUIC %s: %v %s", mode, err, output.String()))
		}
		evidence := "certificate=1 signature=1 handshake=0"
		if transport {
			evidence = "tls_error=51"
		}
		if mode == "bad-certificate-verify" && !bytes.Contains(output.Bytes(), []byte(evidence)) {
			panic("CertificateVerify rejection did not reach real signature verification")
		}
	}
	fmt.Printf("QUIC %s: %s", mode, output.String())
}

func main() {
	peer := flag.String("peer", "", "strict Picotls/minicrypto/PSA client executable")
	transport := flag.Bool("transport", false, "exercise formal owned transport factory and bounded stream API")
	flag.Parse()
	if *peer == "" {
		panic("peer required")
	}
	directory, err := os.MkdirTemp("", "esp-frp-quic-fixture-")
	must(err)
	defer os.RemoveAll(directory)
	for _, mode := range []string{"ok", "wrong-hostname", "expired", "future", "untrusted-ca", "client-usage",
		"no-signature-usage", "bad-certificate-verify", "untrusted-time", "wrong-alpn"} {
		runCase(*peer, directory, mode, *transport)
	}
	if *transport {
		runCase(*peer, directory, "long", true)
		runCase(*peer, directory, "loss-reorder", true)
		runCase(*peer, directory, "reset", true)
		runCase(*peer, directory, "oversized", true)
		runCase(*peer, directory, "late-stop-zero", true)
		runCase(*peer, directory, "late-stop-error", true)
		runCase(*peer, directory, "late-stop-no-fin", true)
		runCase(*peer, directory, "cancel-eagain", true)
		runCase(*peer, directory, "cancel-fail", true)
		runCase(*peer, directory, "cancel-timeout", true)
	} else {
		runFRPS(*peer, directory)
	}
}
