// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func certificate(variant string) (tls.Certificate, []byte) {
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public TLS fixture CA"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(72 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	must(err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"frp.fixture.invalid"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if variant == "expired" {
		leaf.NotBefore = now.Add(-24 * time.Hour)
		leaf.NotAfter = now.Add(-time.Hour)
	}
	if variant == "future" {
		leaf.NotBefore = now.Add(24 * time.Hour)
		leaf.NotAfter = now.Add(48 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	must(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func tlsCase(path, dir, mode, variant string, version uint16, rounds int) {
	cert, ca := certificate(variant)
	host := "frp.fixture.invalid"
	if variant == "wrong-host" {
		host = "wrong.fixture.invalid"
	}
	if variant == "wrong-ca" {
		_, ca = certificate("ok")
	}
	caPath := filepath.Join(dir, "fixture-ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	defer listener.Close()
	results := make(chan error, rounds)
	go func() {
		for round := 0; round < rounds; round++ {
			raw, err := listener.Accept()
			if err != nil {
				results <- err
				return
			}
			func() {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
				if mode == "stall" || mode == "cancel-handshake" {
					_, _ = io.Copy(io.Discard, raw)
					results <- nil
					return
				}
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version,
					SessionTicketsDisabled: false})
				err := conn.Handshake()
				if mode == "reject" {
					if err == nil {
						err = fmt.Errorf("client accepted invalid trust")
					} else {
						err = nil
					}
					results <- err
					return
				}
				if err != nil {
					results <- err
					return
				}
				if conn.ConnectionState().ServerName != host {
					results <- fmt.Errorf("missing SNI")
					return
				}
				if mode == "abrupt" {
					results <- nil
					return
				}
				if mode == "clean" {
					results <- conn.Close()
					return
				}
				if strings.HasPrefix(mode, "stall-") || mode == "cancel-write" {
					_, _ = io.Copy(io.Discard, conn)
					results <- nil
					return
				}
				greeting := make([]byte, 70001)
				for i := range greeting {
					greeting[i] = byte(i * 13)
				}
				_, err = conn.Write(greeting)
				if err != nil {
					results <- err
					return
				}
				var total int64
				buf := make([]byte, 16384)
				for {
					n, readErr := conn.Read(buf)
					if n > 0 {
						for i, v := range buf[:n] {
							if v != byte((total+int64(i))*31) {
								results <- fmt.Errorf("outbound byte mismatch")
								return
							}
						}
						total += int64(n)
						if _, err = conn.Write(buf[:n]); err != nil {
							results <- err
							return
						}
					}
					if readErr != nil {
						if readErr != io.EOF || total != 200001 {
							results <- fmt.Errorf("close=%v bytes=%d", readErr, total)
						} else {
							results <- nil
						}
						return
					}
				}
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, strconv.Itoa(port), caPath, host, mode, strconv.Itoa(rounds), strconv.Itoa(int(version)))
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("TLS %s/%s: %v\n%s", mode, variant, err, out))
	}
	for round := 0; round < rounds; round++ {
		select {
		case err := <-results:
			must(err)
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	fmt.Print(string(out))
}

func runTLS(path string) {
	dir, err := os.MkdirTemp("", "esp-frp-tls-")
	must(err)
	defer os.RemoveAll(dir)
	_, ca := certificate("ok")
	caPath := filepath.Join(dir, "contract-ca.pem")
	must(os.WriteFile(caPath, ca, 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "1", caPath, "frp.fixture.invalid", "contract", "1", "772").CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("TLS contract: %v\n%s", err, out))
	}
	fmt.Print(string(out))
	tlsCase(path, dir, "ok", "ok", tls.VersionTLS13, 100)
	tlsCase(path, dir, "ok", "ok", tls.VersionTLS12, 1)
	tlsCase(path, dir, "split", "ok", tls.VersionTLS13, 1)
	for _, variant := range []string{"wrong-ca", "wrong-host", "expired", "future"} {
		tlsCase(path, dir, "reject", variant, tls.VersionTLS13, 1)
	}
	for _, mode := range []string{"stall", "cancel-handshake", "cancel-write", "stall-write", "stall-close", "abrupt", "clean"} {
		tlsCase(path, dir, mode, "ok", tls.VersionTLS13, 1)
	}
	fmt.Println("Mbed TLS/Go TLS: versions, trust, partial I/O, cancellation, deadlines and 100 lifecycles passed")
}
