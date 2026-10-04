// SPDX-License-Identifier: Apache-2.0
// Run in ../crypto-interop with its exact public quic-go dependency lock.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	quic "github.com/quic-go/quic-go"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

func require(err error) {
	if err != nil {
		panic(err)
	}
}

type badSigner struct{ key, other *ecdsa.PrivateKey }

func (s badSigner) Public() crypto.PublicKey { return &s.key.PublicKey }
func (s badSigner) Sign(r io.Reader, hash []byte, options crypto.SignerOpts) ([]byte, error) {
	return s.other.Sign(r, hash, options)
}
func makeIdentity(server bool, mode string) (tls.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require(err)
	name, usage := "esp-frp-xtcp-visitor", x509.ExtKeyUsageClientAuth
	if server {
		name, usage = "esp-frp-xtcp-provider", x509.ExtKeyUsageServerAuth
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(120 * time.Second), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	switch mode {
	case "wrong-san":
		cert.DNSNames = []string{"wrong-peer-role"}
	case "expired":
		cert.NotBefore, cert.NotAfter = now.Add(-120*time.Second), now.Add(-60*time.Second)
	case "future":
		cert.NotBefore, cert.NotAfter = now.Add(60*time.Second), now.Add(120*time.Second)
	case "missing-ku":
		cert.KeyUsage = 0
	case "missing-eku":
		cert.ExtKeyUsage = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require(err)
	if mode == "bad-self-signature" {
		der[len(der)-1] ^= 1
	}
	var signer crypto.PrivateKey = key
	if mode == "bad-signature" {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require(err)
		signer = badSigner{key, other}
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer}, der
}
func run(path, directory, role, mode string) {
	cServer := role == "provider"
	cert, der := makeIdentity(!cServer, mode)
	peerPath, ownPath := filepath.Join(directory, role+"-"+mode+"-go.der"), filepath.Join(directory, role+"-"+mode+"-c.der")
	require(os.WriteFile(peerPath, der, 0600))
	reserved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require(err)
	cPort := reserved.LocalAddr().(*net.UDPAddr).Port
	require(reserved.Close())
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require(err)
	defer socket.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, role, mode, strconv.Itoa(cPort), strconv.Itoa(socket.LocalAddr().(*net.UDPAddr).Port), peerPath, ownPath)
	input, err := command.StdinPipe()
	require(err)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	require(command.Start())
	var own *x509.Certificate
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		data, err := os.ReadFile(ownPath)
		if err == nil {
			own, err = x509.ParseCertificate(data)
			if err == nil {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if own == nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		panic("C PSA identity was not produced: " + output.String())
	}
	roots := x509.NewCertPool()
	roots.AddCert(own)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"esp-frp-xtcp/1"}, Certificates: []tls.Certificate{cert},
		RootCAs: roots, ClientCAs: roots, ServerName: "esp-frp-xtcp-provider"}
	if !cServer {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if mode == "wrong-alpn" {
		tlsConfig.NextProtos = []string{"frp"}
	}
	if mode == "missing-client" {
		tlsConfig.Certificates = nil
	}
	ownPin := sha256.Sum256(own.RawSubjectPublicKeyInfo)
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo) != ownPin {
			return fmt.Errorf("C SPKI differs from authenticated fixture material")
		}
		return nil
	}
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	var listener *quic.Listener
	if !cServer {
		listener, err = transport.Listen(tlsConfig, &quic.Config{MaxIncomingStreams: 4, MaxIncomingUniStreams: -1})
		require(err)
		defer listener.Close()
	}
	done := make(chan error, 1)
	go func() {
		var err error
		var conn *quic.Conn
		if cServer {
			conn, err = transport.Dial(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cPort}, tlsConfig, &quic.Config{MaxIncomingStreams: -1, MaxIncomingUniStreams: -1})
		} else {
			conn, err = listener.Accept(ctx)
		}
		if err != nil {
			done <- err
			return
		}
		state := conn.ConnectionState().TLS
		manifest := make([]byte, 32)
		manifest[0] = 1
		if mode == "different-context" {
			manifest[0] = 2
		}
		exporter, err := state.ExportKeyingMaterial("EXPORTER-esp-frp-xtcp-peer-v1", manifest, 32)
		if err != nil {
			done <- err
			return
		}
		expected := sha256.Sum256(exporter)
		var stream *quic.Stream
		if cServer {
			stream, err = conn.OpenStreamSync(ctx)
		} else {
			stream, err = conn.AcceptStream(ctx)
		}
		if err != nil {
			done <- err
			return
		}
		if cServer {
			_, err = stream.Write(expected[:])
			if err == nil {
				err = stream.Close()
			}
		}
		if err != nil {
			done <- err
			return
		}
		proof, err := io.ReadAll(io.LimitReader(stream, 33))
		if err == nil && mode != "different-context" && !bytes.Equal(proof, expected[:]) {
			err = fmt.Errorf("TLS exporter proof differs")
		}
		if err != nil {
			done <- err
			return
		}
		if !cServer {
			_, err = stream.Write(expected[:])
			if err == nil {
				err = stream.Close()
			}
		}
		if err != nil {
			done <- err
			return
		}
		if mode != "ok" {
			done <- nil
			return
		}
		var workers sync.WaitGroup
		failures := make(chan error, 2)
		for slot := 1; slot <= 2; slot++ {
			if cServer {
				stream, err = conn.OpenStreamSync(ctx)
			} else {
				stream, err = conn.AcceptStream(ctx)
			}
			if err != nil {
				done <- err
				return
			}
			workers.Add(1)
			go func(slot int, stream *quic.Stream) {
				var err error
				defer workers.Done()
				data := make([]byte, 35017)
				for i := range data {
					data[i] = byte(i*23 + slot*11)
				}
				if cServer {
					_, err = stream.Write(data)
					if err == nil {
						err = stream.Close()
					}
				}
				received, e := io.ReadAll(io.LimitReader(stream, 35018))
				if e == nil && !bytes.Equal(data, received) {
					e = fmt.Errorf("bidi %d payload differs", slot)
				}
				if !cServer && e == nil {
					_, e = stream.Write(data)
					if e == nil {
						e = stream.Close()
					}
				}
				failures <- e
			}(slot, stream)
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
	_, err = input.Write([]byte{'G'})
	require(err)
	require(input.Close())
	err = command.Wait()
	if mode == "ok" {
		if err != nil {
			panic(fmt.Sprintf("candidate %s: %v %s", role, err, output.String()))
		}
		require(<-done)
		if !bytes.Contains(output.Bytes(), []byte("handshake=1 bound=1 business=2 bytes=70034")) {
			panic("candidate lacked bidirectional binding evidence")
		}
	} else {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 10 || !bytes.Contains(output.Bytes(), []byte("bound=0 business=0")) {
			panic(fmt.Sprintf("candidate negative %s/%s: %v %s", role, mode, err, output.String()))
		}
	}
	cancel()
	fmt.Printf("QUIC peer %s/%s: %s", role, mode, output.String())
}
func main() {
	peer := flag.String("peer", "", "formal typed peer transport executable")
	flag.Parse()
	if *peer == "" {
		panic("peer required")
	}
	directory, err := os.MkdirTemp("", "esp-frp-quic-peer-")
	require(err)
	defer os.RemoveAll(directory)
	for _, role := range []string{"visitor", "provider"} {
		for _, mode := range []string{"ok", "wrong-pin", "wrong-alpn", "bad-signature", "different-context", "wrong-san", "expired", "future", "missing-ku", "missing-eku", "bad-self-signature"} {
			run(*peer, directory, role, mode)
		}
	}
	run(*peer, directory, "provider", "missing-client")
	run(*peer, directory, "provider", "delayed-initial")
}
