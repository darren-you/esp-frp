// SPDX-License-Identifier: Apache-2.0
// Run from peer/frp: consume the maintained candidate's real proof consumer.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/fatedier/frp/pkg/xtcpbinding"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const bodyBytes = 300001

func require(err error) {
	if err != nil {
		panic(err)
	}
}
func body(slot int, response bool) []byte {
	value := make([]byte, bodyBytes)
	for i := range value {
		if response {
			value[i] = byte(i*19 + slot*29)
		} else {
			value[i] = byte(i*23 + slot*7)
		}
	}
	return value
}
func readBody(r io.Reader) (int, error) {
	data, err := io.ReadAll(io.LimitReader(r, bodyBytes+1))
	if err != nil {
		return 0, err
	}
	if len(data) != bodyBytes {
		return 0, fmt.Errorf("received %d payload bytes", len(data))
	}
	slot := int(data[0]) / 7
	if (slot != 1 && slot != 2) || !bytes.Equal(data, body(slot, false)) {
		return 0, fmt.Errorf("request body differs")
	}
	return slot, nil
}
func reserve(network string) int {
	if network == "udp" {
		s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require(err)
		p := s.LocalAddr().(*net.UDPAddr).Port
		require(s.Close())
		return p
	}
	s, err := net.Listen("tcp4", "127.0.0.1:0")
	require(err)
	p := s.Addr().(*net.TCPAddr).Port
	require(s.Close())
	return p
}
func alteredProof(ctx context.Context, conn *quic.Conn, m xtcpbinding.Manifest, role byte, mode string) error {
	exporter, err := xtcpbinding.Exporter(conn, m)
	if err != nil {
		return err
	}
	defer clear(exporter)
	var stream *quic.Stream
	if role == xtcpbinding.Visitor {
		stream, err = conn.OpenStreamSync(ctx)
	} else {
		stream, err = conn.AcceptStream(ctx)
	}
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		return fmt.Errorf("proof stream is not reserved0")
	}
	if d, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(d)
	}
	if role == xtcpbinding.Provider {
		peer, err := io.ReadAll(io.LimitReader(stream, 70))
		if err != nil {
			return err
		}
		if err = m.Verify(xtcpbinding.Visitor, exporter, peer); err != nil {
			return err
		}
	}
	sender := role
	if mode == "wrong-role" {
		if sender == xtcpbinding.Provider {
			sender = xtcpbinding.Visitor
		} else {
			sender = xtcpbinding.Provider
		}
	}
	proof, err := m.Proof(sender, exporter)
	if err != nil {
		return err
	}
	if mode == "trailing" {
		proof = append(proof, 0)
	}
	if mode == "truncated" {
		proof = proof[:len(proof)-1]
	}
	if _, err = stream.Write(proof); err != nil {
		return err
	}
	return stream.Close()
}
func run(path, directory, roleName, mode string) {
	success := mode == "ok" || mode == "credit-block"
	cRole, goRole := byte(xtcpbinding.Provider), byte(xtcpbinding.Visitor)
	if roleName == "visitor" {
		cRole, goRole = xtcpbinding.Visitor, xtcpbinding.Provider
	}
	identity, err := xtcpbinding.NewIdentity(goRole)
	require(err)
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require(err)
	defer socket.Close()
	cUDP, cTCP := reserve("udp"), reserve("tcp")
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	require(err)
	defer backend.Close()
	ownPath := filepath.Join(directory, roleName+"-"+mode+".der")
	manifestPath := filepath.Join(directory, roleName+"-"+mode+".manifest")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, roleName, mode, strconv.Itoa(cUDP), strconv.Itoa(socket.LocalAddr().(*net.UDPAddr).Port), ownPath, manifestPath, strconv.Itoa(cTCP), strconv.Itoa(backend.Addr().(*net.TCPAddr).Port))
	input, err := command.StdinPipe()
	require(err)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	require(command.Start())
	var ownDER []byte
	var own *x509.Certificate
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		ownDER, err = os.ReadFile(ownPath)
		if err == nil {
			own, err = x509.ParseCertificate(ownDER)
			if err == nil {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	if own == nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		panic("C identity missing: " + output.String())
	}
	ownPin := sha256.Sum256(own.RawSubjectPublicKeyInfo)
	m := xtcpbinding.Manifest{ProxyName: "direct-peer-work", IssuedAt: uint64(time.Now().Unix()), ExpiresAt: uint64(time.Now().Unix() + 60)}
	requireFill := func(v []byte) { _, e := rand.Read(v); require(e) }
	requireFill(m.SID[:])
	for i := range m.ProviderControl {
		m.ProviderControl[i] = 11
		m.VisitorControl[i] = 12
		m.ProviderNonce[i] = 21
		m.VisitorNonce[i] = 22
	}
	if cRole == xtcpbinding.Provider {
		m.ProviderSPKI, m.VisitorSPKI = ownPin, identity.SPKI
	} else {
		m.ProviderSPKI, m.VisitorSPKI = identity.SPKI, ownPin
	}
	canonical, err := m.Encode()
	require(err)
	require(os.WriteFile(manifestPath, canonical, 0600))
	tlsConfig, err := xtcpbinding.PeerTLS(identity, ownDER, m, goRole)
	require(err)
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	var listener *quic.Listener
	if goRole == xtcpbinding.Provider {
		incoming := int64(4)
		if mode == "credit-block" {
			incoming = 1
		}
		listener, err = transport.Listen(tlsConfig, &quic.Config{MaxIncomingStreams: incoming, MaxIncomingUniStreams: -1})
		require(err)
		defer listener.Close()
	}
	var proofAccepted atomic.Bool
	var backendCount atomic.Int32
	backendDone := make(chan error, 1)
	if cRole == xtcpbinding.Provider {
		go func() {
			var workers sync.WaitGroup
			failures := make(chan error, 2)
			for i := 0; i < 2; i++ {
				conn, e := backend.Accept()
				if e != nil {
					backendDone <- e
					return
				}
				backendCount.Add(1)
				if !proofAccepted.Load() {
					_ = conn.Close()
					backendDone <- fmt.Errorf("backend accepted before both proof consumers passed")
					return
				}
				workers.Add(1)
				go func(conn net.Conn) {
					defer workers.Done()
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					slot, e := readBody(conn)
					if e == nil {
						_, e = conn.Write(body(slot, true))
						if e == nil {
							e = conn.(*net.TCPConn).CloseWrite()
						}
					}
					failures <- e
				}(conn)
			}
			workers.Wait()
			for i := 0; i < 2; i++ {
				if e := <-failures; e != nil {
					backendDone <- e
					return
				}
			}
			backendDone <- nil
		}()
	}
	localDone := make(chan error, 1)
	retainedDone := make(chan error, 1)
	if cRole == xtcpbinding.Visitor {
		var local [2]*net.TCPConn
		for i := range local {
			raw, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", cTCP), time.Second)
			require(e)
			local[i] = raw.(*net.TCPConn)
		}
		if mode == "credit-block" {
			ready := false
			for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
				if _, e := os.Stat(ownPath + ".accepted"); e == nil {
					ready = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !ready {
				panic("listener did not accept the first two sockets")
			}
			raw, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", cTCP), time.Second)
			require(e)
			go func() {
				defer raw.Close()
				_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
				var data [1]byte
				n, e := raw.Read(data[:])
				if n != 0 || e == nil {
					retainedDone <- fmt.Errorf("capacity-rejected socket was not closed")
				} else {
					retainedDone <- nil
				}
			}()
		}
		go func() {
			var workers sync.WaitGroup
			failures := make(chan error, 2)
			for i, conn := range local {
				workers.Add(1)
				go func(slot int, conn *net.TCPConn) {
					defer workers.Done()
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
					_, e := conn.Write(body(slot, false))
					if e == nil {
						e = conn.CloseWrite()
					}
					var got []byte
					if e == nil {
						got, e = io.ReadAll(io.LimitReader(conn, bodyBytes+1))
					}
					if e == nil && !bytes.Equal(got, body(slot, true)) {
						e = fmt.Errorf("local visitor response differs")
					}
					failures <- e
				}(i+1, conn)
			}
			workers.Wait()
			for i := 0; i < 2; i++ {
				if e := <-failures; e != nil {
					localDone <- e
					return
				}
			}
			localDone <- nil
		}()
	}
	done := make(chan error, 1)
	go func() {
		var conn *quic.Conn
		var e error
		if goRole == xtcpbinding.Visitor {
			conn, e = transport.Dial(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cUDP}, tlsConfig, &quic.Config{MaxIncomingStreams: -1, MaxIncomingUniStreams: -1})
		} else {
			conn, e = listener.Accept(ctx)
		}
		if e != nil {
			done <- e
			return
		}
		proofContext, proofCancel := context.WithTimeout(ctx, 10*time.Second)
		defer proofCancel()
		peerManifest := m
		if mode == "different-sid" {
			peerManifest.SID[0] ^= 1
		}
		if mode == "different-proxy" {
			peerManifest.ProxyName = "other-peer-work"
		}
		if mode == "wrong-role" || mode == "trailing" || mode == "truncated" {
			e = alteredProof(proofContext, conn, peerManifest, goRole, mode)
		} else {
			e = xtcpbinding.ExchangeProof(proofContext, conn, peerManifest, goRole)
		}
		if e != nil {
			done <- e
			return
		}
		if !success {
			done <- nil
			return
		}
		proofAccepted.Store(true)
		var workers sync.WaitGroup
		failures := make(chan error, 2)
		for i := 1; i <= 2; i++ {
			var stream *quic.Stream
			if goRole == xtcpbinding.Visitor {
				stream, e = conn.OpenStreamSync(ctx)
			} else {
				stream, e = conn.AcceptStream(ctx)
			}
			if e != nil {
				done <- e
				return
			}
			if stream.StreamID() < 4 || uint64(stream.StreamID())&3 != 0 {
				done <- fmt.Errorf("business ID invalid")
				return
			}
			if mode == "credit-block" && i == 1 {
				time.Sleep(200 * time.Millisecond)
			}
			workers.Add(1)
			go func(slot int, stream *quic.Stream) {
				defer workers.Done()
				_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
				var e error
				if goRole == xtcpbinding.Visitor {
					_, e = stream.Write(body(slot, false))
					if e == nil {
						e = stream.Close()
					}
					var got []byte
					if e == nil {
						got, e = io.ReadAll(io.LimitReader(stream, bodyBytes+1))
					}
					if e == nil && !bytes.Equal(got, body(slot, true)) {
						e = fmt.Errorf("provider response differs")
					}
				} else {
					slot, e = readBody(stream)
					if e == nil {
						_, e = stream.Write(body(slot, true))
						if e == nil {
							e = stream.Close()
						}
					}
				}
				failures <- e
			}(i, stream)
		}
		workers.Wait()
		for i := 0; i < 2; i++ {
			if e := <-failures; e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	_, err = input.Write([]byte{'G'})
	require(err)
	require(input.Close())
	err = command.Wait()
	if success {
		if err != nil {
			panic(fmt.Sprintf("%s work: %v %s", roleName, err, output.String()))
		}
		require(<-done)
		if cRole == xtcpbinding.Provider {
			require(<-backendDone)
			if backendCount.Load() != 2 {
				panic("provider backend count differs")
			}
		} else {
			require(<-localDone)
			if mode == "credit-block" {
				require(<-retainedDone)
			}
		}
		if !bytes.Contains(output.Bytes(), []byte("bound=1 requests=2 completed=2 failed=0 active=0 bytes=600002/600002")) {
			panic("direct work lacked exact byte/FIN evidence: " + output.String())
		}
	} else {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 10 || !bytes.Contains(output.Bytes(), []byte("bound=0 requests=0 completed=0 failed=0 active=0 bytes=0/0")) {
			panic(fmt.Sprintf("negative %s/%s: %v %s", roleName, mode, err, output.String()))
		}
		if backendCount.Load() != 0 {
			panic("negative reached fixed backend")
		}
	}
	cancel()
	fmt.Printf("XTCP direct work %s/%s: %s", roleName, mode, output.String())
}
func main() {
	peer := flag.String("peer", "", "formal direct peer work executable")
	role := flag.String("role", "", "one targeted provider or visitor fixture")
	mode := flag.String("mode", "", "one targeted fixture mode")
	flag.Parse()
	if *peer == "" {
		panic("peer required")
	}
	directory, err := os.MkdirTemp("", "esp-frp-xtcp-work-")
	require(err)
	defer os.RemoveAll(directory)
	if *role != "" || *mode != "" {
		if (*role != "provider" && *role != "visitor") || *mode == "" {
			panic("targeted role and mode required")
		}
		run(*peer, directory, *role, *mode)
		return
	}
	for _, role := range []string{"provider", "visitor"} {
		for _, mode := range []string{"ok", "different-sid", "different-proxy", "wrong-role", "trailing", "truncated"} {
			run(*peer, directory, role, mode)
		}
	}
	run(*peer, directory, "visitor", "credit-block")
}
