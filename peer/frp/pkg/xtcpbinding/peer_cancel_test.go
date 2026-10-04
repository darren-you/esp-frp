package xtcpbinding

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type proofStageContext struct {
	context.Context
	opened chan struct{}
	once   sync.Once
}

func (ctx *proofStageContext) Deadline() (time.Time, bool) {
	ctx.once.Do(func() { close(ctx.opened) })
	return ctx.Context.Deadline()
}

func TestOwnerCancelInterruptsReservedProofAfterStreamOpen(t *testing.T) {
	for _, role := range []byte{Visitor, Provider} {
		t.Run(map[byte]string{Visitor: "visitor", Provider: "provider"}[role], func(t *testing.T) {
			provider, visitor, manifest := peerFixture(t)
			serverTLS, err := PeerTLS(provider, visitor.DER, manifest, Provider)
			if err != nil {
				t.Fatal(err)
			}
			clientTLS, err := PeerTLS(visitor, provider.DER, manifest, Visitor)
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			listener, err := quic.Listen(udp, serverTLS, &quic.Config{MaxIncomingStreams: 3, MaxIncomingUniStreams: -1})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			setup, cancelSetup := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelSetup()
			accepted := make(chan *quic.Conn, 1)
			go func() {
				c, e := listener.Accept(setup)
				if e == nil {
					accepted <- c
				}
			}()
			client, err := quic.DialAddr(setup, udp.LocalAddr().String(), clientTLS, &quic.Config{MaxIncomingStreams: 3, MaxIncomingUniStreams: -1})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(0, "done")
			var server *quic.Conn
			select {
			case server = <-accepted:
			case <-setup.Done():
				t.Fatal(setup.Err())
			}
			defer server.CloseWithError(0, "done")
			owner, cancel := context.WithCancel(context.Background())
			defer cancel()
			stage := &proofStageContext{Context: owner, opened: make(chan struct{})}
			done := make(chan error, 1)
			if role == Visitor {
				go func() { done <- ExchangeProof(stage, client, manifest, Visitor) }()
				stream, e := server.AcceptStream(setup)
				if e != nil {
					t.Fatal(e)
				}
				// Read the real complete visitor proof, but withhold the provider proof.
				buf := make([]byte, ProofBytes)
				if _, e = io.ReadFull(stream, buf); e != nil {
					t.Fatal(e)
				}
			} else {
				stream, e := client.OpenStreamSync(setup)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = stream.Write([]byte{1}); e != nil {
					t.Fatal(e)
				}
				go func() { done <- ExchangeProof(stage, server, manifest, Provider) }()
			}
			// Actual quic-go Accept/OpenStreamSync only consume Done/Err; the
			// proof Deadline call occurs after the real streamID=0 admission.
			select {
			case <-stage.opened:
			case <-setup.Done():
				t.Fatal("proof stream did not reach I/O", setup.Err())
			}
			cancel()
			select {
			case err = <-done:
				if err == nil {
					t.Fatal("cancelled proof accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("reserved proof survived owner cancellation")
			}
		})
	}
}
