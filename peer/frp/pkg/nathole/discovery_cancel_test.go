package nathole

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDiscoverOwnerCancellationDuringSTUN(t *testing.T) {
	server := listenTestUDP4(t)
	seen := serveOneSTUNRequest(server, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := Discover(ctx, []string{server.LocalAddr().String()}, ""); done <- err }()
	from := waitSTUNExchange(t, seen)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner cancel retained pending native STUN socket")
	}
	// Rebind the exact local port: the real pending socket has closed.
	rebound, err := net.ListenUDP("udp4", &net.UDPAddr{Port: from.Port})
	if err != nil {
		t.Fatal("STUN socket still held", err)
	}
	rebound.Close()
}

func TestDiscoverAlreadyCancelledHasNoSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addresses, local, err := Discover(ctx, []string{"127.0.0.1:1"}, "")
	if !errors.Is(err, context.Canceled) || addresses != nil || local != nil {
		t.Fatal(addresses, local, err)
	}
}
