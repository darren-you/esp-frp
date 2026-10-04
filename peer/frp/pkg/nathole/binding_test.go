// SPDX-License-Identifier: Apache-2.0
package nathole

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/msg"
)

func TestCandidateDatagramAuthenticatesAllBytes(t *testing.T) {
	key := []byte("public-detection-key")
	m := &msg.NatHoleSid{Sid: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), TransactionID: "public-txn", Nonce: hex.EncodeToString(bytes.Repeat([]byte{2}, 32)), Response: true}
	encoded, err := EncodeMessage(m, key)
	if err != nil {
		t.Fatal(err)
	}
	var decoded msg.NatHoleSid
	if err = DecodeMessageInto(encoded, key, &decoded); err != nil || decoded != *m {
		t.Fatal(decoded, err)
	}
	if err = DecodeMessageInto(encoded, []byte("wrong-key"), &decoded); err == nil {
		t.Fatal("wrong secret accepted")
	}
	for i := range encoded {
		tampered := bytes.Clone(encoded)
		tampered[i] ^= 1
		if err = DecodeMessageInto(tampered, key, &decoded); err == nil {
			t.Fatalf("changed byte %d accepted", i)
		}
	}
	if err = DecodeMessageInto(append(encoded, 0), key, &decoded); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if err = DecodeMessageInto([]byte("old official discovery packet"), key, &decoded); err == nil {
		t.Fatal("old packet accepted")
	}
}
func TestInvalidDatagramsDoNotExtendAbsoluteDeadline(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		t.Run(map[bool]string{false: "fixed-budget", true: "control-cancel"}[cancelEarly], func(t *testing.T) {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Now()
			result := make(chan error, 1)
			go func() {
				_, err := waitDetectMessage(ctx, c, hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), "public-txn", hex.EncodeToString(bytes.Repeat([]byte{2}, 32)), []byte("public-key"), 150*time.Millisecond, DetectRoleSender)
				result <- err
			}()
			done := make(chan struct{})
			go func() {
				defer close(done)
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						_, _ = sender.WriteToUDP([]byte("bad-packet"), c.LocalAddr().(*net.UDPAddr))
					}
				}
			}()
			if cancelEarly {
				time.AfterFunc(25*time.Millisecond, cancel)
			}
			select {
			case err = <-result:
				if err == nil {
					t.Fatal("invalid packet accepted")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("invalid packets extended wait budget")
			}
			elapsed := time.Since(start)
			if cancelEarly && elapsed > 125*time.Millisecond {
				t.Fatal("cancel did not interrupt read", elapsed)
			}
			cancel()
			<-done
		})
	}
}

func TestResponseRequiresFreshProbeNonce(t *testing.T) {
	own, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer own.Close()
	peer, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	sid := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	nonce := hex.EncodeToString(bytes.Repeat([]byte{2}, 32))
	key := []byte("public-key")
	result := make(chan error, 1)
	go func() {
		_, e := waitDetectMessage(context.Background(), own, sid, "public-txn", nonce, key, time.Second, DetectRoleSender)
		result <- e
	}()
	m := &msg.NatHoleSid{Sid: sid, TransactionID: "public-txn", Nonce: hex.EncodeToString(bytes.Repeat([]byte{3}, 32)), Response: true}
	wrong, e := EncodeMessage(m, key)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = peer.WriteToUDP(wrong, own.LocalAddr().(*net.UDPAddr))
	select {
	case e := <-result:
		t.Fatal("wrong echoed nonce completed probe", e)
	case <-time.After(30 * time.Millisecond):
	}
	m.Nonce = nonce
	correct, e := EncodeMessage(m, key)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = peer.WriteToUDP(correct, own.LocalAddr().(*net.UDPAddr))
	select {
	case e := <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("correct echoed nonce rejected")
	}
	_, _ = peer.WriteToUDP([]byte("post-probe"), own.LocalAddr().(*net.UDPAddr))
	var payload [32]byte
	_ = own.SetReadDeadline(time.Now().Add(time.Second))
	n, _, e := own.ReadFromUDP(payload[:])
	if e != nil || string(payload[:n]) != "post-probe" {
		t.Fatal(n, e)
	}
}
func TestRandomListenerWorkersCancelBeforeReturn(t *testing.T) {
	own, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer own.Close()
	unused, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer unused.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	defer cancel()
	response := &msg.NatHoleResp{Sid: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), CandidateAddrs: []string{unused.LocalAddr().String()}, DetectBehavior: msg.NatHoleDetectBehavior{Role: DetectRoleReceiver, ListenRandomPorts: 4, ReadTimeoutMs: 60000}}
	start := time.Now()
	winner, _, e := MakeHole(ctx, own, response, []byte("public-key"))
	if e == nil || winner != nil || time.Since(start) > 250*time.Millisecond {
		t.Fatal("random listeners not synchronously cancelled", winner, e, time.Since(start))
	}
	if _, e = own.WriteToUDP([]byte("closed-loser"), unused.LocalAddr().(*net.UDPAddr)); e == nil {
		t.Fatal("original losing socket retained")
	}
}
