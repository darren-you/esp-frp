// SPDX-License-Identifier: Apache-2.0
package xtcpbinding

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func peerFixture(t *testing.T) (*Identity, *Identity, Manifest) {
	t.Helper()
	provider, err := NewIdentity(Provider)
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := NewIdentity(Visitor)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{ProxyName: "provider.private", ProviderNonce: provider.Nonce, VisitorNonce: visitor.Nonce, ProviderSPKI: provider.SPKI, VisitorSPKI: visitor.SPKI, IssuedAt: uint64(time.Now().Unix())}
	m.ExpiresAt = m.IssuedAt + 60
	for _, f := range []*[32]byte{&m.SID, &m.ProviderControl, &m.VisitorControl} {
		if _, err := rand.Read(f[:]); err != nil {
			t.Fatal(err)
		}
	}
	return provider, visitor, m
}
func TestStrictMutualPeerAndReservedProof(t *testing.T) {
	for _, negative := range []string{"", "wrong-sid", "wrong-proxy", "missing-client-certificate", "official-alpn"} {
		t.Run(negative, func(t *testing.T) {
			provider, visitor, m := peerFixture(t)
			serverTLS, err := PeerTLS(provider, visitor.DER, m, Provider)
			if err != nil {
				t.Fatal(err)
			}
			clientManifest := m
			if negative == "wrong-sid" {
				clientManifest.SID[0] ^= 1
			}
			if negative == "wrong-proxy" {
				clientManifest.ProxyName = "wrong.private"
			}
			clientTLS, err := PeerTLS(visitor, provider.DER, clientManifest, Visitor)
			if err != nil {
				t.Fatal(err)
			}
			if negative == "missing-client-certificate" {
				clientTLS.Certificates = nil
			}
			if negative == "official-alpn" {
				clientTLS.NextProtos = []string{"frp"}
			}
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			listener, err := quic.Listen(socket, serverTLS, &quic.Config{MaxIncomingStreams: 3, MaxIncomingUniStreams: -1})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result := make(chan error, 1)
			reached := make(chan bool, 1)
			go func() {
				c, e := listener.Accept(ctx)
				if e != nil {
					result <- e
					return
				}
				defer c.CloseWithError(0, "complete")
				if e = ExchangeProof(ctx, c, m, Provider); e != nil {
					result <- e
					return
				}
				stream, e := c.AcceptStream(ctx)
				if e != nil {
					result <- e
					return
				}
				reached <- true
				input := make([]byte, 8193)
				_, e = io.ReadFull(stream, input)
				if e == nil {
					_, e = stream.Write(input)
				}
				if e == nil {
					var done [1]byte
					_, e = io.ReadFull(stream, done[:])
				}
				result <- e
			}()
			client, e := quic.DialAddr(ctx, socket.LocalAddr().String(), clientTLS, &quic.Config{MaxIncomingUniStreams: -1})
			if e == nil {
				defer client.CloseWithError(0, "complete")
				e = ExchangeProof(ctx, client, clientManifest, Visitor)
			}
			if negative != "" {
				if e == nil {
					t.Fatal("unbound peer admitted")
				}
				cancel()
				if <-result == nil {
					t.Fatal("provider accepted negative")
				}
				select {
				case <-reached:
					t.Fatal("backend bytes admitted before binding")
				default:
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			stream, e := client.OpenStreamSync(ctx)
			if e != nil {
				t.Fatal(e)
			}
			input := make([]byte, 8193)
			if _, e = rand.Read(input); e != nil {
				t.Fatal(e)
			}
			if _, e = stream.Write(input); e != nil {
				t.Fatal(e)
			}
			output := make([]byte, len(input))
			if _, e = io.ReadFull(stream, output); e != nil {
				t.Fatal(e)
			}
			for i := range input {
				if input[i] != output[i] {
					t.Fatal("business corruption")
				}
			}
			if _, e = stream.Write([]byte{1}); e != nil {
				t.Fatal(e)
			}
			if e = <-result; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestPeerCertificatePinAndRoleRejectBeforeHandshake(t *testing.T) {
	provider, visitor, m := peerFixture(t)
	wrong, _, _ := peerFixture(t)
	if _, err := PeerTLS(visitor, wrong.DER, m, Visitor); err == nil {
		t.Fatal("wrong SPKI admitted")
	}
	if _, err := PeerTLS(visitor, visitor.DER, m, Visitor); err == nil {
		t.Fatal("wrong certificate role admitted")
	}
	if _, err := ValidateCertificate(Visitor, provider.DER, provider.SPKI[:]); err == nil {
		t.Fatal("provider key reflected as visitor")
	}
}

func TestExplicitCertificateRoleUsageAndSAN(t *testing.T) {
	identity, _, _ := peerFixture(t)
	key := identity.Certificate.PrivateKey.(*ecdsa.PrivateKey)
	for _, invalid := range []string{"missing-digital-signature", "any-eku", "other-role-eku", "extra-san"} {
		t.Run(invalid, func(t *testing.T) {
			leaf := *identity.Certificate.Leaf
			switch invalid {
			case "missing-digital-signature":
				leaf.KeyUsage = x509.KeyUsageKeyEncipherment
			case "any-eku":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
			case "other-role-eku":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "extra-san":
				leaf.DNSNames = []string{PeerName(Provider), "unrelated.invalid"}
			}
			der, err := x509.CreateCertificate(rand.Reader, &leaf, &leaf, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ValidateCertificate(Provider, der, identity.SPKI[:]); err == nil {
				t.Fatal("role certificate without exact usage/SAN accepted")
			}
		})
	}
}
