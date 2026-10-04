// SPDX-License-Identifier: Apache-2.0
package xtcpbinding

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func vector() Manifest {
	m := Manifest{ProxyName: "provider.private", IssuedAt: 1700000000, ExpiresAt: 1700000010}
	for i, f := range []*[32]byte{&m.SID, &m.ProviderControl, &m.VisitorControl, &m.ProviderNonce, &m.VisitorNonce, &m.ProviderSPKI, &m.VisitorSPKI} {
		for j := range f {
			f[j] = byte((i + 1) * 17)
		}
	}
	return m
}
func TestCanonicalCAndIndependentVectors(t *testing.T) {
	m := vector()
	wire, err := m.Encode()
	if err != nil || len(wire) != 265 {
		t.Fatal(len(wire), err)
	}
	parsed, err := Decode(wire, 1700000001)
	if err != nil || parsed != m {
		t.Fatal(parsed, err)
	}
	d, err := m.Hash()
	if err != nil || hex.EncodeToString(d[:]) != "2cd8f421a36fce3f5af0fff18fad4ef8d8876fd200ab0690cfee9c87f737ae15" {
		t.Fatal(d, err)
	}
	p, err := m.Proof(Provider, bytes.Repeat([]byte{0x88}, 32))
	if err != nil || hex.EncodeToString(p[37:]) != "bd833d1a648605ff12850fa945e0fbe9708fad46d7d7f5b1992a0fc45f84b773" {
		t.Fatal(p, err)
	}
	for _, tc := range []struct{ key, want string }{{"public-signal-secret", "a878b434dcbff0878865b5d9910923557d0124f5bf6fa47fa21292eafe474715"}, {string(bytes.Repeat([]byte{'k'}, 128)), "01ad5c9bdd4e32c52652af37f328912db5ba9539882f693169bd7b04e459903c"}} {
		proof, err := SignalProof(tc.key, Provider, m.ProxyName, m.ProviderControl[:], m.ProviderNonce[:], m.ProviderSPKI[:], 1700000000)
		if err != nil || hex.EncodeToString(proof) != tc.want {
			t.Fatal(proof, err)
		}
	}
	for _, now := range []uint64{1699999999, 1700000010} {
		if _, err := Decode(wire, now); err == nil {
			t.Fatal("outside admission window")
		}
	}
	m.ExpiresAt = m.IssuedAt + 60
	if _, err := m.Encode(); err != nil {
		t.Fatal(err)
	}
	m.ExpiresAt++
	if _, err := m.Encode(); err == nil {
		t.Fatal("61s admission accepted")
	}
}
func TestProofDoesNotCrossContextOrReflectRole(t *testing.T) {
	m := vector()
	exporter := bytes.Repeat([]byte{0x88}, 32)
	proof, _ := m.Proof(Provider, exporter)
	if err := m.Verify(Provider, exporter, proof); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(Visitor, exporter, proof); err == nil {
		t.Fatal("role reflection")
	}
	for _, f := range []*[32]byte{&m.SID, &m.ProviderControl, &m.VisitorControl, &m.ProviderNonce, &m.VisitorNonce, &m.ProviderSPKI, &m.VisitorSPKI} {
		f[0] ^= 1
		if err := m.Verify(Provider, exporter, proof); err == nil {
			t.Fatal("manifest context substitution")
		}
		f[0] ^= 1
	}
	m.ProxyName = "provider.another"
	if err := m.Verify(Provider, exporter, proof); err == nil {
		t.Fatal("proxy substitution")
	}
	m = vector()
	exporter[0] ^= 1
	if err := m.Verify(Provider, exporter, proof); err == nil {
		t.Fatal("TLS channel substitution")
	}
	if _, err := Decode(append(mustEncode(t, m), 0), 1700000001); err == nil {
		t.Fatal("trailing byte accepted")
	}
}
func mustEncode(t *testing.T, m Manifest) []byte {
	t.Helper()
	b, e := m.Encode()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
