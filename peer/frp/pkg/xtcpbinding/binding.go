// SPDX-License-Identifier: Apache-2.0
// Package xtcpbinding implements the candidate protocol shared with esp-frp.
package xtcpbinding

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const ALPN = "esp-frp-xtcp/1"
const ExporterLabel = "EXPORTER-esp-frp-xtcp-peer-v1"
const Provider byte = 1
const Visitor byte = 2
const ProofBytes = 69

var ErrBinding = errors.New("XTCP candidate binding rejected")

type Manifest struct {
	ProxyName                       string
	SID                             [32]byte
	ProviderControl, VisitorControl [32]byte
	ProviderNonce, VisitorNonce     [32]byte
	ProviderSPKI, VisitorSPKI       [32]byte
	IssuedAt, ExpiresAt             uint64
}

func Nonzero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func ID(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) != 32 || !Nonzero(b) {
		return out, ErrBinding
	}
	copy(out[:], b)
	return out, nil
}
func (m Manifest) Encode() ([]byte, error) {
	if len(m.ProxyName) < 1 || len(m.ProxyName) > 128 || !utf8.ValidString(m.ProxyName) || m.IssuedAt == 0 ||
		m.ExpiresAt <= m.IssuedAt || m.ExpiresAt-m.IssuedAt > 60 {
		return nil, ErrBinding
	}
	for _, v := range []byte(m.ProxyName) {
		if v < 0x20 || v == 0x7f {
			return nil, ErrBinding
		}
	}
	fields := [][32]byte{m.SID, m.ProviderControl, m.VisitorControl, m.ProviderNonce, m.VisitorNonce, m.ProviderSPKI, m.VisitorSPKI}
	out := append([]byte("EFRPXTC1"), byte(len(m.ProxyName)))
	out = append(out, m.ProxyName...)
	for _, f := range fields {
		if !Nonzero(f[:]) {
			return nil, ErrBinding
		}
		out = append(out, f[:]...)
	}
	out = binary.BigEndian.AppendUint64(out, m.IssuedAt)
	out = binary.BigEndian.AppendUint64(out, m.ExpiresAt)
	return out, nil
}
func Decode(wire []byte, now uint64) (Manifest, error) {
	var m Manifest
	if len(wire) < 250 || len(wire) > 377 || !bytes.Equal(wire[:8], []byte("EFRPXTC1")) ||
		wire[8] == 0 || wire[8] > 128 || len(wire) != 249+int(wire[8]) {
		return m, ErrBinding
	}
	m.ProxyName = string(wire[9 : 9+int(wire[8])])
	at := 9 + int(wire[8])
	for _, f := range []*[32]byte{&m.SID, &m.ProviderControl, &m.VisitorControl, &m.ProviderNonce, &m.VisitorNonce, &m.ProviderSPKI, &m.VisitorSPKI} {
		copy(f[:], wire[at:at+32])
		at += 32
	}
	m.IssuedAt = binary.BigEndian.Uint64(wire[at:])
	m.ExpiresAt = binary.BigEndian.Uint64(wire[at+8:])
	if _, err := m.Encode(); err != nil || now < m.IssuedAt || now >= m.ExpiresAt {
		return Manifest{}, ErrBinding
	}
	return m, nil
}
func (m Manifest) Hash() ([32]byte, error) {
	wire, err := m.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(wire), nil
}
func (m Manifest) CheckLocal(role byte, control, nonce, spki []byte) error {
	if _, err := m.Encode(); err != nil {
		return err
	}
	c, n, s := m.ProviderControl, m.ProviderNonce, m.ProviderSPKI
	if role == Visitor {
		c, n, s = m.VisitorControl, m.VisitorNonce, m.VisitorSPKI
	} else if role != Provider {
		return ErrBinding
	}
	if !hmac.Equal(control, c[:]) || !hmac.Equal(nonce, n[:]) || !hmac.Equal(spki, s[:]) {
		return ErrBinding
	}
	return nil
}
func (m Manifest) Proof(role byte, exporter []byte) ([]byte, error) {
	if role != Provider && role != Visitor || len(exporter) != 32 || !Nonzero(exporter) {
		return nil, ErrBinding
	}
	d, err := m.Hash()
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, exporter)
	h.Write([]byte("esp-frp-xtcp-proof-v1"))
	h.Write([]byte{role})
	h.Write(d[:])
	out := append([]byte("XTP1"), role)
	out = append(out, d[:]...)
	out = append(out, h.Sum(nil)...)
	return out, nil
}
func (m Manifest) Verify(role byte, exporter, proof []byte) error {
	expected, err := m.Proof(role, exporter)
	if err != nil {
		return err
	}
	if !hmac.Equal(proof, expected) {
		return ErrBinding
	}
	return nil
}

// SignalProof binds a proxy capability to the current server-assigned control
// instance, role, nonce, ephemeral key and timestamp. It is not an FRPS Token.
func SignalProof(secret string, role byte, proxy string, control, nonce, spki []byte, timestamp int64) ([]byte, error) {
	if len(secret) < 1 || len(secret) > 128 || len(proxy) < 1 || len(proxy) > 128 || !utf8.ValidString(proxy) ||
		(role != Provider && role != Visitor) || timestamp <= 0 {
		return nil, ErrBinding
	}
	for _, f := range [][]byte{control, nonce, spki} {
		if _, err := ID(f); err != nil {
			return nil, err
		}
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("esp-frp-xtcp-signal-v1"))
	h.Write([]byte{role, byte(len(proxy))})
	h.Write([]byte(proxy))
	h.Write(control)
	h.Write(nonce)
	h.Write(spki)
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(timestamp))
	h.Write(stamp[:])
	return h.Sum(nil), nil
}
