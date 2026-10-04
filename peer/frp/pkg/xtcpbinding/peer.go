// SPDX-License-Identifier: Apache-2.0
package xtcpbinding

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

type Identity struct {
	Certificate tls.Certificate
	DER         []byte
	SPKI        [32]byte
	Nonce       [32]byte
}

func PeerName(role byte) string {
	if role == Provider {
		return "esp-frp-xtcp-provider"
	}
	if role == Visitor {
		return "esp-frp-xtcp-visitor"
	}
	return ""
}
func NewIdentity(role byte) (*Identity, error) {
	name := PeerName(role)
	if name == "" {
		return nil, ErrBinding
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	usage := x509.ExtKeyUsageServerAuth
	if role == Visitor {
		usage = x509.ExtKeyUsageClientAuth
	}
	when := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: when.Add(-30 * time.Second), NotAfter: when.Add(120 * time.Second), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	out := &Identity{DER: der, Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, SPKI: sha256.Sum256(parsed.RawSubjectPublicKeyInfo)}
	if _, err = rand.Read(out.Nonce[:]); err != nil {
		return nil, err
	}
	return out, nil
}
func ValidateCertificate(role byte, der, expectedSPKI []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > 1024 || len(expectedSPKI) != 32 || PeerName(role) == "" {
		return nil, ErrBinding
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrBinding
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if !hmac.Equal(digest[:], expectedSPKI) {
		return nil, ErrBinding
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != PeerName(role) || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, ErrBinding
	}
	if err = cert.VerifyHostname(PeerName(role)); err != nil {
		return nil, err
	}
	if err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	usage := x509.ExtKeyUsageServerAuth
	if role == Visitor {
		usage = x509.ExtKeyUsageClientAuth
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != usage {
		return nil, ErrBinding
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}, DNSName: PeerName(role)}); err != nil {
		return nil, err
	}
	return cert, nil
}

// The only trust anchor is the exact ephemeral certificate delivered through
// this SID's strict authenticated signal control. Default Go X509 verification
// remains enabled; no skip-verification option or system trust fallback exists.
func PeerTLS(local *Identity, peerDER []byte, m Manifest, role byte) (*tls.Config, error) {
	if local == nil || (role != Provider && role != Visitor) {
		return nil, ErrBinding
	}
	peerRole := Visitor
	expected := m.VisitorSPKI
	if role == Visitor {
		peerRole = Provider
		expected = m.ProviderSPKI
	}
	cert, err := ValidateCertificate(peerRole, peerDER, expected[:])
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	cfg := &tls.Config{Certificates: []tls.Certificate{local.Certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN}, CurvePreferences: []tls.CurveID{tls.X25519}, RootCAs: roots, ServerName: PeerName(peerRole)}
	if role == Provider {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = roots
	}
	cfg.VerifyConnection = func(s tls.ConnectionState) error {
		if s.NegotiatedProtocol != ALPN || s.Version != tls.VersionTLS13 || len(s.PeerCertificates) != 1 {
			return ErrBinding
		}
		pin := sha256.Sum256(s.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if !hmac.Equal(pin[:], expected[:]) {
			return ErrBinding
		}
		return nil
	}
	return cfg, nil
}
func Exporter(conn *quic.Conn, m Manifest) ([]byte, error) {
	digest, err := m.Hash()
	if err != nil {
		return nil, err
	}
	state := conn.ConnectionState().TLS
	if state.NegotiatedProtocol != ALPN {
		return nil, ErrBinding
	}
	return state.ExportKeyingMaterial(ExporterLabel, digest[:], 32)
}
func ExchangeProof(ctx context.Context, conn *quic.Conn, m Manifest, role byte) error {
	// Admission expiry is checked once by the role before starting this peer.
	// The handshake and reserved proof share their separate absolute budget.
	if _, err := m.Encode(); err != nil {
		return err
	}
	exporter, err := Exporter(conn, m)
	if err != nil {
		return err
	}
	defer clear(exporter)
	var stream *quic.Stream
	if role == Visitor {
		stream, err = conn.OpenStreamSync(ctx)
	} else if role == Provider {
		stream, err = conn.AcceptStream(ctx)
	} else {
		return ErrBinding
	}
	if err != nil {
		return err
	}
	if stream.StreamID() != 0 {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return ErrBinding
	}
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	local, err := m.Proof(role, exporter)
	if err != nil {
		return err
	}
	read := func(expected byte) error {
		peer := make([]byte, ProofBytes)
		if _, e := io.ReadFull(stream, peer); e != nil {
			return e
		}
		if e := m.Verify(expected, exporter, peer); e != nil {
			return e
		}
		var extra [1]byte
		n, e := stream.Read(extra[:])
		if n != 0 || e != io.EOF {
			return ErrBinding
		}
		return nil
	}
	write := func() error {
		if _, e := stream.Write(local); e != nil {
			return e
		}
		return stream.Close()
	}
	if role == Visitor {
		if err = write(); err == nil {
			err = read(Provider)
		}
	} else {
		if err = read(Visitor); err == nil {
			err = write()
		}
	}
	clear(local)
	if err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
	}
	return err
}
func DecodeMustCurrent(m Manifest) (Manifest, error) {
	wire, err := m.Encode()
	if err != nil {
		return Manifest{}, err
	}
	return Decode(wire, uint64(time.Now().Unix()))
}
