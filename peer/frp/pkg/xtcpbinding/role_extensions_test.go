// SPDX-License-Identifier: Apache-2.0
package xtcpbinding

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestPeerCertificateExactRoleExtensions(t *testing.T) {
	for _, role := range []byte{Provider, Visitor} {
		identity, err := NewIdentity(role)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ValidateCertificate(role, identity.DER, identity.SPKI[:]); err != nil {
			t.Fatal(err)
		}
		key := identity.Certificate.PrivateKey.(*ecdsa.PrivateKey)
		for _, variant := range []string{"unknown_eku", "registered_id_san", "other_name_san"} {
			t.Run(PeerName(role)+"/"+variant, func(t *testing.T) {
				leaf := *identity.Certificate.Leaf
				if variant == "unknown_eku" {
					leaf.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
				} else {
					var opaque asn1.RawValue
					if variant == "registered_id_san" {
						encoded, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3, 4})
						if err != nil {
							t.Fatal(err)
						}
						var oid asn1.RawValue
						if _, err = asn1.Unmarshal(encoded, &oid); err != nil {
							t.Fatal(err)
						}
						opaque = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: oid.Bytes}
					} else {
						encoded, err := asn1.Marshal(struct {
							OID   asn1.ObjectIdentifier
							Value string `asn1:"explicit,tag:0,utf8"`
						}{asn1.ObjectIdentifier{1, 2, 3, 4}, "other identity"})
						if err != nil {
							t.Fatal(err)
						}
						var other asn1.RawValue
						if _, err = asn1.Unmarshal(encoded, &other); err != nil {
							t.Fatal(err)
						}
						opaque = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: other.Bytes}
					}
					san, err := asn1.Marshal([]asn1.RawValue{
						{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(PeerName(role))}, opaque,
					})
					if err != nil {
						t.Fatal(err)
					}
					leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
				}
				der, err := x509.CreateCertificate(rand.Reader, &leaf, &leaf, &key.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if err = parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature); err != nil {
					t.Fatal(err)
				}
				if sha256.Sum256(parsed.RawSubjectPublicKeyInfo) != identity.SPKI {
					t.Fatal("same-key fixture changed SPKI")
				}
				_, err = ValidateCertificate(role, der, identity.SPKI[:])
				t.Logf("self-signature valid; DNS=%d EKU=%d unknownEKU=%d accepted=%v", len(parsed.DNSNames), len(parsed.ExtKeyUsage), len(parsed.UnknownExtKeyUsage), err == nil)
				if err == nil {
					t.Error("role certificate with additional raw SAN/EKU accepted")
				}
			})
		}
	}
}
