package mtc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/papashik/mtc/pkg/cert"
)

const (
	ModeProtoCheck = iota
	ModeAlwaysFull
	ModeAlwaysShort
)

func GetCertificateFunc(certDER []byte, privateKey []byte, mode int) func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}
		var key crypto.Signer
		var ml *mldsa44.PrivateKey
		if err := ml.UnmarshalBinary(privateKey); err != nil {
			pub, err := x509.ParsePKCS8PrivateKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
			key = pub.(crypto.Signer)
		} else {
			key = ml
		}
		proof, err := cert.DeserializeMTCProof(c.Signature)
		if err != nil {
			return nil, fmt.Errorf("parse mtc proof: %w", err)
		}

		tmpKey, _ := rsa.GenerateKey(rand.Reader, 2048) // without it we have server-side problems, with it we have client-side problems :(
		full := func() (*tls.Certificate, error) {
			return &tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  tmpKey,
				Leaf:        c,
			}, nil
		}
		short := func() (*tls.Certificate, error) {
			newSigBytes := cert.SerializeMTCProof(&cert.MTCProof{Start: proof.Start, End: proof.End, InclusionProof: proof.InclusionProof})
			newBytes, err := asn1.Marshal(cert.NewMTCCertificate(c.RawTBSCertificate, newSigBytes))
			if err != nil {
				return nil, err
			}
			return &tls.Certificate{Certificate: [][]byte{newBytes}, PrivateKey: key}, nil
		}

		switch mode {
		case ModeAlwaysFull:
			return full()
		case ModeAlwaysShort:
			return short()
		}

		lms := ParseProto(c.Issuer, clientHello.SupportedProtos)
		if len(lms) == 0 {
			return full()
		}

		for _, lm := range lms {
			if lm.Start == proof.Start && lm.End == proof.End {
				return short()
			}
		}
		return full()
	}
}

// ShortifyCertificate removes all MTC signatures from a certificate if any.
func ShortifyCertificate(certDER []byte) ([]byte, error) {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	proof, err := cert.DeserializeMTCProof(c.Signature)
	if err != nil {
		return nil, fmt.Errorf("parse mtc proof: %w", err)
	}
	newSigBytes := cert.SerializeMTCProof(&cert.MTCProof{Start: proof.Start, End: proof.End, InclusionProof: proof.InclusionProof})
	newBytes, err := asn1.Marshal(cert.NewMTCCertificate(c.RawTBSCertificate, newSigBytes))
	if err != nil {
		return nil, err
	}
	return newBytes, nil
}
