package main

import (
	"crypto"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/papashik/mtc/internal/helpers"
	"github.com/papashik/mtc/pkg/cert"
)

type CASigner struct {
	priv crypto.Signer
	caID string
}

func LoadCASigner(keyPath, caID string) (*CASigner, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	priv := new(mldsa44.PrivateKey)
	if err := priv.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return &CASigner{priv: priv, caID: caID}, nil
}

func (s *CASigner) SignSubtree(start, end uint64, hash []byte) (cert.MTCSignature, error) {
	msg := helpers.CosignedMessage(s.caID, s.caID, start, end, hash)
	sig, err := s.priv.Sign(nil, msg, nil)
	if err != nil {
		return cert.MTCSignature{}, fmt.Errorf("sign: %w", err)
	}
	return cert.MTCSignature{
		CosignerID: s.caID,
		Signature:  sig,
	}, nil
}

func (s *CASigner) PublicKeyBytes() ([]byte, error) {
	return s.priv.Public().(*mldsa44.PublicKey).MarshalBinary()
}
