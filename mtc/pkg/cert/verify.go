package cert

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/papashik/mtc/internal/helpers"
	"github.com/papashik/mtc/pkg/core"
)

type Policy struct {
	RequireCASignature bool
	MinCosigners       int
}

type VerifyContext struct {
	CAs       map[string][]byte
	Cosigners map[string][]byte
	Policy    Policy
	Landmarks map[string][]Checkpoint
}

func VerifyCertificate(certDER []byte, ctx VerifyContext) error {
	c, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	proof, err := DeserializeMTCProof(c.Signature)
	if err != nil {
		return fmt.Errorf("parse mtc proof: %w", err)
	}

	var tbs TBSCertificate
	if _, err := asn1.Unmarshal(c.RawTBSCertificate, &tbs); err != nil {
		return fmt.Errorf("tbs unmarshal: %w", err)
	}
	index := tbs.SerialNumber.Uint64() % (1 << 48)

	entry, err := tbs.TBSCertificateLogEntry()
	if err != nil {
		return err
	}

	entryBytes, err := SerializeEntry(entry)
	if err != nil {
		return err
	}

	expectedHash, err := core.EvaluateInclusionProof(
		proof.Start,
		proof.End,
		index,
		proof.InclusionProof,
		core.HashLeaf(entryBytes),
	)
	if err != nil {
		return fmt.Errorf("evaluate inclusion proof: %w", err)
	}

	caID := c.Issuer.Names[0].Value.(string)
	for _, ts := range ctx.Landmarks[caID] {
		if proof.Start == 0 && proof.End == ts.End {
			if string(ts.RootHash) == string(expectedHash) {
				return nil
			}
			return fmt.Errorf("subtree hash mismatch with trusted subtree [%d %d)", proof.Start, proof.End)
		}
	}

	return verifySignatures(caID, proof, expectedHash, ctx)
}

func verifySignatures(caID string, proof *MTCProof, subtreeHash []byte, ctx VerifyContext) error {
	caFound := false
	cosignerCount := 0

	for _, sig := range proof.Signatures {
		if pubKey, ok := ctx.CAs[sig.CosignerID]; ok {
			if caID != sig.CosignerID {
				return fmt.Errorf("expected another CA: %s %s", caID, sig.CosignerID)
			}
			sigMsg := helpers.CosignedMessage(caID, caID, proof.Start, proof.End, subtreeHash)
			if err := verifyMLDSA(pubKey, sigMsg, sig.Signature); err != nil {
				return fmt.Errorf("CA signature invalid: %w", err)
			}
			caFound = true
		} else if pubKey, ok := ctx.Cosigners[sig.CosignerID]; ok {
			sigMsg := helpers.CosignedMessage(sig.CosignerID, caID, proof.Start, proof.End, subtreeHash)
			if err := verifyMLDSA(pubKey, sigMsg, sig.Signature); err != nil {
				return fmt.Errorf("cosigner %s signature invalid: %w", sig.CosignerID, err)
			}
			cosignerCount++
		}
	}

	if ctx.Policy.RequireCASignature && !caFound {
		return fmt.Errorf("CA signature required but not found")
	}
	if cosignerCount < ctx.Policy.MinCosigners {
		return fmt.Errorf("need %d cosigners, got %d", ctx.Policy.MinCosigners, cosignerCount)
	}
	return nil
}

func verifyMLDSA(pubKeyBytes, message, signature []byte) error {
	pub := new(mldsa44.PublicKey)
	if err := pub.UnmarshalBinary(pubKeyBytes); err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	if !mldsa44.Verify(pub, message, nil, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
