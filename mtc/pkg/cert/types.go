package cert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
)

var (
	OIDTrustAnchorID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	OIDAlgMTCProof   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	algorithmID      = pkix.AlgorithmIdentifier{Algorithm: OIDAlgMTCProof}
)

type MTCSignature struct {
	CosignerID string `json:"cosigner_id"`
	Signature  []byte `json:"signature"`
}

type MTCProof struct {
	Start          uint64
	End            uint64
	InclusionProof [][]byte
	Signatures     []MTCSignature
}

type Certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

func NewMTCCertificate(tbsDER, signature []byte) Certificate {
	return Certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmID,
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	}
}

type Checkpoint struct {
	Start      uint64         `json:"start"`
	End        uint64         `json:"end"`
	RootHash   []byte         `json:"root_hash"`
	Signatures []MTCSignature `json:"signatures"`
}

func (c *Checkpoint) Copy() Checkpoint {
	var sigs = make([]MTCSignature, 0, len(c.Signatures))
	for _, sig := range c.Signatures {
		sigs = append(sigs, MTCSignature{CosignerID: sig.CosignerID, Signature: slices.Clone(sig.Signature)})
	}
	return Checkpoint{
		Start:      c.Start,
		End:        c.End,
		RootHash:   slices.Clone(c.RootHash),
		Signatures: sigs,
	}
}
