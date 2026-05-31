package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/papashik/mtc/internal/helpers"
)

type TBSCertificateLogEntry struct {
	Version                   int `asn1:"optional,explicit,tag:0,default:0"`
	Issuer                    pkix.RDNSequence
	Validity                  Validity
	Subject                   pkix.RDNSequence
	SubjectPublicKeyAlgorithm pkix.AlgorithmIdentifier
	SubjectPublicKeyInfoHash  []byte
	Extensions                []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type TBSCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	Extensions         []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

func (tbs TBSCertificate) TBSCertificateLogEntry() (*TBSCertificateLogEntry, error) {
	var issuer pkix.RDNSequence
	if _, err := asn1.Unmarshal(tbs.Issuer.FullBytes, &issuer); err != nil {
		return nil, fmt.Errorf("parse issuer: %w", err)
	}

	var validity Validity
	if _, err := asn1.Unmarshal(tbs.Validity.FullBytes, &validity); err != nil {
		return nil, fmt.Errorf("parse validity: %w", err)
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(tbs.Subject.FullBytes, &subject); err != nil {
		return nil, fmt.Errorf("parse subject: %w", err)
	}

	var spki SPKI
	if _, err := asn1.Unmarshal(tbs.PublicKey.FullBytes, &spki); err != nil {
		return nil, fmt.Errorf("parse subjectPublicKeyInfo: %w", err)
	}

	sum := sha256.Sum256(tbs.PublicKey.FullBytes)

	return &TBSCertificateLogEntry{
		Version:                   tbs.Version,
		Issuer:                    issuer,
		Validity:                  validity,
		Subject:                   subject,
		SubjectPublicKeyAlgorithm: spki.Algorithm,
		SubjectPublicKeyInfoHash:  sum[:],
		Extensions:                tbs.Extensions,
	}, nil
}

type Validity struct {
	NotBefore, NotAfter time.Time
}

type SPKI struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func BytesToSPKI(key []byte) SPKI {
	return SPKI{
		Algorithm: algorithmID,
		PublicKey: asn1.BitString{
			Bytes:     key,
			BitLength: 8 * len(key),
		},
	}
}

func BuildEntryFromCSR(
	csr *x509.CertificateRequest,
	caID string,
	notBefore, notAfter time.Time,
	spkiDER []byte,
) (*TBSCertificateLogEntry, error) {
	issuerDN := CAIDToDN(caID)
	spkiHash := sha256.Sum256(spkiDER)

	var spki SPKI
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, fmt.Errorf("unmarshal spki: %w", err)
	}

	var subjectRDN pkix.RDNSequence
	if _, err := asn1.Unmarshal(csr.RawSubject, &subjectRDN); err != nil {
		return nil, fmt.Errorf("parse subject: %w", err)
	}

	return &TBSCertificateLogEntry{
		Version:                   2,
		Issuer:                    issuerDN,
		Validity:                  Validity{notBefore, notAfter},
		Subject:                   subjectRDN,
		SubjectPublicKeyAlgorithm: spki.Algorithm,
		SubjectPublicKeyInfoHash:  spkiHash[:],
		Extensions:                csr.Extensions,
	}, nil
}

func SerializeEntry(e *TBSCertificateLogEntry) ([]byte, error) {
	der, err := asn1.Marshal(*e)
	if err != nil {
		return nil, err
	}

	entryType := []byte{0x00, 0x01}
	return append(entryType, der...), nil
}

func SerializeMTCProof(p *MTCProof) []byte {
	buf := make([]byte, 0, 256)

	buf = append(buf, helpers.Uint64ToBytes(p.Start)...)
	buf = append(buf, helpers.Uint64ToBytes(p.End)...)

	proofLen := uint16(len(p.InclusionProof) * 32)
	buf = append(buf, byte(proofLen>>8), byte(proofLen))
	for _, h := range p.InclusionProof {
		buf = append(buf, h...)
	}

	sigsBuf := make([]byte, 0, 256)
	for _, sig := range p.Signatures {
		sigsBuf = append(sigsBuf, byte(len(sig.CosignerID)))
		sigsBuf = append(sigsBuf, sig.CosignerID...)
		sigLen := uint16(len(sig.Signature))
		sigsBuf = append(sigsBuf, byte(sigLen>>8), byte(sigLen))
		sigsBuf = append(sigsBuf, sig.Signature...)
	}
	sigsLen := uint16(len(sigsBuf))
	buf = append(buf, byte(sigsLen>>8), byte(sigsLen))
	buf = append(buf, sigsBuf...)
	return buf
}

func DeserializeMTCProof(data []byte) (*MTCProof, error) {
	if len(data) < 18 {
		return nil, fmt.Errorf("proof too short")
	}
	p := &MTCProof{}
	p.Start = binary.BigEndian.Uint64(data[0:8])
	p.End = binary.BigEndian.Uint64(data[8:16])
	off := 16

	proofLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if len(data) < off+proofLen {
		return nil, fmt.Errorf("truncated proof hashes")
	}
	for i := 0; i < proofLen/32; i++ {
		h := make([]byte, 32)
		copy(h, data[off+i*32:])
		p.InclusionProof = append(p.InclusionProof, h)
	}
	off += proofLen

	if len(data) < off+2 {
		return nil, fmt.Errorf("truncated sigs length")
	}
	sigsLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	end := off + sigsLen
	for off < end {
		if off >= len(data) {
			return nil, fmt.Errorf("truncated sig")
		}
		idLen := int(data[off])
		off++
		if off+idLen > len(data) {
			return nil, fmt.Errorf("truncated cosigner id")
		}
		id := make([]byte, idLen)
		copy(id, data[off:])
		off += idLen

		if off+2 > len(data) {
			return nil, fmt.Errorf("truncated sig len")
		}
		sigLen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+sigLen > len(data) {
			return nil, fmt.Errorf("truncated sig bytes")
		}
		sig := make([]byte, sigLen)
		copy(sig, data[off:])
		off += sigLen
		p.Signatures = append(p.Signatures, MTCSignature{CosignerID: string(id), Signature: sig})
	}
	return p, nil
}

func AssembleCertificate(
	entry *TBSCertificateLogEntry,
	logID uint64,
	index uint64,
	proof *MTCProof,
	subjectPubKeyDER []byte,
) ([]byte, error) {
	if index >= (1 << 48) {
		return nil, fmt.Errorf("index %d exceeds 48 bits", index)
	}
	serial := new(big.Int).SetUint64((logID << 48) | index)

	issuerDER, err := asn1.Marshal(entry.Issuer)
	if err != nil {
		return nil, err
	}
	subjectDER, err := asn1.Marshal(entry.Subject)
	if err != nil {
		return nil, err
	}
	validityDER, err := asn1.Marshal(Validity{entry.Validity.NotBefore, entry.Validity.NotAfter})
	if err != nil {
		return nil, err
	}

	tbs := TBSCertificate{
		Version:            2,
		SerialNumber:       serial,
		SignatureAlgorithm: algorithmID,
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		Validity:           asn1.RawValue{FullBytes: validityDER},
		Subject:            asn1.RawValue{FullBytes: subjectDER},
		PublicKey:          asn1.RawValue{FullBytes: subjectPubKeyDER},
		Extensions:         entry.Extensions,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	tbs.Raw = tbsDER

	proofBytes := SerializeMTCProof(proof)

	return asn1.Marshal(NewMTCCertificate(tbsDER, proofBytes))
}

func CAIDToDN(caID string) pkix.RDNSequence {
	val, _ := asn1.Marshal(caID)
	return pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  OIDTrustAnchorID,
				Value: asn1.RawValue{FullBytes: val},
			},
		},
	}
}
