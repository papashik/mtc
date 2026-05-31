package core

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

var ErrInvalidProof = errors.New("invalid proof")

func GenerateInclusionProof(
	index, start, end uint64,
	getLeafHash func(i uint64) ([]byte, error),
	getNodeHash func(s, e uint64) ([]byte, error),
) ([][]byte, error) {
	if err := CheckSubtree(start, end); err != nil {
		return nil, err
	}
	if index < start || index >= end {
		return nil, fmt.Errorf("index %d not in [%d, %d)", index, start, end)
	}
	if getLeafHash == nil {
		return nil, errors.New("getLeafHash is nil")
	}
	if getNodeHash == nil {
		return nil, errors.New("getNodeHash is nil")
	}

	return inclusionProofRec(start, end, index, getLeafHash, getNodeHash)
}

func inclusionProofRec(
	start, end, index uint64,
	getLeafHash func(i uint64) ([]byte, error),
	getNodeHash func(s, e uint64) ([]byte, error),
) ([][]byte, error) {
	if end-start == 1 {
		_, err := getLeafHash(index)
		if err != nil {
			return nil, err
		}
		return nil, nil
	}

	n := end - start
	k := LargestPowerOfTwoLessThan(n)
	mid := start + k

	if index < mid {
		proof, err := inclusionProofRec(start, mid, index, getLeafHash, getNodeHash)
		if err != nil {
			return nil, err
		}
		rightHash, err := getNodeHash(mid, end)
		if err != nil {
			return nil, err
		}
		return append(proof, slices.Clone(rightHash)), nil
	}

	proof, err := inclusionProofRec(mid, end, index, getLeafHash, getNodeHash)
	if err != nil {
		return nil, err
	}
	leftHash, err := getNodeHash(start, mid)
	if err != nil {
		return nil, err
	}
	return append(proof, slices.Clone(leftHash)), nil
}

func EvaluateInclusionProof(
	start, end, index uint64,
	proof [][]byte,
	entryHash []byte,
) ([]byte, error) {
	if err := CheckSubtree(start, end); err != nil {
		return nil, err
	}
	if index < start || index >= end {
		return nil, fmt.Errorf("index %d not in [%d, %d)", index, start, end)
	}
	if entryHash == nil {
		return nil, errors.New("entryHash is nil")
	}

	fn := index - start
	sn := end - start - 1
	r := slices.Clone(entryHash)

	for _, p := range proof {
		if sn == 0 {
			return nil, ErrInvalidProof
		}

		if (fn&1) == 1 || fn == sn {
			r = HashNode(p, r)

			for (fn & 1) == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashNode(r, p)
		}

		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return nil, ErrInvalidProof
	}

	return r, nil
}

func VerifyInclusionProof(
	start, end, index uint64,
	proof [][]byte,
	entryHash []byte,
	subtreeHash []byte,
) error {
	if subtreeHash == nil {
		return errors.New("subtreeHash is nil")
	}

	expectedSubtreeHash, err := EvaluateInclusionProof(start, end, index, proof, entryHash)
	if err != nil {
		return err
	}

	if !bytes.Equal(expectedSubtreeHash, subtreeHash) {
		return fmt.Errorf("inclusion proof subtree hash does not match")
	}

	return nil
}

func GenerateConsistencyProof(
	start, end, treeSize uint64,
	getNodeHash func(s, e uint64) ([]byte, error),
) ([][]byte, error) {
	if treeSize == 0 {
		return nil, fmt.Errorf("tree size = 0")
	}
	if err := CheckSubtree(start, end); err != nil {
		return nil, err
	}
	if getNodeHash == nil {
		return nil, errors.New("getNodeHash is nil")
	}

	return subtreeSubproof(start, end, 0, treeSize, true, getNodeHash)
}

func subtreeSubproof(
	start, end uint64,
	base, treeSize uint64,
	b bool,
	getNodeHash func(s, e uint64) ([]byte, error),
) ([][]byte, error) {
	if start == 0 && end == treeSize {
		if b {
			return nil, nil
		}
		h, err := getNodeHash(base, base+treeSize)
		if err != nil {
			return nil, err
		}
		return [][]byte{slices.Clone(h)}, nil
	}

	if treeSize <= 1 {
		return nil, fmt.Errorf("subtree size <= 1")
	}

	k := LargestPowerOfTwoLessThan(treeSize)

	switch {
	case end <= k:
		proof, err := subtreeSubproof(start, end, base, k, b, getNodeHash)
		if err != nil {
			return nil, err
		}
		right, err := getNodeHash(base+k, base+treeSize)
		if err != nil {
			return nil, err
		}
		return append(proof, slices.Clone(right)), nil

	case k <= start:
		proof, err := subtreeSubproof(start-k, end-k, base+k, treeSize-k, b, getNodeHash)
		if err != nil {
			return nil, err
		}
		left, err := getNodeHash(base, base+k)
		if err != nil {
			return nil, err
		}
		return append(proof, slices.Clone(left)), nil

	default:
		if start != 0 {
			return nil, fmt.Errorf("subtree start != 0")
		}
		proof, err := subtreeSubproof(0, end-k, base+k, treeSize-k, false, getNodeHash)
		if err != nil {
			return nil, err
		}
		left, err := getNodeHash(base, base+k)
		if err != nil {
			return nil, err
		}
		return append(proof, slices.Clone(left)), nil
	}
}

func VerifyConsistencyProof(
	start, end, treeSize uint64,
	proof [][]byte,
	nodeHash, rootHash []byte,
) error {
	if treeSize == 0 {
		return fmt.Errorf("tree size = 0")
	}
	if err := CheckSubtree(start, end); err != nil {
		return err
	}
	if nodeHash == nil || rootHash == nil {
		return errors.New("nodeHash/rootHash is nil")
	}

	fn := start
	sn := end - 1
	tn := treeSize - 1

	if sn == tn {
		for fn != sn {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	} else {
		for fn != sn && (sn&1) == 1 {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	}

	var fr, sr []byte
	proofIndex := 0

	if fn == sn {
		fr = slices.Clone(nodeHash)
		sr = slices.Clone(nodeHash)
	} else {
		if len(proof) == 0 {
			return ErrInvalidProof
		}
		fr = slices.Clone(proof[0])
		sr = slices.Clone(proof[0])
		proofIndex = 1
	}

	for ; proofIndex < len(proof); proofIndex++ {
		c := proof[proofIndex]

		if tn == 0 {
			return ErrInvalidProof
		}

		if (sn&1) == 1 || sn == tn {
			if fn < sn {
				fr = HashNode(c, fr)
			}
			sr = HashNode(c, sr)

			for (sn & 1) == 0 {
				fn >>= 1
				sn >>= 1
				tn >>= 1
			}
		} else {
			sr = HashNode(sr, c)
		}

		fn >>= 1
		sn >>= 1
		tn >>= 1
	}

	if tn != 0 {
		return fmt.Errorf("%w: tn != 0", ErrInvalidProof)
	}
	if !bytes.Equal(fr, nodeHash) {
		return fmt.Errorf("reconstructed subtree hash does not match")
	}
	if !bytes.Equal(sr, rootHash) {
		return fmt.Errorf("reconstructed root hash does not match")
	}

	return nil
}
