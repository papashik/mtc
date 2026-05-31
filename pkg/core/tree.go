package core

import (
	"crypto/sha256"
	"fmt"
)

type MerkleTree struct {
	peaks    [][]byte
	treeSize uint64
}

func NewMerkleTree() *MerkleTree {
	return &MerkleTree{}
}

func NewMerkleTreeFromPeaks(peaks [][]byte, treeSize uint64) *MerkleTree {
	return &MerkleTree{peaks: peaks, treeSize: treeSize}
}

func (t *MerkleTree) AddLeaf(leafHash []byte) {
	if len(leafHash) != HashSize {
		panic(fmt.Errorf("len(leafHash) != HashSize %d %d", len(leafHash), HashSize))
	}
	carry := leafHash
	n := t.treeSize
	i := 0
	for n&1 == 1 {
		left := t.peaks[len(t.peaks)-1-i]
		carry = HashNode(left, carry)
		i++
		n >>= 1
	}
	if i > 0 {
		t.peaks = t.peaks[:len(t.peaks)-i]
	}
	t.peaks = append(t.peaks, carry)
	t.treeSize++
}

func (t *MerkleTree) RootHash() []byte {
	if len(t.peaks) == 0 {
		return sha256.New().Sum(nil)
	}
	result := t.peaks[len(t.peaks)-1]
	for i := len(t.peaks) - 2; i >= 0; i-- {
		result = HashNode(t.peaks[i], result)
	}
	return result
}

func (t *MerkleTree) TreeSize() uint64 {
	return t.treeSize
}

func (t *MerkleTree) Peaks() [][]byte {
	cp := make([][]byte, len(t.peaks))
	for i, p := range t.peaks {
		cp[i] = make([]byte, len(p))
		copy(cp[i], p)
	}
	return cp
}
