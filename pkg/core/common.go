package core

import (
	"crypto/sha256"
	"math/bits"
)

const HashSize = 32

func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func HashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func LargestPowerOfTwoLessThan(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}

func BitCeil(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	if bits.OnesCount64(n) == 1 {
		return n
	}
	return 1 << bits.Len64(n)
}
