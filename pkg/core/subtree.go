package core

import (
	"fmt"
	"math/bits"
)

func CheckSubtree(start, end uint64) error {
	if start >= end {
		return fmt.Errorf("start %d >= end %d", start, end)
	}
	size := end - start
	bc := BitCeil(size)
	if start%bc != 0 {
		return fmt.Errorf("start %d %% bit_ceil(size) %d != 0", start, bc)
	}
	return nil
}

func FindSubtrees(start, end uint64) ([][]uint64, error) {
	if start >= end {
		return nil, fmt.Errorf("start %d >= end %d", start, end)
	}
	if CheckSubtree(start, end) == nil {
		return [][]uint64{{start, end}}, nil
	}

	last := end - 1
	split := bits.Len64(start^last) - 1
	mask := (uint64(1) << split) - 1
	mid := last &^ mask

	leftMask := (^start) & mask
	leftSplit := 0
	if leftMask != 0 {
		leftSplit = bits.Len64(leftMask)
	}
	leftStart := start &^ ((uint64(1) << leftSplit) - 1)

	return [][]uint64{{leftStart, mid}, {mid, end}}, nil
}
