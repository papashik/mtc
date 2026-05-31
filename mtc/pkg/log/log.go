package log

import (
	"fmt"
	"slices"
	"sync"

	"github.com/papashik/mtc/pkg/cert"
	"github.com/papashik/mtc/pkg/core"
)

type Meta struct {
	CAID       string `json:"ca_id"`
	LogID      uint16 `json:"log_id"`
	Checkpoint cert.Checkpoint

	MaxActiveLandmarks int               `json:"max_active_landmarks"`
	Landmarks          []cert.Checkpoint `json:"landmarks"`
}

func NewMeta(caID string, maxActiveLandmarks int) Meta {
	return Meta{
		CAID:               caID,
		LogID:              1,
		Checkpoint:         cert.Checkpoint{Start: 0, End: 1, RootHash: nil},
		MaxActiveLandmarks: maxActiveLandmarks,
		Landmarks:          []cert.Checkpoint{{Start: 0, End: 1, RootHash: nil}},
	}
}

type Log struct {
	mu      sync.RWMutex
	storage *Storage
	tree    *core.MerkleTree
	meta    Meta
}

func Open(storage *Storage, caID string, maxActiveLandmarks int) (*Log, error) {
	l := &Log{storage: storage}

	peaks, treeSize, err := storage.LoadPeaks()
	if err != nil {
		return nil, fmt.Errorf("load peaks: %w", err)
	}
	l.tree = core.NewMerkleTreeFromPeaks(peaks, treeSize)

	l.meta, err = storage.LoadMeta()
	if err != nil {
		return nil, fmt.Errorf("load meta: %w", err)
	}
	if l.meta.CAID == "" {
		l.meta = NewMeta(caID, maxActiveLandmarks)
		if err := l.storage.SaveMeta(l.meta); err != nil {
			return nil, err
		}
	} else if l.meta.CAID != caID {
		return nil, fmt.Errorf("meta error: %s != %s", l.meta.CAID, caID)
	}

	if treeSize == 0 {
		if _, err := l.Append([]byte{0x00, 0x00}); err != nil {
			return nil, fmt.Errorf("init null entry: %w", err)
		}
	}
	return l, nil
}

func (l *Log) Append(entryData []byte) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	leafHash := core.HashLeaf(entryData)
	index := l.tree.TreeSize()

	if err := l.storage.AppendEntry(index, entryData); err != nil {
		return 0, err
	}
	if err := l.storage.AppendLeafHash(index, leafHash); err != nil {
		return 0, err
	}
	l.tree.AddLeaf(leafHash)

	if err := l.storage.SavePeaks(l.tree.Peaks(), l.tree.TreeSize()); err != nil {
		return 0, err
	}

	return index, nil
}

func (l *Log) TreeInfo() (uint64, []byte) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.TreeSize(), l.tree.RootHash()
}

func (l *Log) Checkpoint() cert.Checkpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.meta.Checkpoint.Copy()
}

func (l *Log) UpdateCheckpoint(cp cert.Checkpoint) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.meta.Checkpoint = cp
	return l.storage.SaveMeta(l.meta)
}

func (l *Log) ActiveLandmarks() []cert.Checkpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.meta.Landmarks) <= l.meta.MaxActiveLandmarks {
		return slices.Clone(l.meta.Landmarks)
	}
	start := len(l.meta.Landmarks) - l.meta.MaxActiveLandmarks
	return slices.Clone(l.meta.Landmarks[start:])
}

func (l *Log) AddLandmark() (cert.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	last := l.meta.Landmarks[len(l.meta.Landmarks)-1]
	if l.meta.Checkpoint.End <= last.End {
		return cert.Checkpoint{}, fmt.Errorf("checkpoint %d not greater than last landmark %d", l.meta.Checkpoint.End, last.End)
	}
	l.meta.Landmarks = append(l.meta.Landmarks, l.meta.Checkpoint.Copy())
	if err := l.storage.SaveMeta(l.meta); err != nil {
		return cert.Checkpoint{}, err
	}

	return l.meta.Checkpoint.Copy(), nil
}

func (l *Log) GetEntry(index uint64) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.storage.GetEntry(index)
}

func (l *Log) GetNodeHash(start, end uint64) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.computeNodeHash(start, end)
}

func (l *Log) computeNodeHash(start, end uint64) ([]byte, error) {
	if end-start == 1 {
		return l.storage.GetLeafHash(start)
	}
	k := core.LargestPowerOfTwoLessThan(end - start)
	mid := start + k
	left, err := l.computeNodeHash(start, mid)
	if err != nil {
		return nil, err
	}
	right, err := l.computeNodeHash(mid, end)
	if err != nil {
		return nil, err
	}
	return core.HashNode(left, right), nil
}

func (l *Log) GenerateInclusionProof(index, subStart, subEnd uint64) ([][]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return core.GenerateInclusionProof(
		index, subStart, subEnd,
		l.storage.GetLeafHash,
		l.computeNodeHash,
	)
}

func (l *Log) GenerateConsistencyProof(start, end uint64) ([][]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return core.GenerateConsistencyProof(start, end, l.tree.TreeSize(), l.computeNodeHash)
}

func (l *Log) Close() {
	l.storage.Close()
}
