package log

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	hashSize       = 32
	entriesDirName = "entries"
	hashesFileName = "hashes.bin"
	peaksFileName  = "peaks.bin"
	metaFileName   = "meta.json"
)

type Storage struct {
	dir        string
	hashesFile *os.File
	peaksFile  *os.File
	metaFile   *os.File
}

func OpenStorage(dir string) (*Storage, error) {
	if err := os.MkdirAll(filepath.Join(dir, entriesDirName), 0755); err != nil {
		return nil, err
	}

	hashesPath := filepath.Join(dir, hashesFileName)
	hashes, err := os.OpenFile(hashesPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	peaksPath := filepath.Join(dir, peaksFileName)
	peaks, err := os.OpenFile(peaksPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	metaPath := filepath.Join(dir, metaFileName)
	meta, err := os.OpenFile(metaPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	return &Storage{dir: dir, hashesFile: hashes, peaksFile: peaks, metaFile: meta}, nil
}

func (s *Storage) Close() {
	_ = s.hashesFile.Close()
	_ = s.peaksFile.Close()
	_ = s.metaFile.Close()
}

func (s *Storage) AppendLeafHash(index uint64, hash []byte) error {
	offset := int64(index) * hashSize
	_, err := s.hashesFile.WriteAt(hash[:hashSize], offset)
	return err
}

func (s *Storage) GetLeafHash(index uint64) ([]byte, error) {
	offset := int64(index) * hashSize
	buf := make([]byte, hashSize)
	_, err := s.hashesFile.ReadAt(buf, offset)
	if err != nil {
		return nil, fmt.Errorf("read leaf hash %d: %w", index, err)
	}
	return buf, nil
}

func (s *Storage) AppendEntry(index uint64, data []byte) error {
	entryPath := filepath.Join(s.dir, entriesDirName, fmt.Sprintf("%d.bin", index))
	return os.WriteFile(entryPath, data, 0644)
}

func (s *Storage) GetEntry(index uint64) ([]byte, error) {
	entryPath := filepath.Join(s.dir, entriesDirName, fmt.Sprintf("%d.bin", index))
	data, err := os.ReadFile(entryPath)
	if err != nil {
		return nil, fmt.Errorf("read entry %d: %w", index, err)
	}
	return data, nil
}

func (s *Storage) SavePeaks(peaks [][]byte, treeSize uint64) error {
	buf := make([]byte, 8+8+len(peaks)*hashSize)
	binary.BigEndian.PutUint64(buf[0:8], treeSize)
	binary.BigEndian.PutUint64(buf[8:16], uint64(len(peaks)))
	for i, p := range peaks {
		copy(buf[16+i*hashSize:], p)
	}
	if err := s.peaksFile.Truncate(0); err != nil {
		return err
	}
	_, err := s.peaksFile.WriteAt(buf, 0)
	return err
}

func (s *Storage) LoadPeaks() ([][]byte, uint64, error) {
	if _, err := s.peaksFile.Seek(0, 0); err != nil {
		return nil, 0, err
	}
	data, err := io.ReadAll(s.peaksFile)
	if err != nil {
		return nil, 0, err
	}
	if len(data) == 0 {
		return nil, 0, nil
	} else if len(data) < 16 {
		return nil, 0, fmt.Errorf("len(peaks) < 16")
	}
	treeSize := binary.BigEndian.Uint64(data[0:8])
	count := binary.BigEndian.Uint64(data[8:16])
	peaks := make([][]byte, count)
	for i := uint64(0); i < count; i++ {
		off := 16 + i*hashSize
		p := make([]byte, hashSize)
		copy(p, data[off:off+uint64(hashSize)])
		peaks[i] = p
	}
	return peaks, treeSize, nil
}

func (s *Storage) SaveMeta(meta Meta) error {
	if err := s.metaFile.Truncate(0); err != nil {
		return err
	}
	jsonBytes, err := json.MarshalIndent(meta, "", "\t")
	if err != nil {
		return err
	}
	_, err = s.metaFile.WriteAt(jsonBytes, 0)
	return err
}

func (s *Storage) LoadMeta() (Meta, error) {
	if _, err := s.metaFile.Seek(0, 0); err != nil {
		return Meta{}, err
	}
	var m Meta
	err := json.NewDecoder(s.metaFile).Decode(&m)
	if err == io.EOF {
		return Meta{}, nil
	}
	return m, err
}
