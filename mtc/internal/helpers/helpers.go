package helpers

import (
	"encoding/binary"
)

func Uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func CosignedMessage(cosignerID, caID string, start, end uint64, hash []byte) []byte {
	label := []byte("subtree/v1\n\x00")
	msg := make([]byte, 0, 128)
	msg = append(msg, label...)
	msg = append(msg, byte(len(cosignerID)))
	msg = append(msg, []byte(cosignerID)...)
	msg = append(msg, byte(len(caID)))
	msg = append(msg, []byte(caID)...)
	msg = append(msg, Uint64ToBytes(start)...)
	msg = append(msg, Uint64ToBytes(end)...)
	msg = append(msg, hash...)
	return msg
}
