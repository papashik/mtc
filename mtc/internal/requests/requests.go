package requests

const (
	SignCheckpointURL = "/sign-checkpoint"
)

type SignCheckpointRequest struct {
	CAID             string   `json:"ca_id"`
	CheckpointSize   uint64   `json:"checkpoint_size"`
	CheckpointHash   []byte   `json:"checkpoint_hash"`
	CASignature      []byte   `json:"ca_signature"`
	ConsistencyProof [][]byte `json:"consistency_proof"`
}
