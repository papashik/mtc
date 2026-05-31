package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/papashik/mtc/internal/requests"
	"github.com/papashik/mtc/pkg/cert"
	"github.com/papashik/mtc/pkg/log"
	"go.uber.org/zap"
)

type Checkpointer struct {
	cfg          *Config
	log          *log.Log
	signer       *CASigner
	logger       *zap.Logger
	prevTreeSize uint64
}

func NewCheckpointer(cfg *Config, l *log.Log, signer *CASigner, logger *zap.Logger) *Checkpointer {
	return &Checkpointer{
		cfg:    cfg,
		log:    l,
		signer: signer,
		logger: logger,
	}
}

func (c *Checkpointer) Run(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.CheckpointInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.run(); err != nil {
				c.logger.Error("checkpointer failed", zap.Error(err))
			}
		}
	}
}

func (c *Checkpointer) run() error {
	treeSize, rootHash := c.log.TreeInfo()
	cp := c.log.Checkpoint()
	if treeSize == cp.End {
		return nil
	}

	consistencyProof, err := c.log.GenerateConsistencyProof(0, cp.End)
	if err != nil {
		return fmt.Errorf("generate consistency proof: %w", err)
	}

	c.logger.Info("running checkpoint", zap.Uint64("tree_size", treeSize))

	sig, err := c.signer.SignSubtree(0, treeSize, rootHash)
	if err != nil {
		return fmt.Errorf("sign subtree: %w", err)
	}
	sigs, err := c.requestCosignatures(treeSize, rootHash, sig, consistencyProof)
	if err != nil {
		return fmt.Errorf("cosignature request failed: %w", err)
	}
	sigs = append(sigs, sig)
	slices.SortFunc(sigs, func(a, b cert.MTCSignature) int { return cmp.Compare(string(a.CosignerID), string(b.CosignerID)) })

	c.prevTreeSize = treeSize
	return c.log.UpdateCheckpoint(cert.Checkpoint{
		Start:      0,
		End:        treeSize,
		RootHash:   rootHash,
		Signatures: sigs,
	})
}

func (c *Checkpointer) requestCosignatures(
	treeSize uint64,
	rootHash []byte,
	caSig cert.MTCSignature,
	consistencyProof [][]byte,
) ([]cert.MTCSignature, error) {

	req := requests.SignCheckpointRequest{
		CAID:             c.cfg.CAID,
		CheckpointSize:   treeSize,
		CheckpointHash:   rootHash,
		CASignature:      caSig.Signature,
		ConsistencyProof: consistencyProof,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	var sigs []cert.MTCSignature
	for _, cs := range c.cfg.Cosigners {
		url := cs.URL + requests.SignCheckpointURL
		resp, err := http.Post(url, "application/json", bytes.NewReader(reqBytes))
		if err != nil {
			c.logger.Warn("cosigner unreachable", zap.String("cosigner", cs.ID), zap.Error(err))
			return nil, fmt.Errorf("cosigner unreachable: %w", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()

		var sig cert.MTCSignature
		if err := json.Unmarshal(body, &sig); err != nil {
			c.logger.Warn("cosigner bad response", zap.String("cosigner", cs.ID), zap.String("error", string(body)))
			return nil, fmt.Errorf("cosigner bad response: %s", string(body))
		}

		if resp.StatusCode != http.StatusOK {
			c.logger.Warn("cosigner rejected", zap.String("cosigner", cs.ID), zap.Int("status", resp.StatusCode), zap.Any("response", sig))
			return nil, fmt.Errorf("cosigner rejected: %w", err)
		}

		sigs = append(sigs, sig)
	}
	return sigs, nil
}
