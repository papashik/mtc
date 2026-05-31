package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/papashik/mtc/internal/helpers"
	"github.com/papashik/mtc/internal/requests"
	"github.com/papashik/mtc/pkg/cert"
	"github.com/papashik/mtc/pkg/core"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	checkpointFileName = "checkpoint.json"
)

var logger *zap.Logger

func main() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	var cfgPath string
	root := &cobra.Command{
		Use:   "cosigner",
		Short: "Run MTC cosigner",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			return runCosigner(cfg)
		},
	}
	root.Flags().StringVar(&cfgPath, "config", "cosigner.yaml", "Config file path")

	if err := root.Execute(); err != nil {
		logger.Fatal("execute", zap.Error(err))
	}
}

type Cosigner struct {
	mu    sync.Mutex
	cp    cert.Checkpoint
	priv  *mldsa44.PrivateKey
	caPub *mldsa44.PublicKey
	cfg   *Config
}

func newCosigner(cfg *Config) (*Cosigner, error) {
	privData, err := os.ReadFile(cfg.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	priv := new(mldsa44.PrivateKey)
	if err := priv.UnmarshalBinary(privData); err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}

	caPubData, err := os.ReadFile(cfg.CAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("read ca public key: %w", err)
	}
	caPub := new(mldsa44.PublicKey)
	if err := caPub.UnmarshalBinary(caPubData); err != nil {
		return nil, fmt.Errorf("parse ca public key: %w", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, err
	}

	s := &Cosigner{priv: priv, caPub: caPub, cfg: cfg}
	path := filepath.Join(s.cfg.DataDir, checkpointFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		logger.Debug("no existing checkpoint", zap.Error(err))
	} else if err != nil {
		return nil, err
	} else if err := json.Unmarshal(data, &s.cp); err != nil {
		return nil, err
	} else {
		logger.Info("loaded checkpoint", zap.Uint64("tree_size", s.cp.End))
	}

	return s, nil
}

func (s *Cosigner) saveCheckpoint() error {
	path := filepath.Join(s.cfg.DataDir, checkpointFileName)
	data, err := json.MarshalIndent(s.cp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s *Cosigner) handleSignSubtree(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var req requests.SignCheckpointRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "parse body", http.StatusBadRequest)
		return
	}

	if req.CAID != s.cfg.CAID {
		http.Error(w, "wrong CA id", http.StatusBadRequest)
		return
	}

	caMsg := helpers.CosignedMessage(req.CAID, req.CAID, 0, req.CheckpointSize, req.CheckpointHash)
	if !mldsa44.Verify(s.caPub, caMsg, nil, req.CASignature) {
		http.Error(w, "CA checkpoint signature invalid", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cp.End > 0 {
		if err := core.VerifyConsistencyProof(
			s.cp.Start, s.cp.End,
			req.CheckpointSize,
			req.ConsistencyProof,
			s.cp.RootHash,
			req.CheckpointHash,
		); err != nil {
			logger.Warn("consistency proof failed",
				zap.Error(err),
				zap.Uint64("prev", s.cp.End),
				zap.Uint64("new", req.CheckpointSize),
			)
			http.Error(w, "consistency proof failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if req.CheckpointSize > s.cp.End {
		s.cp.End = req.CheckpointSize
		s.cp.RootHash = req.CheckpointHash
		s.cp.Signatures = []cert.MTCSignature{{CosignerID: req.CAID, Signature: req.CASignature}}
		if err := s.saveCheckpoint(); err != nil {
			logger.Error("save checkpoint failed", zap.Error(err))
		}
	}

	msg := helpers.CosignedMessage(s.cfg.CosignerID, req.CAID, 0, req.CheckpointSize, req.CheckpointHash)
	sig, err := s.priv.Sign(nil, msg, nil)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}

	resp := cert.MTCSignature{
		CosignerID: s.cfg.CosignerID,
		Signature:  sig,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error("writing response", zap.Error(err))
	}

	logger.Info("signed subtree", zap.Uint64("tree_size", req.CheckpointSize))
}

func runCosigner(cfg *Config) error {
	state, err := newCosigner(cfg)
	if err != nil {
		return fmt.Errorf("init state: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+requests.SignCheckpointURL, state.handleSignSubtree)

	logger.Info("cosigner starting", zap.String("addr", cfg.ServerAddr), zap.String("id", cfg.CosignerID))
	return http.ListenAndServe(cfg.ServerAddr, mux)
}
