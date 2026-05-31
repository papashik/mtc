package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/papashik/mtc/pkg/cert"
	"github.com/papashik/mtc/pkg/log"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	cfgPath string

	logger *zap.Logger
	cfg    *Config
	l      *log.Log
)

func main() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	root := &cobra.Command{Use: "ca"}
	root.PersistentFlags().StringVar(&cfgPath, "config", "ca.yaml", "Config file path")
	root.AddCommand(serveCmd())
	_ = root.ParseFlags(os.Args[1:])

	cfg, err = loadConfig(cfgPath)
	if err != nil {
		logger.Fatal("load config", zap.Error(err))
	}
	storage, err := log.OpenStorage(cfg.DataDir)
	if err != nil {
		logger.Fatal("open storage", zap.Error(err))
	}
	l, err = log.Open(storage, cfg.CAID, cfg.MaxActiveLandmarks)
	if err != nil {
		logger.Fatal("open log", zap.Error(err))
	}
	defer l.Close()

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run CA HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			signer, err := LoadCASigner(cfg.SigningKey, cfg.CAID)
			if err != nil {
				return fmt.Errorf("load signer: %w", err)
			}

			cp := NewCheckpointer(cfg, l, signer, logger)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go cp.Run(ctx)

			return runServer(cfg, l)
		},
	}
}

func issueFromCSR(cfg *Config, l *log.Log, csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	// var rawKey []byte
	// for _, ext := range csr.Extensions {
	// 	if ext.Id.Equal(cert.OIDAlgMTCProof) {
	// 		var b64data string
	// 		_, err := asn1.Unmarshal(ext.Value, &b64data)
	// 		if err != nil {
	// 			return nil, fmt.Errorf("failed to unmarshal UTF8String: %w", err)
	// 		}
	// 		rawKey, err = base64.StdEncoding.DecodeString(b64data)
	// 		if err != nil {
	// 			return nil, fmt.Errorf("failed to unmarshal UTF8String: %w", err)
	// 		}
	// 	}
	// }

	// spki := cert.BytesToSPKI(rawKey)
	// spkiDER, err := asn1.Marshal(spki)
	// if err != nil {
	// 	return nil, err
	// }

	spkiDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	now := time.Now()
	entry, err := cert.BuildEntryFromCSR(csr, cfg.CAID, now, now.Add(cfg.CertValidity), spkiDER)
	if err != nil {
		return nil, fmt.Errorf("build entry: %w", err)
	}

	entryBytes, err := cert.SerializeEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("serialize entry: %w", err)
	}

	index, err := l.Append(entryBytes)
	if err != nil {
		return nil, fmt.Errorf("append to log: %w", err)
	}

	time.Sleep(2 * cfg.CheckpointInterval)
	cp := l.Checkpoint()

	inclusionProof, err := l.GenerateInclusionProof(index, 0, cp.End)
	if err != nil {
		return nil, fmt.Errorf("generate inclusion proof: %w", err)
	}

	proof := &cert.MTCProof{
		Start:          0,
		End:            cp.End,
		InclusionProof: inclusionProof,
		Signatures:     cp.Signatures,
	}

	certDER, err := cert.AssembleCertificate(entry, 1, index, proof, spkiDER)
	if err != nil {
		return nil, fmt.Errorf("assemble cert: %w", err)
	}

	logger.Info("issued certificate",
		zap.Uint64("index", index),
		zap.Uint64("subtree_start", 0),
		zap.Uint64("subtree_end", cp.End),
	)
	return certDER, nil
}

func runServer(cfg *Config, l *log.Log) error {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /issue", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		certDER, err := issueFromCSR(cfg, l, body)
		if err != nil {
			logger.Error("issue failed", zap.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			logger.Error("writing response", zap.Error(err))
		}
	})

	mux.HandleFunc("POST /landmark", func(w http.ResponseWriter, r *http.Request) {
		lm, err := l.AddLandmark()
		if err != nil {
			logger.Error("allocating failed", zap.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logger.Info("landmark allocated", zap.Uint64("tree_size", lm.End))
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(lm.End); err != nil {
			logger.Error("writing response", zap.Error(err))
		}
	})

	mux.HandleFunc("GET /landmarks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(l.ActiveLandmarks()); err != nil {
			logger.Error("writing response", zap.Error(err))
		}
	})

	mux.HandleFunc("GET /entry/{n}", func(w http.ResponseWriter, r *http.Request) {
		nStr := r.PathValue("n")
		n, err := strconv.ParseUint(nStr, 10, 64)
		if err != nil || n < 0 {
			http.Error(w, "bad entry number", http.StatusBadRequest)
			return
		}
		entry, err := l.GetEntry(n)
		if err != nil {
			logger.Error("getting entry", zap.Error(err))
			http.Error(w, "getting entry: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(entry); err != nil {
			logger.Error("writing response", zap.Error(err))
		}
	})

	mux.HandleFunc("GET /checkpoint", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(l.Checkpoint()); err != nil {
			logger.Error("writing response", zap.Error(err))
		}
	})

	logger.Info("CA server starting", zap.String("addr", cfg.ServerAddr))
	return http.ListenAndServe(cfg.ServerAddr, mux)
}
