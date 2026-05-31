package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	var algo string
	var out string

	root := &cobra.Command{
		Use:   "keygen",
		Short: "Generate ML-DSA keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generate(logger, algo, out)
		},
	}
	root.Flags().StringVar(&algo, "algo", "mldsa44", "Algorithm: mldsa44, mldsa65, mldsa87")
	root.Flags().StringVar(&out, "out", "", "Output path prefix (required)")
	_ = root.MarkFlagRequired("out")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func generate(logger *zap.Logger, algo, out string) error {
	type key interface{ MarshalBinary() ([]byte, error) }
	var (
		pub, priv key
		err       error
	)

	switch algo {
	case "mldsa44":
		pub, priv, err = mldsa44.GenerateKey(nil)

	case "mldsa65":
		pub, priv, err = mldsa65.GenerateKey(nil)

	case "mldsa87":
		pub, priv, err = mldsa87.GenerateKey(nil)

	default:
		return fmt.Errorf("unknown algorithm: %s", algo)
	}

	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	pubB, err := pub.MarshalBinary()
	if err != nil {
		return err
	}
	privB, err := priv.MarshalBinary()
	if err != nil {
		return err
	}

	if err := os.WriteFile(out+".pub", pubB, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	if err := os.WriteFile(out+".priv", privB, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	logger.Info("keys generated",
		zap.String("algo", algo),
		zap.String("pub", out+".pub"),
		zap.String("priv", out+".priv"),
	)
	return nil
}
