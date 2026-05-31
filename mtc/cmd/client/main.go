package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/papashik/mtc/pkg/cert"
	"github.com/papashik/mtc/pkg/mtc"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	cfgPath string
	logger  *zap.Logger
)

func main() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	root := &cobra.Command{Use: "client"}
	root.PersistentFlags().StringVar(&cfgPath, "config", "client.yaml", "Config file path")
	root.AddCommand(validateCmd(), updateCmd(), connectCmd(), serveCmd(), requestCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate MTC certificate from stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			certPEM := mustReadAll(os.Stdin)
			block, _ := pem.Decode(certPEM)
			if block == nil {
				return fmt.Errorf("no PEM block")
			}

			return cert.VerifyCertificate(block.Bytes, mtc.MustLoadVerifyContext(cfgPath))
		},
	}
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update MTC landmarks",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := mtc.MustLoadConfig(cfgPath)
			for _, ca := range cfg.CAServers {
				req, err := http.NewRequest(http.MethodGet, ca.URL, nil)
				if err != nil {
					return err
				}

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode/100 != 2 {
					return fmt.Errorf("GET %s: status %s", ca.URL, resp.Status)
				}

				var landmarks []cert.Checkpoint
				if err := json.NewDecoder(resp.Body).Decode(&landmarks); err != nil {
					return err
				}

				for i, lm := range landmarks {
					if lm.End == 0 || lm.Start >= lm.End {
						logger.Debug("landmark with wrong range", zap.Int("i", i), zap.Uint64("start", lm.Start), zap.Uint64("end", lm.End))
					}
					if i != 0 && len(lm.RootHash) == 0 {
						return fmt.Errorf("landmark %d has empty root_hash", i)
					}
				}
				if err := mtc.WriteCALandmarks(landmarks, cfg.DataDir, ca.ID); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func connectCmd() *cobra.Command {
	var url string
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to server with MTC support",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := mtc.MustLoadVerifyContext(cfgPath)

			config := &tls.Config{
				NextProtos:            mtc.LoadProtos(ctx),
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: mtc.VerifyPeerCertificateFunc(ctx),
			}

			conn, err := tls.Dial("tcp", url, config)
			if err != nil {
				return fmt.Errorf("TLS handshake failed: %w", err)
			}

			logger.Info("got response", zap.Binary("response", mustReadAll(conn)))
			return nil
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "URL to connect")
	return cmd
}

func serveCmd() *cobra.Command {
	var certPath string
	var privKeyPath string
	var port string
	var mode int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "example serve with MTC",
		RunE: func(cmd *cobra.Command, args []string) error {
			if certPath == "" {
				return fmt.Errorf("no cert provided")
			}
			if privKeyPath == "" {
				return fmt.Errorf("no priv key provided")
			}
			certPEM := mustReadFile(certPath)
			certDER, _ := pem.Decode(certPEM)
			config := &tls.Config{
				GetCertificate: mtc.GetCertificateFunc(certDER.Bytes, mustReadFile(privKeyPath), mode),
			}
			ln, err := tls.Listen("tcp", ":"+port, config)
			if err != nil {
				return fmt.Errorf("tls listen: %w", err)
			}
			logger.Info("listening", zap.String("port", port))

			for {
				conn, err := ln.Accept()
				if err != nil {
					logger.Error("accepting conn", zap.Error(err))
					continue
				}
				go func(c net.Conn) {
					_, err := io.WriteString(c, "It works!")
					if err != nil {
						logger.Error("writing response", zap.Error(err))
					}
				}(conn)
			}
		},
	}
	cmd.Flags().StringVar(&certPath, "cert", "", "certificate file path")
	cmd.Flags().StringVar(&privKeyPath, "priv", "", "private key path")
	cmd.Flags().StringVar(&port, "port", "8443", "port to listen")
	cmd.Flags().IntVar(&mode, "mode", 0, "mode to get certificate: 0 - check proto, 1 - always full, 2 - always short")
	return cmd
}

func requestCmd() *cobra.Command {
	var caURL string
	var pubKeyPath string
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Request certificate from CA (CSR on stdin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if caURL == "" {
				return fmt.Errorf("no CA provided")
			}
			if pubKeyPath == "" {
				return fmt.Errorf("no pub key provided")
			}

			csrPEM := mustReadAll(os.Stdin)
			// pubKey := mustReadFile(pubKeyPath)
			// block, _ := pem.Decode(csrPEM)
			// if block == nil {
			// 	return fmt.Errorf("no PEM block")
			// }
			// csr, err := x509.ParseCertificateRequest(block.Bytes)
			// if err != nil {
			// 	return err
			// }

			// b64Data := base64.StdEncoding.EncodeToString(pubKey)
			// utf8Value, err := asn1.Marshal(b64Data)
			// if err != nil {
			// 	return err
			// }
			// csr.ExtraExtensions = append(csr.ExtraExtensions, pkix.Extension{
			// 	Id:    cert.OIDAlgMTCProof,
			// 	Value: utf8Value,
			// })
			// tls.LoadX509KeyPair()
			// priv, _ := rsa.GenerateKey(rand.Reader, 2048)
			// newCsrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
			// if err != nil {
			// 	return err
			// }
			// var b bytes.Buffer
			// if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: newCsrDER}); err != nil {
			// 	return err
			// }
			//resp, err := http.Post(caURL+"/issue", "application/x-pem-file", &b)

			resp, err := http.Post(caURL+"/issue", "application/x-pem-file", bytes.NewReader(csrPEM))
			if err != nil {
				return fmt.Errorf("request cert: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode/2 != 100 {
				return fmt.Errorf("CA error %d: %s", resp.StatusCode, mustReadAll(resp.Body))
			}

			_, err = io.Copy(os.Stdout, resp.Body)
			return err
		},
	}
	cmd.Flags().StringVar(&caURL, "url", "", "CA server URL")
	cmd.Flags().StringVar(&pubKeyPath, "pub", "", "public key path")
	return cmd
}

func mustReadFile(filePath string) []byte {
	b, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	return b
}

func mustReadAll(r io.Reader) []byte {
	b, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}
	return b
}
