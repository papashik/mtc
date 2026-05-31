package mtc

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/papashik/mtc/pkg/cert"
	"gopkg.in/yaml.v3"
)

type Config struct {
	CAServers []CAServerConfig `yaml:"ca_servers"`
	Cosigners []CosignerConfig `yaml:"cosigners"`
	Policy    PolicyConfig     `yaml:"policy"`
	DataDir   string           `yaml:"data_dir"`
}

type CAServerConfig struct {
	ID        string `yaml:"id"`
	URL       string `yaml:"url"`
	PublicKey string `yaml:"public_key"`
}

type CosignerConfig struct {
	ID        string `yaml:"id"`
	PublicKey string `yaml:"public_key"`
}

type PolicyConfig struct {
	RequireCASignature bool `yaml:"require_ca_signature"`
	MinCosigners       int  `yaml:"min_cosigners"`
}

func LoadProtos(ctx cert.VerifyContext) []string {
	protos := make([]string, 0, len(ctx.Landmarks))
	for caID, lms := range ctx.Landmarks {
		protos = append(protos, Proto(caID, lms))
	}
	return protos
}

func VerifyPeerCertificateFunc(ctx cert.VerifyContext) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificates provided")
		}
		return cert.VerifyCertificate(rawCerts[0], ctx)
	}
}

func MustLoadVerifyContext(path string) cert.VerifyContext {
	ctx, err := LoadVerifyContext(path)
	if err != nil {
		panic(err)
	}
	return ctx
}

func LoadVerifyContext(path string) (cert.VerifyContext, error) {
	cfg, err := LoadConfig(path)
	if err == nil {
		return BuildVerifyContext(cfg)
	}
	return cert.VerifyContext{}, err
}

func MustLoadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}
	return &cfg
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func BuildVerifyContext(cfg *Config) (cert.VerifyContext, error) {
	ctx := cert.VerifyContext{
		Policy: cert.Policy{
			RequireCASignature: cfg.Policy.RequireCASignature,
			MinCosigners:       cfg.Policy.MinCosigners,
		},
	}

	ctx.CAs = map[string][]byte{}
	ctx.Cosigners = map[string][]byte{}
	ctx.Landmarks = map[string][]cert.Checkpoint{}

	for _, ca := range cfg.CAServers {
		keyData, err := os.ReadFile(ca.PublicKey)
		if err != nil {
			return cert.VerifyContext{}, fmt.Errorf("read CA key %s: %w", ca.ID, err)
		}
		ctx.CAs[ca.ID] = keyData

		ctx.Landmarks[ca.ID], _ = ReadCALandmarks(cfg.DataDir, ca.ID)
		// if err != nil {
		// 	return cert.VerifyContext{}, fmt.Errorf("read CA landmarks %s: %w", ca.ID, err)
		// }
	}

	for _, cs := range cfg.Cosigners {
		keyData, err := os.ReadFile(cs.PublicKey)
		if err != nil {
			return cert.VerifyContext{}, fmt.Errorf("read cosigner key %s: %w", cs.ID, err)
		}
		ctx.Cosigners[cs.ID] = keyData
	}

	return ctx, nil
}

func ReadCALandmarks(dataDir, caID string) ([]cert.Checkpoint, error) {
	file, err := os.Open(filepath.Join(dataDir, caID+".json"))
	if err != nil {
		return nil, err
	}
	var lms []cert.Checkpoint
	return lms, json.NewDecoder(file).Decode(&lms)
}

func WriteCALandmarks(lms []cert.Checkpoint, dataDir, caID string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}
	file, err := os.Create(filepath.Join(dataDir, caID+".json"))
	if err != nil {
		return err
	}
	return json.NewEncoder(file).Encode(lms)
}
