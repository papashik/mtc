package main

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultCheckpointInterval = 5 * time.Second
	defaultCertValidity       = 7 * 24 * time.Hour
	defaultMaxActiveLandmarks = 1000
)

type CosignerConfig struct {
	ID        string `yaml:"id"`
	URL       string `yaml:"url"`
	PublicKey string `yaml:"public_key"`
}

type Config struct {
	CAID               string           `yaml:"ca_id"`
	DataDir            string           `yaml:"data_dir"`
	SigningKey         string           `yaml:"signing_key"`
	Cosigners          []CosignerConfig `yaml:"cosigners"`
	ServerAddr         string           `yaml:"server_addr"`
	CheckpointInterval time.Duration    `yaml:"checkpoint_interval"`
	CertValidity       time.Duration    `yaml:"cert_validity"`
	MaxActiveLandmarks int              `yaml:"max_active_landmarks"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.CheckpointInterval == 0 {
		cfg.CheckpointInterval = defaultCheckpointInterval
	}
	if cfg.CertValidity == 0 {
		cfg.CertValidity = defaultCertValidity
	}
	if cfg.MaxActiveLandmarks == 0 {
		cfg.MaxActiveLandmarks = defaultMaxActiveLandmarks
	}
	return &cfg, nil
}
