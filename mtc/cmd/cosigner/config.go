package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CosignerID  string `yaml:"cosigner_id"`
	SigningKey  string `yaml:"signing_key"`
	CAID        string `yaml:"ca_id"`
	CAPublicKey string `yaml:"ca_public_key"`
	ServerAddr  string `yaml:"server_addr"`
	DataDir     string `yaml:"data_dir"`
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
	return &cfg, nil
}
