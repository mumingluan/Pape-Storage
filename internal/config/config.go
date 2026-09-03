package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	BindHost        string `yaml:"bind_host"`
	BindPort        int    `yaml:"bind_port"`
	DataDir         string `yaml:"data_dir"`
	PublicBaseURL   string `yaml:"public_base_url"`
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	MaxUploadBytes  int64  `yaml:"max_upload_bytes"`

	BaseDir string `yaml:"-"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cfg.BaseDir = filepath.Dir(abs)
	if cfg.BindHost == "" {
		cfg.BindHost = "127.0.0.1"
	}
	if cfg.BindPort == 0 {
		cfg.BindPort = 18083
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data/objects"
	}
	if cfg.MaxUploadBytes == 0 {
		cfg.MaxUploadBytes = 256 << 20
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("bucket is required")
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, errors.New("region is required")
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.AccessKeySecret) == "" {
		return nil, errors.New("access_key_id and access_key_secret are required")
	}
	if cfg.MaxUploadBytes < 1 {
		return nil, errors.New("max_upload_bytes must be positive")
	}
	parsed, err := url.Parse(cfg.PublicBaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("public_base_url must be an absolute HTTP(S) URL")
	}
	cfg.PublicBaseURL = strings.TrimRight(cfg.PublicBaseURL, "/")
	return &cfg, nil
}

func (c *Config) ObjectDir() string {
	if filepath.IsAbs(c.DataDir) {
		return filepath.Clean(c.DataDir)
	}
	return filepath.Clean(filepath.Join(c.BaseDir, c.DataDir))
}
