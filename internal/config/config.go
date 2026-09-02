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
	AdminToken      string `yaml:"admin_token"`
	SigningKey      string `yaml:"signing_key"`
	TokenTTLSeconds int    `yaml:"token_ttl_seconds"`
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
	if cfg.TokenTTLSeconds == 0 {
		cfg.TokenTTLSeconds = 20 * 60
	}
	if cfg.MaxUploadBytes == 0 {
		cfg.MaxUploadBytes = 256 << 20
	}
	if strings.TrimSpace(cfg.AdminToken) == "" {
		return nil, errors.New("admin_token is required")
	}
	if len(cfg.SigningKey) < 32 {
		return nil, errors.New("signing_key must contain at least 32 characters")
	}
	if cfg.TokenTTLSeconds < 1 {
		return nil, errors.New("token_ttl_seconds must be positive")
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
