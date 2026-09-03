package config

import (
	"path/filepath"
	"testing"
)

func TestExampleConfigUsesCurrentSchema(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindPort != 65287 || cfg.PublicBaseURL != "https://storage-deepspace.papegames.com" || cfg.Bucket != "pape" || cfg.Region != "cn-hangzhou" {
		t.Fatalf("example config = %+v", cfg)
	}
}
