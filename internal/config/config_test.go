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
	if cfg.BindPort != 18083 || cfg.PublicBaseURL != "https://storage-deepspace.papegames.com" || cfg.TokenTTLSeconds != 1200 {
		t.Fatalf("example config = %+v", cfg)
	}
}
