package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objstore.json")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Tanpa file: nilai bawaan.
	cfg, err := loadConfig(nil)
	if err != nil || cfg.Addr != ":9000" || cfg.Region != "us-east-1" || cfg.MaxBuckets != 1000 {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}

	// File menimpa bawaan; flag eksplisit menimpa file; sisanya tetap bawaan.
	write(`{"addr": ":8000", "domain": "s3.contoh.test", "max_buckets": 5}`)
	cfg, err = loadConfig([]string{"--config", path, "--addr", ":7000"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":7000" || cfg.Domain != "s3.contoh.test" || cfg.MaxBuckets != 5 || cfg.Data != "./data" {
		t.Fatalf("cfg = %+v", cfg)
	}

	write(`{"adr": ":8000"}`)
	if _, err := loadConfig([]string{"--config", path}); err == nil {
		t.Fatal("nama pengaturan yang salah ketik harus ditolak")
	}

	write(`{"tls_cert": "cert.pem"}`)
	if _, err := loadConfig([]string{"--config", path}); err == nil {
		t.Fatal("tls_cert tanpa tls_key harus ditolak")
	}
}
