package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"object-storage/internal/auth"
	"object-storage/internal/s3api"
	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

func TestCLI(t *testing.T) {
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tokens, _ := auth.NewManager(store, bytes.Repeat([]byte{3}, 32), "rootkey", "rootsecret")
	ts := httptest.NewServer(&s3api.Server{Store: store, Auth: &sigv4.Verifier{Keys: tokens}, Tokens: tokens,
		Region: "us-east-1", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer ts.Close()

	t.Setenv("OBJSTORE_ENDPOINT", ts.URL)
	t.Setenv("OBJSTORE_ACCESS_KEY", "rootkey")
	t.Setenv("OBJSTORE_SECRET_KEY", "rootsecret")
	t.Setenv("OBJSTORE_SESSION_TOKEN", "")

	run := func(args ...string) (int, map[string]any, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := runCLI(args, &stdout, &stderr)
		out := map[string]any{}
		if stdout.Len() > 0 {
			if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
				t.Fatalf("keluaran bukan JSON: %q", stdout.String())
			}
		}
		return code, out, stderr.String()
	}

	code, out, stderr := run("token", "create", "--name", "app", "--permission", "object-read", "--bucket", "a", "--bucket", "b", "--ttl", "2h")
	if code != 0 || out["secret_access_key"] == nil || len(out["buckets"].([]any)) != 2 || out["expires"] == nil {
		t.Fatalf("create: kode %d, %v, %s", code, out, stderr)
	}
	id := out["id"].(string)

	if code, out, _ := run("token", "list"); code != 0 || len(out["tokens"].([]any)) != 1 {
		t.Fatalf("list: kode %d, %v", code, out)
	}
	if code, out, _ := run("token", "show", id); code != 0 || out["name"] != "app" {
		t.Fatalf("show: kode %d, %v", code, out)
	}
	if code, out, _ := run("token", "rotate", id); code != 0 || out["secret_access_key"] == nil {
		t.Fatalf("rotate: kode %d, %v", code, out)
	}
	if code, out, _ := run("token", "disable", id); code != 0 || out["disabled"] != true {
		t.Fatalf("disable: kode %d, %v", code, out)
	}
	if code, out, _ := run("whoami"); code != 0 || out["token_id"] != "root" {
		t.Fatalf("whoami: kode %d, %v", code, out)
	}
	if code, out, _ := run("temp-credentials", "--permission", "object-read", "--ttl", "10m", "--prefix", "foto/"); code != 0 || out["session_token"] == nil {
		t.Fatalf("temp-credentials: kode %d, %v", code, out)
	}
	if code, _, _ := run("token", "delete", id); code != 0 {
		t.Fatalf("delete: kode %d", code)
	}

	// Perintah bucket: akses publik, custom domain, dan aturan lock dari file.
	if err := store.CreateBucket("foto"); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := run("bucket", "public", "foto", "--enable", "--domain", "cdn.contoh.test"); code != 0 || out["public"] != true || len(out["domains"].([]any)) != 1 {
		t.Fatalf("bucket public: kode %d, %v, %s", code, out, stderr)
	}
	if code, _, _ := run("bucket", "public", "foto"); code != 1 {
		t.Fatalf("bucket public tanpa --enable/--disable: kode %d", code)
	}
	rules := filepath.Join(t.TempDir(), "lock.json")
	os.WriteFile(rules, []byte(`[{"id": "arsip", "enabled": true, "prefix": "arsip/", "mode": "age", "days": 30}]`), 0o600)
	if code, out, stderr := run("bucket", "lock", "foto", "--file", rules); code != 0 || len(out["locks"].([]any)) != 1 {
		t.Fatalf("bucket lock: kode %d, %v, %s", code, out, stderr)
	}
	if code, out, _ := run("bucket", "show", "foto"); code != 0 || out["name"] != "foto" || out["public"] != true {
		t.Fatalf("bucket show: kode %d, %v", code, out)
	}
	if code, out, _ := run("bucket", "lock", "foto", "--clear"); code != 0 || out["locks"] != nil {
		t.Fatalf("bucket lock --clear: kode %d, %v", code, out)
	}
	if code, out, _ := run("bucket", "public", "foto", "--disable"); code != 0 || out["public"] != false || out["domains"] != nil {
		t.Fatalf("bucket public --disable: kode %d, %v", code, out)
	}
	if code, _, stderr := run("bucket", "show", "tidak-ada"); code != 1 || !strings.Contains(stderr, "NoSuchBucket") {
		t.Fatalf("bucket show tak ada: kode %d, %q", code, stderr)
	}

	// Kegagalan dilaporkan lewat kode keluar dan pesan di stderr.
	if code, _, stderr := run("token", "delete", id); code != 1 || !strings.Contains(stderr, "NoSuchToken") {
		t.Fatalf("delete kedua: kode %d, %q", code, stderr)
	}
	if code, _, stderr := run("token", "create", "--permission", "ngawur"); code != 1 || !strings.Contains(stderr, "InvalidArgument") {
		t.Fatalf("izin tak dikenal: kode %d, %q", code, stderr)
	}
	if code, _, _ := run("token", "show"); code != 1 {
		t.Fatalf("show tanpa ID: kode %d", code)
	}
	t.Setenv("OBJSTORE_SECRET_KEY", "salah")
	if code, _, stderr := run("token", "list"); code != 1 || !strings.Contains(stderr, "SignatureDoesNotMatch") {
		t.Fatalf("secret salah: kode %d, %q", code, stderr)
	}
}
