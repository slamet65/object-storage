// Perintah objstore menjalankan server object storage yang kompatibel dengan
// S3 ("objstore" atau "objstore serve") dan mengelola tokennya lewat API
// admin ("objstore token ...", "objstore bucket ...", "objstore
// temp-credentials", "objstore whoami").
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"object-storage/internal/auth"
	"object-storage/internal/lifecycle"
	"object-storage/internal/s3api"
	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

// config adalah pengaturan server. Urutan prioritas: flag yang diberikan
// eksplisit, lalu file konfigurasi, lalu nilai bawaan. Kredensial sengaja
// tidak ada di sini; keduanya hanya dibaca dari environment.
type config struct {
	Addr       string `json:"addr"`
	Data       string `json:"data"`
	Region     string `json:"region"`
	Domain     string `json:"domain"`
	TLSCert    string `json:"tls_cert"`
	TLSKey     string `json:"tls_key"`
	MaxBuckets int    `json:"max_buckets"`
	// LifecycleInterval adalah jeda antar putaran lifecycle, misalnya "1h";
	// "0" mematikan pekerja lifecycle.
	LifecycleInterval string `json:"lifecycle_interval"`

	lifecycleInterval time.Duration
}

func loadConfig(args []string) (config, error) {
	cfg := config{Addr: ":9000", Data: "./data", Region: "us-east-1", MaxBuckets: 1000, LifecycleInterval: "1h"}
	flags := cfg

	fs := flag.NewFlagSet("objstore", flag.ContinueOnError)
	path := fs.String("config", "", "file konfigurasi JSON")
	fs.StringVar(&flags.Addr, "addr", cfg.Addr, "alamat listen")
	fs.StringVar(&flags.Data, "data", cfg.Data, "folder penyimpanan data")
	fs.StringVar(&flags.Region, "region", cfg.Region, "region yang dilaporkan ke klien")
	fs.StringVar(&flags.Domain, "domain", "", "domain dasar untuk virtual-hosted-style (bucket.domain)")
	fs.StringVar(&flags.TLSCert, "tls-cert", "", "file sertifikat TLS (PEM); mengaktifkan HTTPS bersama --tls-key")
	fs.StringVar(&flags.TLSKey, "tls-key", "", "file kunci privat TLS (PEM)")
	fs.IntVar(&flags.MaxBuckets, "max-buckets", cfg.MaxBuckets, "jumlah bucket maksimum; 0 berarti tanpa batas")
	fs.StringVar(&flags.LifecycleInterval, "lifecycle-interval", cfg.LifecycleInterval, "jeda antar putaran lifecycle; 0 mematikannya")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if *path != "" {
		f, err := os.Open(*path)
		if err != nil {
			return cfg, err
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		dec.DisallowUnknownFields() // salah ketik nama pengaturan harus ketahuan
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("file konfigurasi %s: %w", *path, err)
		}
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = flags.Addr
		case "data":
			cfg.Data = flags.Data
		case "region":
			cfg.Region = flags.Region
		case "domain":
			cfg.Domain = flags.Domain
		case "tls-cert":
			cfg.TLSCert = flags.TLSCert
		case "tls-key":
			cfg.TLSKey = flags.TLSKey
		case "max-buckets":
			cfg.MaxBuckets = flags.MaxBuckets
		case "lifecycle-interval":
			cfg.LifecycleInterval = flags.LifecycleInterval
		}
	})
	interval, err := time.ParseDuration(cfg.LifecycleInterval)
	if cfg.LifecycleInterval == "0" {
		interval, err = 0, nil
	}
	if err != nil || interval < 0 {
		return cfg, fmt.Errorf("lifecycle_interval tidak valid: %q", cfg.LifecycleInterval)
	}
	cfg.lifecycleInterval = interval
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return cfg, errors.New("tls_cert dan tls_key harus diisi bersamaan")
	}
	return cfg, nil
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			args = args[1:]
		case "token", "bucket", "temp-credentials", "whoami":
			os.Exit(runCLI(args, os.Stdout, os.Stderr))
		}
	}
	serve(args)
}

// serve menjalankan server sampai dihentikan.
func serve(args []string) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := loadConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		logger.Error("konfigurasi tidak valid", "err", err)
		os.Exit(2)
	}

	accessKey, secretKey := os.Getenv("OBJSTORE_ACCESS_KEY"), os.Getenv("OBJSTORE_SECRET_KEY")
	if accessKey == "" || secretKey == "" {
		logger.Error("OBJSTORE_ACCESS_KEY dan OBJSTORE_SECRET_KEY wajib diisi")
		os.Exit(2)
	}

	store, err := storage.Open(cfg.Data)
	if err != nil {
		logger.Error("gagal membuka data directory", "dir", cfg.Data, "err", err)
		os.Exit(1)
	}
	defer store.Close()
	store.MaxBuckets = cfg.MaxBuckets

	masterKey, err := auth.LoadMasterKey(cfg.Data)
	if err != nil {
		logger.Error("gagal memuat master key", "err", err)
		store.Close()
		os.Exit(1)
	}
	tokens, err := auth.NewManager(store, masterKey, accessKey, secretKey)
	if err != nil {
		logger.Error("gagal menyiapkan pengelola token", "err", err)
		store.Close()
		os.Exit(1)
	}

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: &s3api.Server{
			Store:  store,
			Auth:   &sigv4.Verifier{Keys: tokens},
			Tokens: tokens,
			Region: cfg.Region,
			Logger: logger,
			Domain: cfg.Domain,
		},
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.lifecycleInterval > 0 {
		worker := &lifecycle.Worker{Store: store, Logger: logger}
		go worker.Run(ctx, cfg.lifecycleInterval)
	}
	go func() {
		<-ctx.Done()
		logger.Info("menghentikan server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	tls := cfg.TLSCert != ""
	logger.Info("server berjalan", "addr", cfg.Addr, "data", cfg.Data, "region", cfg.Region, "domain", cfg.Domain, "tls", tls)
	if tls {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server berhenti", "err", err)
		store.Close()
		os.Exit(1)
	}
}
