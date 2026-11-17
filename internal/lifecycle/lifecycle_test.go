package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"object-storage/internal/storage"
)

type fixture struct {
	t     *testing.T
	store *storage.Store
	w     *Worker
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	f := &fixture{t: t, store: store, now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return f.now }
	store.Now = clock
	f.w = &Worker{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock}
	if err := store.CreateBucket("b"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) put(keys ...string) {
	f.t.Helper()
	for _, k := range keys {
		if _, err := f.store.PutObject("b", k, strings.NewReader("x"), storage.PutInput{}); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) rules(rules ...storage.LifecycleRule) {
	f.t.Helper()
	_, err := f.store.UpdateBucket("b", func(b *storage.BucketInfo) error { b.Lifecycle = rules; return nil })
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) run() Stats {
	f.t.Helper()
	stats, err := f.w.RunOnce(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return stats
}

func (f *fixture) keys() string {
	f.t.Helper()
	res, err := f.store.List("b", "", "", "", 10000)
	if err != nil {
		f.t.Fatal(err)
	}
	var keys []string
	for _, o := range res.Objects {
		keys = append(keys, o.Key)
	}
	return strings.Join(keys, ",")
}

func (f *fixture) exists(key string) bool {
	_, err := f.store.GetObject("b", key)
	return !errors.Is(err, storage.ErrNoSuchKey)
}

func TestExpiration(t *testing.T) {
	f := newFixture(t)
	f.put("log/lama", "simpan/lama")
	f.rules(storage.LifecycleRule{ID: "log", Enabled: true, Prefix: "log/", ExpireDays: 7})

	f.now = f.now.Add(7*day - time.Second)
	f.put("log/baru")
	if stats := f.run(); stats != (Stats{}) {
		t.Fatalf("sebelum jatuh tempo: %+v", stats)
	}
	f.now = f.now.Add(time.Second)
	if stats := f.run(); stats.Expired != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := f.keys(); got != "log/baru,simpan/lama" {
		t.Fatalf("tersisa: %s", got)
	}
	// Putaran kedua tidak melakukan apa-apa.
	if stats := f.run(); stats != (Stats{}) {
		t.Fatalf("putaran ulang: %+v", stats)
	}

	// Aturan nonaktif diabaikan; aturan bertanggal berlaku mulai tanggalnya.
	date := f.now.Add(day)
	f.rules(
		storage.LifecycleRule{ID: "mati", Enabled: false, ExpireDays: 1},
		storage.LifecycleRule{ID: "tgl", Enabled: true, Prefix: "simpan/", ExpireDate: &date},
	)
	f.now = f.now.Add(30 * day)
	if stats := f.run(); stats.Expired != 1 || f.exists("simpan/lama") || !f.exists("log/baru") {
		t.Fatalf("stats = %+v, tersisa %s", stats, f.keys())
	}
}

func TestExpirationManyObjects(t *testing.T) {
	f := newFixture(t)
	var keys []string
	for i := 0; i < pageSize+250; i++ {
		keys = append(keys, fmt.Sprintf("k%05d", i))
	}
	f.put(keys...)
	f.rules(storage.LifecycleRule{ID: "semua", Enabled: true, ExpireDays: 1})
	f.now = f.now.Add(day)
	if stats := f.run(); stats.Expired != len(keys) || f.keys() != "" {
		t.Fatalf("dihapus %d dari %d", stats.Expired, len(keys))
	}
}

func TestExpirationRespectsLock(t *testing.T) {
	f := newFixture(t)
	f.put("arsip/a", "lain/b")
	f.store.UpdateBucket("b", func(b *storage.BucketInfo) error {
		b.Locks = []storage.LockRule{{ID: "l", Enabled: true, Prefix: "arsip/", Mode: storage.LockAge, Days: 30}}
		b.Lifecycle = []storage.LifecycleRule{{ID: "e", Enabled: true, ExpireDays: 7}}
		return nil
	})
	f.now = f.now.Add(8 * day)
	if stats := f.run(); stats.Expired != 1 || stats.Locked != 1 || !f.exists("arsip/a") {
		t.Fatalf("stats = %+v, tersisa %s", stats, f.keys())
	}
	// Begitu retensi habis, lifecycle menghapusnya.
	f.now = f.now.Add(22 * day)
	if stats := f.run(); stats.Expired != 1 || f.exists("arsip/a") {
		t.Fatalf("setelah retensi: %+v", stats)
	}
}

func TestTransition(t *testing.T) {
	f := newFixture(t)
	f.put("a", "b")
	f.rules(storage.LifecycleRule{ID: "ia", Enabled: true, TransitionDays: 30, TransitionClass: storage.ClassIA})
	f.now = f.now.Add(30 * day)
	f.put("baru")
	if stats := f.run(); stats.Transitioned != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	for key, want := range map[string]string{"a": storage.ClassIA, "b": storage.ClassIA, "baru": ""} {
		if o, _ := f.store.GetObject("b", key); o.StorageClass != want {
			t.Errorf("%s: class %q", key, o.StorageClass)
		}
	}
	// Object yang sudah dipindah tidak dihitung lagi.
	if stats := f.run(); stats != (Stats{}) {
		t.Fatalf("putaran ulang: %+v", stats)
	}
}

func TestAbortUploads(t *testing.T) {
	f := newFixture(t)
	old, _ := f.store.CreateUpload("b", "tmp/lama", storage.Meta{})
	f.store.PutPart("b", "tmp/lama", old.ID, 1, strings.NewReader("part"), nil)
	keep, _ := f.store.CreateUpload("b", "lain/lama", storage.Meta{})
	f.rules(storage.LifecycleRule{ID: "abort", Enabled: true, Prefix: "tmp/", AbortUploadDays: 3})

	f.now = f.now.Add(3 * day)
	fresh, _ := f.store.CreateUpload("b", "tmp/baru", storage.Meta{})
	if stats := f.run(); stats.Aborted != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if _, _, err := f.store.ListParts("b", "tmp/lama", old.ID); !errors.Is(err, storage.ErrNoSuchUpload) {
		t.Fatalf("upload lama masih ada: %v", err)
	}
	for key, id := range map[string]string{"lain/lama": keep.ID, "tmp/baru": fresh.ID} {
		if _, _, err := f.store.ListParts("b", key, id); err != nil {
			t.Errorf("upload %s ikut dibatalkan: %v", key, err)
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.w.Run(ctx, time.Hour)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run tidak berhenti setelah dibatalkan")
	}
}
