package storage

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// clock adalah jam yang bisa dimajukan untuk test.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func openWithClock(t *testing.T) (*Store, *clock) {
	s := open(t)
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s.Now = c.now
	return s, c
}

func setLocks(t *testing.T, s *Store, rules ...LockRule) {
	t.Helper()
	if _, err := s.UpdateBucket("b", func(b *BucketInfo) error { b.Locks = rules; return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestBucketLock(t *testing.T) {
	s, c := openWithClock(t)
	put(t, s, "arsip/a", "v1")
	put(t, s, "bebas/b", "v1")
	setLocks(t, s, LockRule{ID: "r", Enabled: true, Prefix: "arsip/", Mode: LockAge, Days: 30})

	if err := s.DeleteObject("b", "arsip/a"); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("hapus: %v", err)
	}
	if _, err := s.PutObject("b", "arsip/a", strings.NewReader("v2"), PutInput{}); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("timpa: %v", err)
	}
	// Penimpaan lewat multipart juga ditolak.
	u, _ := s.CreateUpload("b", "arsip/a", Meta{})
	p, _ := s.PutPart("b", "arsip/a", u.ID, 1, strings.NewReader("mp"), nil)
	if _, err := s.CompleteUpload("b", "arsip/a", u.ID, []CompletedPart{{1, p.ETag}}, nil); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("complete: %v", err)
	}
	if got, _ := s.GetObject("b", "arsip/a"); got.Size != 2 {
		t.Fatalf("object terkunci berubah: %+v", got)
	}
	// Penolakan tidak boleh meninggalkan blob: object a, object b, dan part multipart.
	if n := countBlobs(t, s); n != 3 {
		t.Fatalf("blob = %d, mau 3", n)
	}

	// Object baru di bawah prefix boleh ditulis; di luar prefix bebas.
	put(t, s, "arsip/baru", "x")
	if err := s.DeleteObject("b", "bebas/b"); err != nil {
		t.Fatal(err)
	}

	// Setelah masa retensi lewat, boleh dihapus.
	c.advance(30*24*time.Hour - time.Second)
	if err := s.DeleteObject("b", "arsip/a"); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("sedetik sebelum habis: %v", err)
	}
	c.advance(time.Second)
	if err := s.DeleteObject("b", "arsip/a"); err != nil {
		t.Fatalf("setelah retensi: %v", err)
	}

	// Mode tanggal dan tanpa batas; aturan nonaktif diabaikan.
	until := c.now().Add(time.Hour)
	setLocks(t, s,
		LockRule{ID: "tgl", Enabled: true, Prefix: "tgl/", Mode: LockDate, Until: &until},
		LockRule{ID: "selamanya", Enabled: true, Prefix: "abadi/", Mode: LockIndefinite},
		LockRule{ID: "mati", Enabled: false, Prefix: "", Mode: LockIndefinite},
	)
	put(t, s, "tgl/x", "x")
	put(t, s, "abadi/x", "x")
	put(t, s, "lain/x", "x")
	if err := s.DeleteObject("b", "lain/x"); err != nil {
		t.Fatalf("aturan nonaktif ikut berlaku: %v", err)
	}
	c.advance(2 * time.Hour)
	if err := s.DeleteObject("b", "tgl/x"); err != nil {
		t.Fatalf("setelah tanggal: %v", err)
	}
	c.advance(10000 * 24 * time.Hour)
	if err := s.DeleteObject("b", "abadi/x"); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("lock tanpa batas: %v", err)
	}
	// Mencabut aturan membuka kunci.
	setLocks(t, s)
	if err := s.DeleteObject("b", "abadi/x"); err != nil {
		t.Fatal(err)
	}
}

func TestBucketDomains(t *testing.T) {
	s := open(t)
	s.CreateBucket("c")
	set := func(bucket string, domains ...string) error {
		_, err := s.UpdateBucket(bucket, func(b *BucketInfo) error { b.Domains = domains; return nil })
		return err
	}
	if err := set("b", "cdn.contoh.test", "img.contoh.test"); err != nil {
		t.Fatal(err)
	}
	if name, ok := s.BucketForDomain("cdn.contoh.test"); !ok || name != "b" {
		t.Fatalf("domain -> %q %v", name, ok)
	}
	if err := set("c", "img.contoh.test"); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("err = %v", err)
	}
	// Perubahan yang ditolak tidak boleh tersimpan sebagian.
	if info, _ := s.HeadBucket("c"); len(info.Domains) != 0 {
		t.Fatalf("domain bucket c = %v", info.Domains)
	}
	// Domain yang dilepas bisa dipakai bucket lain.
	if err := set("b", "cdn.contoh.test"); err != nil {
		t.Fatal(err)
	}
	if err := set("c", "img.contoh.test"); err != nil {
		t.Fatal(err)
	}
	// Menghapus bucket melepas domainnya.
	if err := s.DeleteBucket("c"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.BucketForDomain("img.contoh.test"); ok {
		t.Fatal("domain bucket yang dihapus masih terpetakan")
	}
	if _, err := s.UpdateBucket("tidak-ada", func(*BucketInfo) error { return nil }); !errors.Is(err, ErrNoSuchBucket) {
		t.Fatalf("err = %v", err)
	}
}

func TestSetStorageClass(t *testing.T) {
	s := open(t)
	info := put(t, s, "k", "x")
	if err := s.SetStorageClass("b", "k", "etag-lain", ClassIA); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetObject("b", "k"); got.StorageClass != "" {
		t.Fatal("class berubah walau ETag tidak cocok")
	}
	if err := s.SetStorageClass("b", "k", info.ETag, ClassIA); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetObject("b", "k")
	if got.StorageClass != ClassIA || got.Size != 1 || !got.ModTime.Equal(info.ModTime) {
		t.Fatalf("object = %+v", got)
	}
	if err := s.SetStorageClass("b", "tidak-ada", "x", ClassIA); err != nil {
		t.Fatal(err)
	}
}
