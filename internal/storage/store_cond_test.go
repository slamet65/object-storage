package storage

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var errCond = errors.New("syarat tidak terpenuhi")

func TestPutCheck(t *testing.T) {
	s := open(t)
	onlyIfAbsent := func(existing *ObjectInfo) error {
		if existing != nil {
			return errCond
		}
		return nil
	}
	if _, err := s.PutObject("b", "k", strings.NewReader("v1"), PutInput{Check: onlyIfAbsent}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutObject("b", "k", strings.NewReader("v2"), PutInput{Check: onlyIfAbsent}); !errors.Is(err, errCond) {
		t.Fatalf("err = %v", err)
	}
	// Penulisan yang ditolak tidak boleh mengubah object atau meninggalkan blob.
	got, _ := s.GetObject("b", "k")
	if got.Size != 2 || countBlobs(t, s) != 1 {
		t.Fatalf("object berubah: %+v, blob = %d", got, countBlobs(t, s))
	}

	// Syarat yang baru gagal di dalam transaksi (object muncul selagi body
	// diterima) juga harus membatalkan penulisan dan membuang blob-nya.
	calls := 0
	racy := func(existing *ObjectInfo) error {
		if calls++; calls == 1 {
			put(t, s, "baru", "pesaing")
			return nil
		}
		return onlyIfAbsent(existing)
	}
	if _, err := s.PutObject("b", "baru", strings.NewReader("kalah"), PutInput{Check: racy}); !errors.Is(err, errCond) {
		t.Fatalf("err = %v", err)
	}
	got, _ = s.GetObject("b", "baru")
	if got.Size != int64(len("pesaing")) || countBlobs(t, s) != 2 {
		t.Fatalf("object pesaing tertimpa: %+v, blob = %d", got, countBlobs(t, s))
	}
}

func TestMaxBuckets(t *testing.T) {
	s := open(t) // sudah berisi bucket "b"
	s.MaxBuckets = 2
	if err := s.CreateBucket("c"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBucket("d"); !errors.Is(err, ErrTooManyBuckets) {
		t.Fatalf("err = %v", err)
	}
	if err := s.CreateBucket("c"); !errors.Is(err, ErrBucketExists) {
		t.Fatalf("err = %v", err)
	}
}

// Blob yang masih dibuka pembaca tidak bisa dihapus di Windows. Blob itu
// harus hilang setelah pembaca selesai dan penghapusan dicoba lagi.
func TestDeleteWhileReading(t *testing.T) {
	s := open(t)
	info := put(t, s, "k", "isi object")
	rc := s.OpenRange(info, 0, info.Size)
	if _, err := rc.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteObject("b", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetObject("b", "k"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("err = %v", err)
	}
	rc.Close()
	s.retryPending()
	if n := countBlobs(t, s); n != 0 {
		t.Fatalf("blob tersisa %d", n)
	}
	if len(s.pending) != 0 {
		t.Fatalf("antrean hapus belum kosong: %v", s.pending)
	}
}

func TestListUploads(t *testing.T) {
	s := open(t)
	type entry struct{ key, id string }
	var all []entry
	for _, k := range []string{"a", "a", "dir/x", "dir/y", "z"} {
		u, err := s.CreateUpload("b", k, Meta{})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, entry{k, u.ID})
	}

	collect := func(prefix, delim string, page int) (got []entry, cps []string) {
		km, im := "", ""
		for i := 0; i < 100; i++ {
			res, err := s.ListUploads("b", prefix, delim, km, im, page)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Uploads)+len(res.CommonPrefixes) > page {
				t.Fatalf("halaman melebihi %d", page)
			}
			for _, u := range res.Uploads {
				got = append(got, entry{u.Key, u.ID})
			}
			cps = append(cps, res.CommonPrefixes...)
			if !res.IsTruncated {
				return
			}
			km, im = res.NextKeyMarker, res.NextUploadIDMarker
		}
		t.Fatal("pagination tidak berhenti")
		return
	}
	keys := func(es []entry) (out []string) {
		for _, e := range es {
			out = append(out, e.key)
		}
		return
	}

	for _, page := range []int{1, 2, 1000} {
		got, _ := collect("", "", page)
		if !reflect.DeepEqual(keys(got), []string{"a", "a", "dir/x", "dir/y", "z"}) {
			t.Errorf("page=%d: %v", page, keys(got))
		}
		ids := map[string]bool{}
		for _, e := range got {
			ids[e.id] = true
		}
		if len(ids) != len(all) {
			t.Errorf("page=%d: ada upload yang hilang atau ganda", page)
		}

		got, cps := collect("", "/", page)
		if !reflect.DeepEqual(keys(got), []string{"a", "a", "z"}) || !reflect.DeepEqual(cps, []string{"dir/"}) {
			t.Errorf("page=%d delim: %v %v", page, keys(got), cps)
		}
		got, _ = collect("dir/", "", page)
		if !reflect.DeepEqual(keys(got), []string{"dir/x", "dir/y"}) {
			t.Errorf("page=%d prefix: %v", page, keys(got))
		}
	}

	// key-marker tanpa upload-id-marker melewati semua upload milik key itu.
	res, _ := s.ListUploads("b", "", "", "a", "", 10)
	if got := fmt.Sprint(len(res.Uploads)); got != "3" {
		t.Fatalf("setelah key-marker a: %s upload", got)
	}
}

func TestCompositeChecksum(t *testing.T) {
	s := open(t)
	sum := func(v string) func() *Checksum {
		return func() *Checksum { return &Checksum{Algo: "crc32", Value: v} }
	}
	u, _ := s.CreateUpload("b", "k", Meta{})
	p1, _ := s.PutPart("b", "k", u.ID, 1, strings.NewReader("hello"), sum("NhCmhg=="))
	p2, _ := s.PutPart("b", "k", u.ID, 2, strings.NewReader(" world"), sum("xrdBwA=="))
	_ = p2
	// Part kecil hanya boleh di akhir, jadi selesaikan dengan satu part saja
	// lalu periksa bentuk checksum gabungannya.
	info, err := s.CompleteUpload("b", "k", u.ID, []CompletedPart{{1, p1.ETag}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Checksum == nil || info.Checksum.Type != ChecksumComposite || !strings.HasSuffix(info.Checksum.Value, "-1") {
		t.Fatalf("checksum = %+v", info.Checksum)
	}

	// Part tanpa checksum: object tidak punya checksum.
	u, _ = s.CreateUpload("b", "k2", Meta{})
	p, _ := s.PutPart("b", "k2", u.ID, 1, strings.NewReader("x"), nil)
	info, _ = s.CompleteUpload("b", "k2", u.ID, []CompletedPart{{1, p.ETag}}, nil)
	if info.Checksum != nil {
		t.Fatalf("checksum = %+v", info.Checksum)
	}
}
