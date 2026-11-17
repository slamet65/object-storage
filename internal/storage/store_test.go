package storage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.CreateBucket("b"); err != nil {
		t.Fatal(err)
	}
	return s
}

func put(t *testing.T, s *Store, key, data string) ObjectInfo {
	t.Helper()
	info, err := s.PutObject("b", key, strings.NewReader(data), PutInput{})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func countBlobs(t *testing.T, s *Store) int {
	t.Helper()
	n := 0
	filepath.WalkDir(filepath.Join(s.dir, "blobs"), func(_ string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func TestObjectRoundTrip(t *testing.T) {
	s := open(t)
	info := put(t, s, "a/b.txt", "hello world")
	if info.ETag != "5eb63bbbe01eeed093cb22bb8f5acdc3" || info.Size != 11 {
		t.Fatalf("info salah: %+v", info)
	}
	got, err := s.GetObject("b", "a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	rc := s.OpenRange(got, 6, 5)
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != "world" {
		t.Fatalf("range = %q", data)
	}

	put(t, s, "a/b.txt", "v2") // menimpa: blob lama harus hilang
	if n := countBlobs(t, s); n != 1 {
		t.Fatalf("blob tersisa %d, mau 1", n)
	}
	if err := s.DeleteObject("b", "a/b.txt"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteObject("b", "a/b.txt"); err != nil {
		t.Fatal("hapus kedua harus idempoten:", err)
	}
	if _, err := s.GetObject("b", "a/b.txt"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("err = %v", err)
	}
	if n := countBlobs(t, s); n != 0 {
		t.Fatalf("blob tersisa %d, mau 0", n)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("gagal") }

func TestPutFailureLeavesNothing(t *testing.T) {
	s := open(t)
	r := io.MultiReader(strings.NewReader("sebagian"), failReader{})
	if _, err := s.PutObject("b", "k", r, PutInput{}); err == nil {
		t.Fatal("harus error")
	}
	if _, err := s.GetObject("b", "k"); !errors.Is(err, ErrNoSuchKey) {
		t.Fatalf("err = %v", err)
	}
	if n := countBlobs(t, s); n != 0 {
		t.Fatalf("blob tersisa %d", n)
	}
}

func TestBuckets(t *testing.T) {
	s := open(t)
	if err := s.CreateBucket("b"); !errors.Is(err, ErrBucketExists) {
		t.Fatalf("err = %v", err)
	}
	put(t, s, "k", "x")
	if err := s.DeleteBucket("b"); !errors.Is(err, ErrBucketNotEmpty) {
		t.Fatalf("err = %v", err)
	}
	s.DeleteObject("b", "k")
	if err := s.DeleteBucket("b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutObject("b", "k", strings.NewReader("x"), PutInput{}); !errors.Is(err, ErrNoSuchBucket) {
		t.Fatalf("err = %v", err)
	}
}

func TestList(t *testing.T) {
	s := open(t)
	for _, k := range []string{"a", "a/1", "a/2", "b/1", "b/x/2", "c", "foto/2024/a.jpg", "foto/2025/b.jpg", "foto/c.jpg"} {
		put(t, s, k, "x")
	}

	// Kumpulkan semua halaman dan pastikan hasilnya sama berapa pun ukuran halamannya.
	collect := func(prefix, delim string, page int) (keys, cps []string) {
		marker := ""
		for i := 0; i < 100; i++ {
			res, err := s.List("b", prefix, delim, marker, page)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Objects)+len(res.CommonPrefixes) > page {
				t.Fatalf("halaman melebihi %d", page)
			}
			for _, o := range res.Objects {
				keys = append(keys, o.Key)
			}
			cps = append(cps, res.CommonPrefixes...)
			if !res.IsTruncated {
				return
			}
			marker = res.NextMarker
		}
		t.Fatal("pagination tidak berhenti")
		return
	}

	cases := []struct {
		prefix, delim string
		keys, cps     []string
	}{
		{"", "", []string{"a", "a/1", "a/2", "b/1", "b/x/2", "c", "foto/2024/a.jpg", "foto/2025/b.jpg", "foto/c.jpg"}, nil},
		{"", "/", []string{"a", "c"}, []string{"a/", "b/", "foto/"}},
		{"foto/", "/", []string{"foto/c.jpg"}, []string{"foto/2024/", "foto/2025/"}},
		{"b/", "", []string{"b/1", "b/x/2"}, nil},
		{"zzz", "/", nil, nil},
	}
	for _, c := range cases {
		for _, page := range []int{1, 2, 1000} {
			keys, cps := collect(c.prefix, c.delim, page)
			if !reflect.DeepEqual(keys, c.keys) || !reflect.DeepEqual(cps, c.cps) {
				t.Errorf("prefix=%q delim=%q page=%d: keys=%v cps=%v", c.prefix, c.delim, page, keys, cps)
			}
		}
	}
}

func TestMultipart(t *testing.T) {
	s := open(t)
	u, err := s.CreateUpload("b", "big", Meta{ContentType: "video/mp4"})
	if err != nil {
		t.Fatal(err)
	}
	p1data := bytes.Repeat([]byte("a"), MinPartSize)
	p1, err := s.PutPart("b", "big", u.ID, 1, bytes.NewReader(p1data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPart("b", "big", u.ID, 2, strings.NewReader("buang"), nil); err != nil {
		t.Fatal(err)
	}
	p2, _ := s.PutPart("b", "big", u.ID, 2, strings.NewReader("ekor"), nil) // menimpa part 2
	s.PutPart("b", "big", u.ID, 3, strings.NewReader("tidak dipakai"), nil)

	if _, err := s.PutPart("b", "big", "salah", 1, strings.NewReader("x"), nil); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.CompleteUpload("b", "big", u.ID, []CompletedPart{{2, p2.ETag}, {1, p1.ETag}}, nil); !errors.Is(err, ErrInvalidPartOrder) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.CompleteUpload("b", "big", u.ID, []CompletedPart{{1, "salah"}}, nil); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.CompleteUpload("b", "big", u.ID, []CompletedPart{{1, p1.ETag}, {3, "x"}}, nil); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("err = %v", err)
	}

	info, err := s.CompleteUpload("b", "big", u.ID, []CompletedPart{{1, p1.ETag}, {2, p2.ETag}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(info.ETag, "-2") || info.Size != MinPartSize+4 || info.ContentType != "video/mp4" {
		t.Fatalf("info salah: %+v", info)
	}
	// Baca melintasi batas segment.
	rc := s.OpenRange(info, MinPartSize-2, 6)
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != "aaekor" {
		t.Fatalf("range = %q", data)
	}
	if n := countBlobs(t, s); n != 2 {
		t.Fatalf("blob tersisa %d, mau 2", n)
	}
	if _, err := s.CompleteUpload("b", "big", u.ID, []CompletedPart{{1, p1.ETag}}, nil); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("err = %v", err)
	}

	// Abort membuang semua part.
	u2, _ := s.CreateUpload("b", "lain", Meta{})
	s.PutPart("b", "lain", u2.ID, 1, strings.NewReader("x"), nil)
	if err := s.AbortUpload("b", "lain", u2.ID); err != nil {
		t.Fatal(err)
	}
	if n := countBlobs(t, s); n != 2 {
		t.Fatalf("blob tersisa %d, mau 2", n)
	}
}

func TestSweepRemovesOrphans(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.CreateBucket("b")
	put(t, s, "simpan", "x")
	if _, _, _, err := s.writeBlob(strings.NewReader("yatim")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := countBlobs(t, s); n != 1 {
		t.Fatalf("blob tersisa %d, mau 1", n)
	}
	if _, err := s.GetObject("b", "simpan"); err != nil {
		t.Fatal(fmt.Errorf("object hilang: %w", err))
	}
}
