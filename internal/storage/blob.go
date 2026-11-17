package storage

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (s *Store) blobPath(id string) string {
	return filepath.Join(s.dir, "blobs", id[:2], id[2:4], id)
}

// writeBlob menyalin r ke file blob baru secara atomik (tmp, fsync, rename)
// dan mengembalikan id, ukuran, serta MD5 isinya.
func (s *Store) writeBlob(r io.Reader) (id string, size int64, sum []byte, err error) {
	id = newID()
	tmp := filepath.Join(s.dir, "tmp", id)
	f, err := os.Create(tmp)
	if err != nil {
		return "", 0, nil, err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()

	h := md5.New()
	if size, err = io.Copy(io.MultiWriter(f, h), r); err != nil {
		return "", 0, nil, err
	}
	if err = f.Sync(); err != nil {
		return "", 0, nil, err
	}
	if err = f.Close(); err != nil {
		return "", 0, nil, err
	}
	dst := s.blobPath(id)
	if err = os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", 0, nil, err
	}
	if err = os.Rename(tmp, dst); err != nil {
		return "", 0, nil, err
	}
	return id, size, h.Sum(nil), nil
}

// removeBlobs menghapus blob sebisanya. Yang gagal dihapus (misalnya file
// masih dibuka pembaca lain di Windows) dicatat dan dicoba lagi secara berkala.
func (s *Store) removeBlobs(ids ...string) {
	for _, id := range ids {
		if id == "" {
			continue
		}
		if err := os.Remove(s.blobPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.mu.Lock()
			s.pending[id] = struct{}{}
			s.mu.Unlock()
		}
	}
}

// retryPending mencoba lagi menghapus blob yang sebelumnya gagal dihapus.
func (s *Store) retryPending() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.pending))
	for id := range s.pending {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		if err := os.Remove(s.blobPath(id)); err == nil || errors.Is(err, fs.ErrNotExist) {
			s.mu.Lock()
			delete(s.pending, id)
			s.mu.Unlock()
		}
	}
}

// sweep menghapus file tmp dan blob yang tidak dirujuk metadata mana pun,
// yaitu sisa dari crash atau penghapusan yang gagal.
func (s *Store) sweep() error {
	live, err := s.liveBlobs()
	if err != nil {
		return err
	}
	entries, _ := os.ReadDir(filepath.Join(s.dir, "tmp"))
	for _, e := range entries {
		os.Remove(filepath.Join(s.dir, "tmp", e.Name()))
	}
	return filepath.WalkDir(filepath.Join(s.dir, "blobs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if _, ok := live[d.Name()]; !ok {
			os.Remove(p)
		}
		return nil
	})
}

// segmentReader membaca rentang byte yang melintasi beberapa segment.
type segmentReader struct {
	s      *Store
	segs   []Segment
	skip   int64 // byte yang masih harus dilewati sebelum mulai membaca
	remain int64
	cur    *os.File
}

// OpenRange membuka length byte isi object mulai dari offset off.
func (s *Store) OpenRange(info ObjectInfo, off, length int64) io.ReadCloser {
	return &segmentReader{s: s, segs: info.Segments, skip: off, remain: length}
}

func (r *segmentReader) Read(p []byte) (int, error) {
	for {
		if r.remain <= 0 {
			return 0, io.EOF
		}
		if r.cur == nil {
			if len(r.segs) == 0 {
				return 0, io.ErrUnexpectedEOF
			}
			seg := r.segs[0]
			r.segs = r.segs[1:]
			if r.skip >= seg.Size {
				r.skip -= seg.Size
				continue
			}
			f, err := os.Open(r.s.blobPath(seg.Blob))
			if err != nil {
				return 0, err
			}
			if r.skip > 0 {
				if _, err := f.Seek(r.skip, io.SeekStart); err != nil {
					f.Close()
					return 0, err
				}
				r.skip = 0
			}
			r.cur = f
		}
		if int64(len(p)) > r.remain {
			p = p[:r.remain]
		}
		n, err := r.cur.Read(p)
		r.remain -= int64(n)
		if err == io.EOF || (err == nil && r.remain == 0) {
			// Tutup segera supaya blob bisa dihapus begitu selesai dibaca.
			r.cur.Close()
			r.cur = nil
			err = nil
		}
		if n > 0 || err != nil {
			return n, err
		}
	}
}

func (r *segmentReader) Close() error {
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		return err
	}
	return nil
}
