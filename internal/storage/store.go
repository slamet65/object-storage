package storage

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketsBucket = []byte("buckets")

func objBucket(name string) []byte     { return []byte("obj:" + name) }
func uploadsBucket(name string) []byte { return []byte("uploads:" + name) }
func partsBucket(name string) []byte   { return []byte("parts:" + name) }

type Store struct {
	// MaxBuckets membatasi jumlah bucket; 0 berarti tanpa batas.
	MaxBuckets int
	// Now menggantikan jam sistem (untuk test); nil berarti time.Now.
	Now func() time.Time

	db  *bolt.DB
	dir string

	mu      sync.Mutex
	pending map[string]struct{} // blob yang gagal dihapus dan akan dicoba lagi
	stop    chan struct{}
	done    chan struct{}
	closed  sync.Once
}

// Open membuka (atau membuat) data directory dan membersihkan blob yatim.
func Open(dir string) (*Store, error) {
	for _, d := range []string{"blobs", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	db, err := bolt.Open(filepath.Join(dir, "meta.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dir: dir, pending: map[string]struct{}{}, stop: make(chan struct{}), done: make(chan struct{})}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketsBucket)
		return err
	})
	if err == nil {
		err = s.sweep()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	go s.retryLoop()
	return s, nil
}

// Close aman dipanggil lebih dari sekali.
func (s *Store) Close() error {
	var err error
	s.closed.Do(func() {
		close(s.stop)
		<-s.done
		err = s.db.Close()
	})
	return err
}

// retryLoop secara berkala mencoba lagi menghapus blob yang sebelumnya gagal
// dihapus, misalnya karena masih dibuka pembaca lain di Windows.
func (s *Store) retryLoop() {
	defer close(s.done)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.retryPending()
		}
	}
}

func (s *Store) now() time.Time {
	t := time.Now()
	if s.Now != nil {
		t = s.Now()
	}
	return t.UTC().Truncate(time.Millisecond)
}

// liveBlobs mengumpulkan semua id blob yang masih dirujuk object atau part.
func (s *Store) liveBlobs() (map[string]struct{}, error) {
	live := map[string]struct{}{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			switch {
			case bytes.HasPrefix(name, []byte("obj:")):
				return b.ForEach(func(_, v []byte) error {
					var o ObjectInfo
					if err := json.Unmarshal(v, &o); err != nil {
						return err
					}
					for _, seg := range o.Segments {
						live[seg.Blob] = struct{}{}
					}
					return nil
				})
			case bytes.HasPrefix(name, []byte("parts:")):
				return b.ForEach(func(_, v []byte) error {
					var p Part
					if err := json.Unmarshal(v, &p); err != nil {
						return err
					}
					live[p.Blob] = struct{}{}
					return nil
				})
			}
			return nil
		})
	})
	return live, err
}

// ---- Bucket ----

func (s *Store) CreateBucket(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketsBucket)
		if b.Get([]byte(name)) != nil {
			return ErrBucketExists
		}
		if s.MaxBuckets > 0 {
			n := 0
			c := b.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				n++
			}
			if n >= s.MaxBuckets {
				return ErrTooManyBuckets
			}
		}
		for _, n := range [][]byte{objBucket(name), uploadsBucket(name), partsBucket(name)} {
			if _, err := tx.CreateBucketIfNotExists(n); err != nil {
				return err
			}
		}
		v, _ := json.Marshal(BucketInfo{Name: name, Created: s.now()})
		return b.Put([]byte(name), v)
	})
}

func (s *Store) HeadBucket(name string) (BucketInfo, error) {
	var info BucketInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketsBucket).Get([]byte(name))
		if v == nil {
			return ErrNoSuchBucket
		}
		return json.Unmarshal(v, &info)
	})
	return info, err
}

func (s *Store) ListBuckets() ([]BucketInfo, error) {
	var out []BucketInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketsBucket).ForEach(func(_, v []byte) error {
			var info BucketInfo
			if err := json.Unmarshal(v, &info); err != nil {
				return err
			}
			out = append(out, info)
			return nil
		})
	})
	return out, err
}

// DeleteBucket menghapus bucket kosong. Multipart upload yang belum selesai
// ikut dibatalkan.
func (s *Store) DeleteBucket(name string) error {
	var garbage []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketsBucket)
		info, err := getBucket(tx, name)
		if err != nil {
			return err
		}
		if k, _ := tx.Bucket(objBucket(name)).Cursor().First(); k != nil {
			return ErrBucketNotEmpty
		}
		if idx := tx.Bucket(domainsBucket); idx != nil {
			for _, d := range info.Domains {
				if err := idx.Delete([]byte(d)); err != nil {
					return err
				}
			}
		}
		err = tx.Bucket(partsBucket(name)).ForEach(func(_, v []byte) error {
			var p Part
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			garbage = append(garbage, p.Blob)
			return nil
		})
		if err != nil {
			return err
		}
		for _, n := range [][]byte{objBucket(name), uploadsBucket(name), partsBucket(name)} {
			if err := tx.DeleteBucket(n); err != nil {
				return err
			}
		}
		return b.Delete([]byte(name))
	})
	if err == nil {
		s.removeBlobs(garbage...)
	}
	return err
}

// ---- Object ----

// PutObject menyimpan isi r sebagai object. Kalau r mengembalikan error
// (misalnya checksum tidak cocok), tidak ada yang tersimpan.
func (s *Store) PutObject(bucket, key string, r io.Reader, in PutInput) (ObjectInfo, error) {
	binfo, err := s.HeadBucket(bucket)
	if err != nil {
		return ObjectInfo{}, err
	}
	// Tolak lebih awal kalau key tujuan terkunci, sebelum body diterima.
	// Pemeriksaan yang menentukan tetap ada di commitObject.
	if len(binfo.Locks) > 0 {
		if cur, err := s.GetObject(bucket, key); err == nil && binfo.Locked(key, cur.ModTime, s.now()) {
			return ObjectInfo{}, ErrObjectLocked
		}
	}
	// Periksa lebih awal supaya body tidak perlu diterima kalau pasti gagal.
	if in.Check != nil {
		var existing *ObjectInfo
		if cur, err := s.GetObject(bucket, key); err == nil {
			existing = &cur
		} else if !errors.Is(err, ErrNoSuchKey) {
			return ObjectInfo{}, err
		}
		if err := in.Check(existing); err != nil {
			return ObjectInfo{}, err
		}
	}
	id, size, sum, err := s.writeBlob(r)
	if err != nil {
		return ObjectInfo{}, err
	}
	info := ObjectInfo{
		Key:      key,
		Size:     size,
		ETag:     hex.EncodeToString(sum),
		ModTime:  s.now(),
		Segments: []Segment{{Blob: id, Size: size}},
		Meta:     in.Meta,
	}
	if in.Checksum != nil {
		if info.Checksum = in.Checksum(); info.Checksum != nil {
			info.Checksum.Type = ChecksumFullObject
		}
	}
	if err := s.commitObject(bucket, &info, in.Check, nil); err != nil {
		s.removeBlobs(id)
		return ObjectInfo{}, err
	}
	return info, nil
}

// commitObject menulis metadata object dan menghapus blob versi lama.
// extra dijalankan di transaksi yang sama dan boleh melengkapi info
// sebelum ditulis.
//
// check (boleh nil) menerima object yang sekarang ada, atau nil, dan bisa
// membatalkan penulisan.
func (s *Store) commitObject(bucket string, info *ObjectInfo, check func(*ObjectInfo) error, extra func(tx *bolt.Tx) error) error {
	var garbage []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		garbage = garbage[:0]
		b := tx.Bucket(objBucket(bucket))
		if b == nil {
			return ErrNoSuchBucket
		}
		var existing *ObjectInfo
		if old := b.Get([]byte(info.Key)); old != nil {
			var o ObjectInfo
			if err := json.Unmarshal(old, &o); err != nil {
				return err
			}
			for _, seg := range o.Segments {
				garbage = append(garbage, seg.Blob)
			}
			existing = &o
			binfo, err := getBucket(tx, bucket)
			if err != nil {
				return err
			}
			if binfo.Locked(o.Key, o.ModTime, s.now()) {
				return ErrObjectLocked
			}
		}
		if check != nil {
			if err := check(existing); err != nil {
				return err
			}
		}
		if extra != nil {
			if err := extra(tx); err != nil {
				return err
			}
		}
		v, err := json.Marshal(info)
		if err != nil {
			return err
		}
		return b.Put([]byte(info.Key), v)
	})
	if err == nil {
		s.removeBlobs(garbage...)
	}
	return err
}

func (s *Store) GetObject(bucket, key string) (ObjectInfo, error) {
	var info ObjectInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(objBucket(bucket))
		if b == nil {
			return ErrNoSuchBucket
		}
		v := b.Get([]byte(key))
		if v == nil {
			return ErrNoSuchKey
		}
		return json.Unmarshal(v, &info)
	})
	return info, err
}

// DeleteObject bersifat idempoten: menghapus key yang tidak ada bukan error.
// Object yang masih dalam masa retensi bucket lock menghasilkan ErrObjectLocked.
func (s *Store) DeleteObject(bucket, key string) error {
	return s.DeleteObjectIf(bucket, key, nil)
}

// DeleteObjectIf menghapus object hanya kalau check (boleh nil) menerimanya.
// check dipanggil di dalam transaksi dengan object yang sekarang ada, dan
// tidak dipanggil kalau object tidak ada.
func (s *Store) DeleteObjectIf(bucket, key string, check func(ObjectInfo) error) error {
	var garbage []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		garbage = garbage[:0]
		b := tx.Bucket(objBucket(bucket))
		if b == nil {
			return ErrNoSuchBucket
		}
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		var o ObjectInfo
		if err := json.Unmarshal(v, &o); err != nil {
			return err
		}
		binfo, err := getBucket(tx, bucket)
		if err != nil {
			return err
		}
		if binfo.Locked(o.Key, o.ModTime, s.now()) {
			return ErrObjectLocked
		}
		if check != nil {
			if err := check(o); err != nil {
				return err
			}
		}
		for _, seg := range o.Segments {
			garbage = append(garbage, seg.Blob)
		}
		return b.Delete([]byte(key))
	})
	if err == nil {
		s.removeBlobs(garbage...)
	}
	return err
}

// successor mengembalikan string terkecil yang lebih besar dari semua string
// berawalan p. ok=false kalau tidak ada (p hanya berisi byte 0xff).
func successor(p string) (string, bool) {
	b := []byte(p)
	for len(b) > 0 && b[len(b)-1] == 0xff {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return "", false
	}
	b[len(b)-1]++
	return string(b), true
}

// isCommonPrefix melaporkan apakah marker adalah common prefix untuk prefix
// dan delimiter ini, yaitu berakhir tepat di delimiter pertama setelah prefix.
func isCommonPrefix(marker, prefix, delimiter string) bool {
	if !strings.HasPrefix(marker, prefix) {
		return false
	}
	rest := marker[len(prefix):]
	i := strings.Index(rest, delimiter)
	return i >= 0 && i+len(delimiter) == len(rest)
}

// List mengembalikan object berawalan prefix yang letaknya setelah marker,
// maksimal max entri. Dengan delimiter, key yang masih mengandung delimiter
// setelah prefix digulung menjadi common prefix.
func (s *Store) List(bucket, prefix, delimiter, marker string, max int) (ListResult, error) {
	var res ListResult
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(objBucket(bucket))
		if b == nil {
			return ErrNoSuchBucket
		}
		if max <= 0 {
			return nil
		}
		c := b.Cursor()

		var k, v []byte
		switch {
		case marker <= prefix:
			k, v = c.Seek([]byte(prefix))
			if string(k) == marker && marker != "" {
				k, v = c.Next()
			}
		default:
			seek, skipEqual := marker, true
			// Kalau marker adalah common prefix, lewati semua key di bawahnya.
			if delimiter != "" && strings.HasPrefix(marker, prefix) {
				rest := marker[len(prefix):]
				if i := strings.Index(rest, delimiter); i >= 0 && i+len(delimiter) == len(rest) {
					next, ok := successor(marker)
					if !ok {
						return nil
					}
					seek, skipEqual = next, false
				}
			}
			k, v = c.Seek([]byte(seek))
			if skipEqual && string(k) == marker {
				k, v = c.Next()
			}
		}

		count := 0
		for k != nil && bytes.HasPrefix(k, []byte(prefix)) {
			key := string(k)
			if delimiter != "" {
				rest := key[len(prefix):]
				if i := strings.Index(rest, delimiter); i >= 0 {
					cp := prefix + rest[:i+len(delimiter)]
					if count == max {
						res.IsTruncated = true
						break
					}
					res.CommonPrefixes = append(res.CommonPrefixes, cp)
					res.NextMarker = cp
					count++
					next, ok := successor(cp)
					if !ok {
						break
					}
					k, v = c.Seek([]byte(next))
					continue
				}
			}
			if count == max {
				res.IsTruncated = true
				break
			}
			var o ObjectInfo
			if err := json.Unmarshal(v, &o); err != nil {
				return err
			}
			res.Objects = append(res.Objects, o)
			res.NextMarker = key
			count++
			k, v = c.Next()
		}
		if !res.IsTruncated {
			res.NextMarker = ""
		}
		return nil
	})
	return res, err
}
