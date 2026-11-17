package storage

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Kunci upload: key object + NUL + upload id, sehingga terurut per key.
func uploadKey(key, id string) []byte { return []byte(key + "\x00" + id) }

// Kunci part: upload id + NUL + nomor part big-endian, sehingga terurut per nomor.
func partKey(id string, n int) []byte {
	k := append([]byte(id), 0, 0, 0)
	binary.BigEndian.PutUint16(k[len(k)-2:], uint16(n))
	return k
}

func partPrefix(id string) []byte { return append([]byte(id), 0) }

func getUpload(tx *bolt.Tx, bucket, key, id string) (Upload, error) {
	var u Upload
	b := tx.Bucket(uploadsBucket(bucket))
	if b == nil {
		return u, ErrNoSuchBucket
	}
	v := b.Get(uploadKey(key, id))
	if v == nil {
		return u, ErrNoSuchUpload
	}
	return u, json.Unmarshal(v, &u)
}

func (s *Store) CreateUpload(bucket, key string, meta Meta) (Upload, error) {
	u := Upload{ID: newID(), Key: key, Initiated: s.now(), Meta: meta}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(uploadsBucket(bucket))
		if b == nil {
			return ErrNoSuchBucket
		}
		v, _ := json.Marshal(u)
		return b.Put(uploadKey(key, u.ID), v)
	})
	return u, err
}

// PutPart menyimpan satu part. Mengunggah nomor part yang sama menimpa yang
// lama. checksum (boleh nil) dipanggil setelah body habis dibaca.
func (s *Store) PutPart(bucket, key, id string, number int, r io.Reader, checksum func() *Checksum) (Part, error) {
	err := s.db.View(func(tx *bolt.Tx) error {
		_, err := getUpload(tx, bucket, key, id)
		return err
	})
	if err != nil {
		return Part{}, err
	}
	blob, size, sum, err := s.writeBlob(r)
	if err != nil {
		return Part{}, err
	}
	p := Part{Number: number, Size: size, ETag: hex.EncodeToString(sum), ModTime: s.now(), Blob: blob}
	if checksum != nil {
		p.Checksum = checksum()
	}
	var old string
	err = s.db.Update(func(tx *bolt.Tx) error {
		old = ""
		// Upload bisa saja dibatalkan selagi part ditulis.
		if _, err := getUpload(tx, bucket, key, id); err != nil {
			return err
		}
		b := tx.Bucket(partsBucket(bucket))
		if v := b.Get(partKey(id, number)); v != nil {
			var prev Part
			if err := json.Unmarshal(v, &prev); err != nil {
				return err
			}
			old = prev.Blob
		}
		v, _ := json.Marshal(p)
		return b.Put(partKey(id, number), v)
	})
	if err != nil {
		s.removeBlobs(blob)
		return Part{}, err
	}
	s.removeBlobs(old)
	return p, nil
}

func listParts(tx *bolt.Tx, bucket, id string) ([]Part, error) {
	var parts []Part
	c := tx.Bucket(partsBucket(bucket)).Cursor()
	prefix := partPrefix(id)
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var p Part
		if err := json.Unmarshal(v, &p); err != nil {
			return nil, err
		}
		parts = append(parts, p)
	}
	return parts, nil
}

func (s *Store) ListParts(bucket, key, id string) (Upload, []Part, error) {
	var u Upload
	var parts []Part
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		if u, err = getUpload(tx, bucket, key, id); err != nil {
			return err
		}
		parts, err = listParts(tx, bucket, id)
		return err
	})
	return u, parts, err
}

// ListUploads mengembalikan upload yang belum selesai, terurut menurut key
// lalu upload id, mulai setelah (keyMarker, idMarker). Dengan delimiter, key
// yang masih mengandung delimiter setelah prefix digulung menjadi common prefix.
func (s *Store) ListUploads(bucket, prefix, delimiter, keyMarker, idMarker string, max int) (UploadList, error) {
	var res UploadList
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(uploadsBucket(bucket))
		if b == nil {
			return ErrNoSuchBucket
		}
		if max <= 0 {
			return nil
		}
		c := b.Cursor()

		seek := []byte(prefix)
		if keyMarker != "" {
			var after []byte
			switch {
			case idMarker != "":
				// Tepat setelah upload ini: tambahkan satu byte di belakang kuncinya.
				after = append(uploadKey(keyMarker, idMarker), 0)
			case delimiter != "" && isCommonPrefix(keyMarker, prefix, delimiter):
				next, ok := successor(keyMarker)
				if !ok {
					return nil
				}
				after = []byte(next)
			default:
				// Setelah semua upload milik key ini.
				after = []byte(keyMarker + "\x01")
			}
			if bytes.Compare(after, seek) > 0 {
				seek = after
			}
		}

		count := 0
		k, v := c.Seek(seek)
		for k != nil && bytes.HasPrefix(k, []byte(prefix)) {
			sep := bytes.LastIndexByte(k, 0)
			if sep < 0 {
				k, v = c.Next()
				continue
			}
			key := string(k[:sep])
			if !strings.HasPrefix(key, prefix) {
				break
			}
			if delimiter != "" {
				rest := key[len(prefix):]
				if i := strings.Index(rest, delimiter); i >= 0 {
					cp := prefix + rest[:i+len(delimiter)]
					if count == max {
						res.IsTruncated = true
						break
					}
					res.CommonPrefixes = append(res.CommonPrefixes, cp)
					res.NextKeyMarker, res.NextUploadIDMarker = cp, ""
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
			var u Upload
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			res.Uploads = append(res.Uploads, u)
			res.NextKeyMarker, res.NextUploadIDMarker = u.Key, u.ID
			count++
			k, v = c.Next()
		}
		if !res.IsTruncated {
			res.NextKeyMarker, res.NextUploadIDMarker = "", ""
		}
		return nil
	})
	return res, err
}

// deleteUpload menghapus catatan upload beserta semua part-nya dan
// mengembalikan part yang dihapus.
func deleteUpload(tx *bolt.Tx, bucket, key, id string) ([]Part, error) {
	parts, err := listParts(tx, bucket, id)
	if err != nil {
		return nil, err
	}
	pb := tx.Bucket(partsBucket(bucket))
	for _, p := range parts {
		if err := pb.Delete(partKey(id, p.Number)); err != nil {
			return nil, err
		}
	}
	return parts, tx.Bucket(uploadsBucket(bucket)).Delete(uploadKey(key, id))
}

func (s *Store) AbortUpload(bucket, key, id string) error {
	var parts []Part
	err := s.db.Update(func(tx *bolt.Tx) error {
		if _, err := getUpload(tx, bucket, key, id); err != nil {
			return err
		}
		var err error
		parts, err = deleteUpload(tx, bucket, key, id)
		return err
	})
	if err == nil {
		for _, p := range parts {
			s.removeBlobs(p.Blob)
		}
	}
	return err
}

// CompleteUpload menyusun object dari part yang disebut klien. Blob part
// langsung menjadi segment object; part yang tidak disebut dibuang.
// check (boleh nil) berperan seperti PutInput.Check.
func (s *Store) CompleteUpload(bucket, key, id string, want []CompletedPart, check func(*ObjectInfo) error) (ObjectInfo, error) {
	if len(want) == 0 {
		return ObjectInfo{}, ErrInvalidPart
	}
	for i := 1; i < len(want); i++ {
		if want[i].Number <= want[i-1].Number {
			return ObjectInfo{}, ErrInvalidPartOrder
		}
	}
	info := ObjectInfo{Key: key, ModTime: s.now()}
	var unused []string
	// Validasi dan penyusunan dilakukan di dalam transaksi tulis, supaya dua
	// permintaan complete yang bersamaan tidak sama-sama berhasil.
	err := s.commitObject(bucket, &info, check, func(tx *bolt.Tx) error {
		unused = unused[:0]
		u, err := getUpload(tx, bucket, key, id)
		if err != nil {
			return err
		}
		have, err := listParts(tx, bucket, id)
		if err != nil {
			return err
		}
		byNum := make(map[int]Part, len(have))
		for _, p := range have {
			byNum[p.Number] = p
		}
		sums := md5.New()
		used := make(map[int]bool, len(want))
		chosen := make([]Part, 0, len(want))
		info.Meta, info.Size, info.Segments = u.Meta, 0, nil
		for i, w := range want {
			p, ok := byNum[w.Number]
			if !ok || p.ETag != w.ETag {
				return ErrInvalidPart
			}
			if i < len(want)-1 && p.Size < MinPartSize {
				return ErrEntityTooSmall
			}
			raw, _ := hex.DecodeString(p.ETag)
			sums.Write(raw)
			info.Segments = append(info.Segments, Segment{Blob: p.Blob, Size: p.Size})
			info.Size += p.Size
			used[w.Number] = true
			chosen = append(chosen, p)
		}
		if info.Size > MaxObjectSize {
			return ErrEntityTooLarge
		}
		info.ETag = fmt.Sprintf("%s-%d", hex.EncodeToString(sums.Sum(nil)), len(want))
		info.Checksum = compositeChecksum(chosen)
		for _, p := range have {
			if !used[p.Number] {
				unused = append(unused, p.Blob)
			}
		}
		_, err = deleteUpload(tx, bucket, key, id)
		return err
	})
	if err != nil {
		return ObjectInfo{}, err
	}
	s.removeBlobs(unused...)
	return info, nil
}
