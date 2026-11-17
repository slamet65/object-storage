package storage

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrDomainTaken  = errors.New("domain sudah dipakai bucket lain")
	ErrObjectLocked = errors.New("object dilindungi aturan bucket lock")
)

// Storage class yang dikenal. Kosong di ObjectInfo berarti STANDARD.
const (
	ClassStandard = "STANDARD"
	ClassIA       = "STANDARD_IA"
)

var domainsBucket = sysBucket("domains") // domain -> nama bucket

// CORSRule adalah satu aturan CORS bucket.
type CORSRule struct {
	ID             string   `json:"id,omitempty"`
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers,omitempty"`
	ExposeHeaders  []string `json:"expose_headers,omitempty"`
	MaxAgeSeconds  int      `json:"max_age_seconds,omitempty"`
}

// LifecycleRule adalah satu aturan lifecycle. Tiap aksi aktif kalau
// nilainya terisi.
type LifecycleRule struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Prefix  string `json:"prefix,omitempty"`

	// Kedaluwarsa: hapus object setelah sekian hari sejak diubah, atau
	// mulai tanggal tertentu.
	ExpireDays int        `json:"expire_days,omitempty"`
	ExpireDate *time.Time `json:"expire_date,omitempty"`

	// Transisi: pindahkan object ke storage class lain.
	TransitionDays  int        `json:"transition_days,omitempty"`
	TransitionDate  *time.Time `json:"transition_date,omitempty"`
	TransitionClass string     `json:"transition_class,omitempty"`

	// Batalkan multipart upload yang belum selesai setelah sekian hari.
	AbortUploadDays int `json:"abort_upload_days,omitempty"`
}

// Mode aturan bucket lock.
const (
	LockAge        = "age"        // sekian hari sejak object ditulis
	LockDate       = "date"       // sampai tanggal tertentu
	LockIndefinite = "indefinite" // selama aturan masih ada
)

// LockRule melarang penghapusan dan penimpaan object berawalan Prefix
// selama masa retensinya.
type LockRule struct {
	ID      string     `json:"id"`
	Enabled bool       `json:"enabled"`
	Prefix  string     `json:"prefix,omitempty"`
	Mode    string     `json:"mode"`
	Days    int        `json:"days,omitempty"`
	Until   *time.Time `json:"until,omitempty"`
}

type BucketInfo struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`

	// Public mengizinkan GET/HEAD object tanpa autentikasi (bukan listing).
	Public bool `json:"public"`
	// Domains adalah custom domain yang dilayani dari bucket ini.
	Domains   []string        `json:"domains,omitempty"`
	CORS      []CORSRule      `json:"cors,omitempty"`
	Lifecycle []LifecycleRule `json:"lifecycle,omitempty"`
	Locks     []LockRule      `json:"locks,omitempty"`
}

// Locked melaporkan apakah object dengan key dan waktu tulis modTime masih
// dalam masa retensi pada saat now.
func (b BucketInfo) Locked(key string, modTime, now time.Time) bool {
	for _, r := range b.Locks {
		if !r.Enabled || !strings.HasPrefix(key, r.Prefix) {
			continue
		}
		switch r.Mode {
		case LockIndefinite:
			return true
		case LockDate:
			if r.Until != nil && now.Before(*r.Until) {
				return true
			}
		case LockAge:
			if now.Before(modTime.Add(time.Duration(r.Days) * 24 * time.Hour)) {
				return true
			}
		}
	}
	return false
}

func getBucket(tx *bolt.Tx, name string) (BucketInfo, error) {
	var info BucketInfo
	v := tx.Bucket(bucketsBucket).Get([]byte(name))
	if v == nil {
		return info, ErrNoSuchBucket
	}
	return info, json.Unmarshal(v, &info)
}

// UpdateBucket mengubah konfigurasi bucket secara atomik. Nama dan waktu
// pembuatan tidak bisa diubah. Indeks custom domain ikut diperbarui; domain
// yang sudah dipakai bucket lain menghasilkan ErrDomainTaken.
func (s *Store) UpdateBucket(name string, fn func(*BucketInfo) error) (BucketInfo, error) {
	var info BucketInfo
	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		if info, err = getBucket(tx, name); err != nil {
			return err
		}
		created, oldDomains := info.Created, slices.Clone(info.Domains)
		if err := fn(&info); err != nil {
			return err
		}
		info.Name, info.Created = name, created

		idx, err := tx.CreateBucketIfNotExists(domainsBucket)
		if err != nil {
			return err
		}
		for _, d := range oldDomains {
			if !slices.Contains(info.Domains, d) {
				if err := idx.Delete([]byte(d)); err != nil {
					return err
				}
			}
		}
		for _, d := range info.Domains {
			if owner := idx.Get([]byte(d)); owner != nil && string(owner) != name {
				return ErrDomainTaken
			}
			if err := idx.Put([]byte(d), []byte(name)); err != nil {
				return err
			}
		}
		v, err := json.Marshal(info)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketsBucket).Put([]byte(name), v)
	})
	return info, err
}

// BucketForDomain mengembalikan bucket yang dipetakan ke custom domain.
func (s *Store) BucketForDomain(domain string) (string, bool) {
	var name string
	s.db.View(func(tx *bolt.Tx) error {
		if idx := tx.Bucket(domainsBucket); idx != nil {
			name = string(idx.Get([]byte(domain)))
		}
		return nil
	})
	return name, name != ""
}

// SetStorageClass memindahkan object ke storage class lain, hanya kalau
// object masih versi yang sama (ETag cocok). Object yang sudah berubah atau
// hilang dibiarkan tanpa error.
func (s *Store) SetStorageClass(bucket, key, etag, class string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
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
		if o.ETag != etag {
			return nil
		}
		o.StorageClass = class
		nv, err := json.Marshal(o)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), nv)
	})
}
