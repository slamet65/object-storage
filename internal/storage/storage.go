// Package storage menyimpan bucket dan object di disk lokal.
//
// Metadata disimpan di bbolt (kunci terurut, cocok untuk listing), sedangkan
// isi object disimpan sebagai file blob dengan nama acak. Satu object terdiri
// dari satu atau lebih segment; multipart upload cukup menyusun segment dari
// part yang sudah ada tanpa menyalin data.
package storage

import (
	"errors"
	"time"
)

var (
	ErrNoSuchBucket     = errors.New("bucket tidak ditemukan")
	ErrBucketExists     = errors.New("bucket sudah ada")
	ErrBucketNotEmpty   = errors.New("bucket tidak kosong")
	ErrTooManyBuckets   = errors.New("jumlah bucket sudah mencapai batas")
	ErrNoSuchKey        = errors.New("object tidak ditemukan")
	ErrNoSuchUpload     = errors.New("multipart upload tidak ditemukan")
	ErrInvalidPart      = errors.New("part tidak ditemukan atau ETag tidak cocok")
	ErrInvalidPartOrder = errors.New("urutan part harus menaik")
	ErrEntityTooSmall   = errors.New("part selain yang terakhir harus minimal 5 MiB")
	ErrEntityTooLarge   = errors.New("ukuran object melebihi batas")
)

const (
	// MinPartSize adalah ukuran minimum part multipart, kecuali part terakhir.
	MinPartSize = 5 << 20
	// MaxObjectSize adalah ukuran maksimum object hasil multipart.
	MaxObjectSize = 5 << 40
)

// Jenis checksum object: dihitung atas seluruh isi, atau atas gabungan
// checksum tiap part (hasil multipart).
const (
	ChecksumFullObject = "FULL_OBJECT"
	ChecksumComposite  = "COMPOSITE"
)

// Checksum adalah checksum tambahan (x-amz-checksum-*) yang dikirim klien
// dan sudah diverifikasi saat upload.
type Checksum struct {
	Algo  string `json:"algo"`  // crc32, crc32c, crc64nvme, sha1, sha256
	Value string `json:"value"` // base64
	Type  string `json:"type,omitempty"`
}

// Segment menunjuk satu file blob yang menjadi bagian dari isi object.
type Segment struct {
	Blob string `json:"blob"`
	Size int64  `json:"size"`
}

// Meta adalah metadata yang dikirim klien saat menulis object.
type Meta struct {
	ContentType string `json:"contentType,omitempty"`
	// StorageClass kosong berarti STANDARD.
	StorageClass string            `json:"storageClass,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`  // Cache-Control, Content-Disposition, dst.
	UserMeta     map[string]string `json:"userMeta,omitempty"` // x-amz-meta-*
}

// PutInput adalah masukan tambahan saat menulis object.
type PutInput struct {
	Meta Meta
	// Check, kalau diisi, dipanggil dengan object yang sekarang ada di key
	// tujuan (nil kalau belum ada). Error-nya membatalkan penulisan. Dipanggil
	// sebelum body dibaca dan sekali lagi di dalam transaksi commit.
	Check func(existing *ObjectInfo) error
	// Checksum, kalau diisi, dipanggil setelah body habis dibaca.
	Checksum func() *Checksum
}

type ObjectInfo struct {
	Key      string    `json:"key"`
	Size     int64     `json:"size"`
	ETag     string    `json:"etag"` // tanpa tanda kutip
	ModTime  time.Time `json:"modTime"`
	Segments []Segment `json:"segments"`
	Checksum *Checksum `json:"checksum,omitempty"`
	Meta
}

type ListResult struct {
	Objects        []ObjectInfo
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     string // entri terakhir yang dikembalikan (key atau common prefix)
}

type Upload struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Initiated time.Time `json:"initiated"`
	Meta
}

type Part struct {
	Number   int       `json:"number"`
	Size     int64     `json:"size"`
	ETag     string    `json:"etag"`
	ModTime  time.Time `json:"modTime"`
	Blob     string    `json:"blob"`
	Checksum *Checksum `json:"checksum,omitempty"`
}

// UploadList adalah satu halaman hasil ListUploads.
type UploadList struct {
	Uploads            []Upload
	CommonPrefixes     []string
	IsTruncated        bool
	NextKeyMarker      string
	NextUploadIDMarker string
}

// CompletedPart adalah part yang disebut klien saat menyelesaikan upload.
type CompletedPart struct {
	Number int
	ETag   string
}
