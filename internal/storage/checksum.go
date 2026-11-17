package storage

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
)

var (
	crc32cTable    = crc32.MakeTable(crc32.Castagnoli)
	crc64NVMETable = crc64.MakeTable(0x9a6c9329ac4bc9b5)
)

// ChecksumAlgos adalah daftar algoritma checksum yang dikenal.
var ChecksumAlgos = []string{"crc32", "crc32c", "crc64nvme", "sha1", "sha256"}

// NewChecksumHash mengembalikan hash untuk algoritma checksum S3, atau nil
// kalau algoritmanya tidak dikenal.
func NewChecksumHash(algo string) hash.Hash {
	switch algo {
	case "crc32":
		return crc32.NewIEEE()
	case "crc32c":
		return crc32.New(crc32cTable)
	case "crc64nvme":
		return crc64.New(crc64NVMETable)
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	}
	return nil
}

// compositeChecksum menghitung checksum gabungan gaya S3 untuk object
// multipart: hash atas gabungan checksum mentah tiap part, diberi akhiran
// jumlah part. Hasilnya nil kalau ada part tanpa checksum, algoritmanya
// tidak seragam, atau algoritmanya hanya mendukung checksum seluruh object
// (crc64nvme).
func compositeChecksum(parts []Part) *Checksum {
	if len(parts) == 0 || parts[0].Checksum == nil {
		return nil
	}
	algo := parts[0].Checksum.Algo
	if algo == "crc64nvme" {
		return nil
	}
	h := NewChecksumHash(algo)
	if h == nil {
		return nil
	}
	for _, p := range parts {
		if p.Checksum == nil || p.Checksum.Algo != algo {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(p.Checksum.Value)
		if err != nil {
			return nil
		}
		h.Write(raw)
	}
	return &Checksum{
		Algo:  algo,
		Value: fmt.Sprintf("%s-%d", base64.StdEncoding.EncodeToString(h.Sum(nil)), len(parts)),
		Type:  ChecksumComposite,
	}
}
