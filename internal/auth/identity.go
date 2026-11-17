// Package auth mengelola token akses, izinnya, dan kredensial sementara.
//
// Modelnya mengikuti R2: setiap token punya satu dari empat tingkat izin
// dan berlaku untuk semua bucket atau daftar bucket tertentu. Kredensial
// sementara diturunkan dari sebuah token, dengan izin dan cakupan yang
// tidak melebihi induknya, dan bisa dipersempit sampai prefix atau object.
package auth

import (
	"slices"
	"strings"
)

type Permission string

const (
	AdminReadWrite  Permission = "admin-read-write"
	AdminRead       Permission = "admin-read"
	ObjectReadWrite Permission = "object-read-write"
	ObjectRead      Permission = "object-read"
)

// Action adalah golongan operasi untuk keperluan otorisasi.
type Action int

const (
	// ActBucketInfo: melihat keberadaan dan info bucket (HeadBucket, lokasi).
	ActBucketInfo Action = iota
	// ActList: mendaftar object atau multipart upload dalam bucket.
	ActList
	// ActRead: membaca satu object (GET, HEAD, ListParts, sumber salinan).
	ActRead
	// ActWrite: menulis atau menghapus object, termasuk multipart.
	ActWrite
	// ActAdminRead: melihat konfigurasi dan daftar token.
	ActAdminRead
	// ActAdminWrite: membuat/menghapus bucket, mengubah konfigurasi, mengelola token.
	ActAdminWrite
)

var granted = map[Permission][]Action{
	ObjectRead:      {ActBucketInfo, ActList, ActRead},
	ObjectReadWrite: {ActBucketInfo, ActList, ActRead, ActWrite},
	AdminRead:       {ActBucketInfo, ActList, ActRead, ActAdminRead},
	AdminReadWrite:  {ActBucketInfo, ActList, ActRead, ActWrite, ActAdminRead, ActAdminWrite},
}

// Valid melaporkan apakah p salah satu dari empat tingkat izin.
func (p Permission) Valid() bool {
	_, ok := granted[p]
	return ok
}

func (p Permission) allows(a Action) bool { return slices.Contains(granted[p], a) }

// Covers melaporkan apakah p mengizinkan semua yang diizinkan other.
func (p Permission) Covers(other Permission) bool {
	for _, a := range granted[other] {
		if !p.allows(a) {
			return false
		}
	}
	return other.Valid()
}

// Identity adalah pihak yang menandatangani sebuah permintaan.
type Identity struct {
	TokenID    string // access key token, atau "root"
	Permission Permission
	// Buckets membatasi bucket yang boleh disentuh; nil berarti semua.
	Buckets []string
	// Prefixes dan Objects mempersempit object yang boleh disentuh (hanya
	// pada kredensial sementara). Keduanya kosong berarti semua object.
	Prefixes []string
	Objects  []string
	// Temporary menandai kredensial sementara.
	Temporary bool
}

// AllBuckets melaporkan apakah identitas tidak dibatasi ke bucket tertentu.
func (id Identity) AllBuckets() bool { return id.Buckets == nil }

// CanSeeBucket melaporkan apakah bucket ada dalam cakupan identitas.
func (id Identity) CanSeeBucket(bucket string) bool {
	return id.AllBuckets() || slices.Contains(id.Buckets, bucket)
}

func (id Identity) keyScoped() bool { return len(id.Prefixes) > 0 || len(id.Objects) > 0 }

func (id Identity) keyAllowed(key string) bool {
	if slices.Contains(id.Objects, key) {
		return true
	}
	return slices.ContainsFunc(id.Prefixes, func(p string) bool { return strings.HasPrefix(key, p) })
}

// Allows melaporkan apakah identitas boleh melakukan action pada bucket.
// key adalah key object untuk ActRead/ActWrite, atau prefix yang diminta
// untuk ActList; untuk action lain diabaikan.
func (id Identity) Allows(action Action, bucket, key string) bool {
	if !id.Permission.allows(action) || !id.CanSeeBucket(bucket) {
		return false
	}
	if !id.keyScoped() {
		return true
	}
	switch action {
	case ActBucketInfo:
		return true
	case ActRead, ActWrite:
		return id.keyAllowed(key)
	case ActList:
		// Daftar hanya boleh di bawah prefix yang diizinkan; cakupan
		// per-object saja tidak cukup untuk mendaftar.
		return slices.ContainsFunc(id.Prefixes, func(p string) bool { return strings.HasPrefix(key, p) })
	}
	// Kredensial yang dipersempit ke object tertentu tidak pernah boleh
	// melakukan operasi admin.
	return false
}

// CanManageTokens melaporkan apakah identitas boleh membuat, mengubah, dan
// menghapus token: harus admin baca-tulis tanpa batasan bucket, dan bukan
// kredensial sementara.
func (id Identity) CanManageTokens() bool {
	return id.Permission == AdminReadWrite && id.AllBuckets() && !id.Temporary
}

// CanListTokens melaporkan apakah identitas boleh melihat daftar token.
func (id Identity) CanListTokens() bool {
	return id.Permission.allows(ActAdminRead) && id.AllBuckets() && !id.Temporary
}
