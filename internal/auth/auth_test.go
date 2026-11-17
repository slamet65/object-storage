package auth

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

func newManager(t *testing.T) *Manager {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	m, err := NewManager(store, bytes.Repeat([]byte{1}, 32), "rootkey", "rootsecret")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func code(err error) string {
	var e *sigv4.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "lain: " + err.Error()
}

func TestAllows(t *testing.T) {
	all := []Action{ActBucketInfo, ActList, ActRead, ActWrite, ActAdminRead, ActAdminWrite}
	want := map[Permission]string{ // satu huruf per action sesuai urutan all
		ObjectRead:      "yyy---",
		ObjectReadWrite: "yyyy--",
		AdminRead:       "yyy-y-",
		AdminReadWrite:  "yyyyyy",
	}
	for perm, pattern := range want {
		for i, a := range all {
			got := Identity{Permission: perm}.Allows(a, "b", "k")
			if got != (pattern[i] == 'y') {
				t.Errorf("%s action %d = %v", perm, a, got)
			}
		}
	}

	scoped := Identity{Permission: AdminReadWrite, Buckets: []string{"a"}}
	if !scoped.Allows(ActWrite, "a", "k") || scoped.Allows(ActRead, "b", "k") || scoped.Allows(ActAdminWrite, "b", "") {
		t.Error("cakupan bucket tidak ditegakkan")
	}
	if scoped.CanManageTokens() || !(Identity{Permission: AdminReadWrite}).CanManageTokens() {
		t.Error("CanManageTokens salah")
	}

	narrow := Identity{Permission: AdminReadWrite, Buckets: []string{"a"}, Prefixes: []string{"foto/"}, Objects: []string{"satu.txt"}, Temporary: true}
	cases := []struct {
		action Action
		key    string
		want   bool
	}{
		{ActRead, "foto/x.jpg", true},
		{ActWrite, "foto/x.jpg", true},
		{ActRead, "satu.txt", true},
		{ActRead, "satu.txt.bak", false},
		{ActRead, "lain/x", false},
		{ActList, "foto/2024/", true},
		{ActList, "", false},
		{ActList, "fot", false},
		{ActBucketInfo, "", true},
		{ActAdminWrite, "", false},
	}
	for _, c := range cases {
		if got := narrow.Allows(c.action, "a", c.key); got != c.want {
			t.Errorf("action %d key %q = %v", c.action, c.key, got)
		}
	}
}

func TestCovers(t *testing.T) {
	if !AdminReadWrite.Covers(ObjectRead) || !ObjectReadWrite.Covers(ObjectRead) || !AdminRead.Covers(ObjectRead) {
		t.Error("izin lebih tinggi harus mencakup object-read")
	}
	if ObjectRead.Covers(ObjectReadWrite) || AdminRead.Covers(ObjectReadWrite) || ObjectReadWrite.Covers(AdminRead) {
		t.Error("izin tidak boleh mencakup yang lebih luas")
	}
	if AdminReadWrite.Covers("ngawur") {
		t.Error("izin tak dikenal tidak boleh tercakup")
	}
}

func TestTokenLifecycle(t *testing.T) {
	m := newManager(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }

	if _, _, err := m.Create(CreateInput{Permission: "ngawur"}); err == nil {
		t.Fatal("izin tak dikenal harus ditolak")
	}
	tok, secret, err := m.Create(CreateInput{Name: "aplikasi", Permission: ObjectRead, Buckets: []string{"a"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(tok.SecretEnc, []byte(secret)) {
		t.Fatal("secret tersimpan tanpa enkripsi")
	}

	cred, err := m.Lookup(tok.ID, "")
	if err != nil || cred.Secret != secret {
		t.Fatalf("lookup: %v", err)
	}
	id := cred.Identity.(Identity)
	if id.Permission != ObjectRead || len(id.Buckets) != 1 || id.Temporary {
		t.Fatalf("identity = %+v", id)
	}
	if cred, err := m.Lookup("rootkey", ""); err != nil || cred.Secret != "rootsecret" || !cred.Identity.(Identity).CanManageTokens() {
		t.Fatalf("root lookup: %v", err)
	}
	if _, err := m.Lookup("tidak-ada", ""); code(err) != "InvalidAccessKeyId" {
		t.Fatalf("err = %v", err)
	}

	// Rotasi: secret lama tidak lagi dikembalikan.
	_, secret2, err := m.Rotate(tok.ID)
	if err != nil || secret2 == secret {
		t.Fatalf("rotate: %v", err)
	}
	if cred, _ := m.Lookup(tok.ID, ""); cred.Secret != secret2 {
		t.Fatal("secret baru tidak berlaku")
	}

	m.SetDisabled(tok.ID, true)
	if _, err := m.Lookup(tok.ID, ""); code(err) != "InvalidAccessKeyId" {
		t.Fatalf("token nonaktif: %v", err)
	}
	m.SetDisabled(tok.ID, false)

	now = now.Add(time.Hour)
	if _, err := m.Lookup(tok.ID, ""); code(err) != "ExpiredToken" {
		t.Fatalf("token kedaluwarsa: %v", err)
	}
	now = now.Add(-time.Minute)

	if err := m.Delete(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Lookup(tok.ID, ""); code(err) != "InvalidAccessKeyId" {
		t.Fatalf("token terhapus: %v", err)
	}
	if err := m.Delete(tok.ID); !errors.Is(err, ErrNoSuchToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestTempCredentials(t *testing.T) {
	m := newManager(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }

	tok, _, _ := m.Create(CreateInput{Permission: ObjectReadWrite, Buckets: []string{"a", "b"}})
	parent := tok.identity()

	bad := []TempInput{
		{TTL: time.Hour, Permission: AdminRead},                          // melebihi induk
		{TTL: time.Hour, Permission: ObjectRead, Buckets: []string{"c"}}, // bucket di luar cakupan
		{TTL: 0, Permission: ObjectRead},                                 // tanpa masa berlaku
		{TTL: MaxTempTTL + time.Second, Permission: ObjectRead},          // terlalu lama
		{TTL: time.Hour, Permission: "ngawur"},                           // izin tak dikenal
	}
	for i, in := range bad {
		var inv *InvalidError
		if _, err := m.IssueTemp(parent, in); !errors.As(err, &inv) {
			t.Errorf("kasus %d: err = %v", i, err)
		}
	}

	creds, err := m.IssueTemp(parent, TempInput{TTL: time.Hour, Permission: ObjectRead, Buckets: []string{"a"}, Prefixes: []string{"foto/"}})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := m.Lookup(creds.AccessKeyID, creds.SessionToken)
	if err != nil || cred.Secret != creds.SecretAccessKey {
		t.Fatalf("lookup: %v", err)
	}
	id := cred.Identity.(Identity)
	if !id.Temporary || id.Permission != ObjectRead || !id.Allows(ActRead, "a", "foto/x") || id.Allows(ActRead, "b", "foto/x") || id.Allows(ActWrite, "a", "foto/x") {
		t.Fatalf("identity = %+v", id)
	}
	// Kredensial sementara tidak bisa menerbitkan kredensial lain.
	if _, err := m.IssueTemp(id, TempInput{TTL: time.Minute, Permission: ObjectRead}); err == nil {
		t.Fatal("harus ditolak")
	}
	// Tanpa daftar bucket, cakupan induk diwariskan.
	inherit, _ := m.IssueTemp(parent, TempInput{TTL: time.Hour, Permission: ObjectRead})
	cred, _ = m.Lookup(inherit.AccessKeyID, inherit.SessionToken)
	if id := cred.Identity.(Identity); !id.CanSeeBucket("b") || id.CanSeeBucket("c") {
		t.Fatalf("cakupan warisan salah: %+v", id)
	}

	// Token yang diubah atau dipasangkan dengan access key lain ditolak.
	if _, err := m.Lookup(creds.AccessKeyID, creds.SessionToken[:len(creds.SessionToken)-2]+"AA"); code(err) != "InvalidToken" {
		t.Fatalf("err = %v", err)
	}
	if _, err := m.Lookup(inherit.AccessKeyID, creds.SessionToken); code(err) != "InvalidToken" {
		t.Fatalf("err = %v", err)
	}
	// Access key sementara tanpa session token tidak dikenal.
	if _, err := m.Lookup(creds.AccessKeyID, ""); code(err) != "InvalidAccessKeyId" {
		t.Fatalf("err = %v", err)
	}

	// Rotasi induk menggugurkan kredensial sementara lama.
	m.Rotate(tok.ID)
	if _, err := m.Lookup(creds.AccessKeyID, creds.SessionToken); code(err) != "InvalidToken" {
		t.Fatalf("setelah rotasi: %v", err)
	}
	fresh, _ := m.IssueTemp(parent, TempInput{TTL: time.Hour, Permission: ObjectRead})
	if _, err := m.Lookup(fresh.AccessKeyID, fresh.SessionToken); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Hour)
	if _, err := m.Lookup(fresh.AccessKeyID, fresh.SessionToken); code(err) != "ExpiredToken" {
		t.Fatalf("setelah TTL: %v", err)
	}
	now = now.Add(-time.Minute)

	// Induk dicabut: kredensial sementaranya ikut gugur.
	m.Delete(tok.ID)
	if _, err := m.Lookup(fresh.AccessKeyID, fresh.SessionToken); code(err) != "InvalidToken" {
		t.Fatalf("setelah induk dicabut: %v", err)
	}

	// Kredensial sementara dari root.
	rootCred, _ := m.Lookup("rootkey", "")
	fromRoot, err := m.IssueTemp(rootCred.Identity.(Identity), TempInput{TTL: time.Minute, Permission: AdminRead})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Lookup(fromRoot.AccessKeyID, fromRoot.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestMasterKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OBJSTORE_MASTER_KEY", "")
	k1, err := LoadMasterKey(dir)
	if err != nil || len(k1) != 32 {
		t.Fatalf("key = %d byte, err = %v", len(k1), err)
	}
	k2, _ := LoadMasterKey(dir)
	if !bytes.Equal(k1, k2) {
		t.Fatal("master key berubah antar pemanggilan")
	}
	t.Setenv("OBJSTORE_MASTER_KEY", "bukan-base64-32-byte")
	if _, err := LoadMasterKey(dir); err == nil {
		t.Fatal("master key tidak valid harus ditolak")
	}

	// Secret yang dienkripsi dengan master key lain tidak boleh terbaca.
	store, _ := storage.Open(t.TempDir())
	defer store.Close()
	m1, _ := NewManager(store, bytes.Repeat([]byte{1}, 32), "r", "s")
	tok, _, _ := m1.Create(CreateInput{Permission: ObjectRead})
	m2, _ := NewManager(store, bytes.Repeat([]byte{2}, 32), "r", "s")
	if _, err := m2.Lookup(tok.ID, ""); err == nil {
		t.Fatal("lookup dengan master key lain harus gagal")
	}
}
