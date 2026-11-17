package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

const (
	tokensNS = "tokens"
	// RootID adalah TokenID untuk kredensial root dari environment.
	RootID = "root"
	// MaxTempTTL adalah masa berlaku terpanjang kredensial sementara.
	MaxTempTTL = 7 * 24 * time.Hour
)

var ErrNoSuchToken = errors.New("token tidak ditemukan")

// InvalidError menandai masukan yang tidak valid dari pemanggil.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &InvalidError{Msg: fmt.Sprintf(format, args...)}
}

// Token adalah kredensial jangka panjang. ID-nya sekaligus access key ID.
type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Permission Permission `json:"permission"`
	Buckets    []string   `json:"buckets,omitempty"` // kosong berarti semua bucket
	Created    time.Time  `json:"created"`
	Expires    *time.Time `json:"expires,omitempty"`
	Disabled   bool       `json:"disabled,omitempty"`
	// Gen naik setiap kali secret dirotasi, sehingga kredensial sementara
	// yang diterbitkan dari secret lama ikut gugur.
	Gen       int    `json:"gen"`
	SecretEnc []byte `json:"secret_enc"`
}

func (t Token) identity() Identity {
	id := Identity{TokenID: t.ID, Permission: t.Permission}
	if len(t.Buckets) > 0 {
		id.Buckets = t.Buckets
	}
	return id
}

// Manager menyimpan token di metadata store dan memverifikasi kredensial.
// Secret disimpan terenkripsi dengan master key, karena SigV4 membutuhkan
// secret aslinya untuk menghitung ulang signature.
type Manager struct {
	Now func() time.Time // nil berarti time.Now

	store      *storage.Store
	aead       cipher.AEAD
	rootAccess string
	rootSecret string
}

// LoadMasterKey mengambil master key 32 byte dari OBJSTORE_MASTER_KEY
// (base64), atau dari file master.key di data directory, yang dibuat acak
// saat pertama kali dibutuhkan.
func LoadMasterKey(dataDir string) ([]byte, error) {
	if v := os.Getenv("OBJSTORE_MASTER_KEY"); v != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil || len(key) != 32 {
			return nil, errors.New("OBJSTORE_MASTER_KEY harus 32 byte dalam base64")
		}
		return key, nil
	}
	path := filepath.Join(dataDir, "master.key")
	if data, err := os.ReadFile(path); err == nil {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("%s rusak: harus 32 byte dalam base64", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		return nil, err
	}
	return key, f.Sync()
}

func NewManager(store *storage.Store, masterKey []byte, rootAccess, rootSecret string) (*Manager, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Manager{store: store, aead: aead, rootAccess: rootAccess, rootSecret: rootSecret}, nil
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// seal mengenkripsi data; aad mengikat ciphertext ke konteks pemakaiannya.
func (m *Manager) seal(data []byte, aad string) []byte {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return m.aead.Seal(nonce, nonce, data, []byte(aad))
}

func (m *Manager) open(sealed []byte, aad string) ([]byte, error) {
	n := m.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("ciphertext terlalu pendek")
	}
	return m.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
}

func secretAAD(id string) string { return "objstore-token-secret-v1:" + id }

func (m *Manager) get(id string) (Token, error) {
	var t Token
	v, err := m.store.SysGet(tokensNS, id)
	if err != nil {
		return t, err
	}
	if v == nil {
		return t, ErrNoSuchToken
	}
	return t, json.Unmarshal(v, &t)
}

// update mengubah token secara atomik.
func (m *Manager) update(id string, fn func(*Token) error) (Token, error) {
	var t Token
	err := m.store.SysUpdate(tokensNS, id, func(old []byte) ([]byte, error) {
		if old == nil {
			return nil, ErrNoSuchToken
		}
		if err := json.Unmarshal(old, &t); err != nil {
			return nil, err
		}
		if err := fn(&t); err != nil {
			return nil, err
		}
		return json.Marshal(t)
	})
	return t, err
}

// CreateInput adalah masukan pembuatan token.
type CreateInput struct {
	Name       string
	Permission Permission
	Buckets    []string      // kosong berarti semua bucket
	TTL        time.Duration // nol berarti tidak kedaluwarsa
}

// Create membuat token baru dan mengembalikan secret-nya. Secret hanya
// bisa dilihat di sini; setelah itu hanya bisa dirotasi.
func (m *Manager) Create(in CreateInput) (Token, string, error) {
	if !in.Permission.Valid() {
		return Token{}, "", invalid("izin tidak dikenal: %q", in.Permission)
	}
	if in.TTL < 0 {
		return Token{}, "", invalid("masa berlaku tidak boleh negatif")
	}
	for _, b := range in.Buckets {
		if b == "" {
			return Token{}, "", invalid("nama bucket tidak boleh kosong")
		}
	}
	now := m.now().UTC()
	t := Token{ID: randomHex(16), Name: in.Name, Permission: in.Permission, Buckets: in.Buckets, Created: now}
	if in.TTL > 0 {
		exp := now.Add(in.TTL)
		t.Expires = &exp
	}
	secret := randomHex(32)
	t.SecretEnc = m.seal([]byte(secret), secretAAD(t.ID))
	err := m.store.SysUpdate(tokensNS, t.ID, func([]byte) ([]byte, error) { return json.Marshal(t) })
	return t, secret, err
}

func (m *Manager) List() ([]Token, error) {
	var out []Token
	err := m.store.SysList(tokensNS, func(_ string, v []byte) error {
		var t Token
		if err := json.Unmarshal(v, &t); err != nil {
			return err
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

// Delete mencabut token. Berlaku seketika, termasuk untuk kredensial
// sementara yang diterbitkan darinya.
func (m *Manager) Delete(id string) error {
	return m.store.SysUpdate(tokensNS, id, func(old []byte) ([]byte, error) {
		if old == nil {
			return nil, ErrNoSuchToken
		}
		return nil, nil
	})
}

// Rotate mengganti secret token. Secret lama dan kredensial sementara yang
// diterbitkan darinya langsung tidak berlaku.
func (m *Manager) Rotate(id string) (Token, string, error) {
	secret := randomHex(32)
	t, err := m.update(id, func(t *Token) error {
		t.Gen++
		t.SecretEnc = m.seal([]byte(secret), secretAAD(t.ID))
		return nil
	})
	return t, secret, err
}

// SetDisabled menonaktifkan atau mengaktifkan kembali token.
func (m *Manager) SetDisabled(id string, disabled bool) (Token, error) {
	return m.update(id, func(t *Token) error {
		t.Disabled = disabled
		return nil
	})
}

// ---- Kredensial sementara ----

// claims adalah isi session token. Token ini tidak disimpan di server:
// seluruh keterangannya, termasuk secret, terenkripsi di dalam token.
type claims struct {
	AccessKey  string     `json:"ak"`
	Secret     string     `json:"sk"`
	Parent     string     `json:"par"`
	ParentGen  int        `json:"gen"`
	Permission Permission `json:"perm"`
	Buckets    []string   `json:"b,omitempty"`
	Prefixes   []string   `json:"p,omitempty"`
	Objects    []string   `json:"o,omitempty"`
	Expires    int64      `json:"exp"`
}

const sessionAAD = "objstore-session-v1"

// TempInput adalah masukan penerbitan kredensial sementara.
type TempInput struct {
	TTL        time.Duration
	Permission Permission
	Buckets    []string // kosong berarti sama dengan induk
	Prefixes   []string
	Objects    []string
}

type TempCredentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expires         time.Time `json:"expires"`
}

// IssueTemp menerbitkan kredensial sementara atas nama parent. Izin dan
// cakupannya tidak boleh melebihi parent.
func (m *Manager) IssueTemp(parent Identity, in TempInput) (TempCredentials, error) {
	if parent.Temporary {
		return TempCredentials{}, invalid("kredensial sementara tidak bisa menerbitkan kredensial lain")
	}
	if in.TTL < time.Second || in.TTL > MaxTempTTL {
		return TempCredentials{}, invalid("masa berlaku harus antara 1 detik dan 7 hari")
	}
	if !in.Permission.Valid() {
		return TempCredentials{}, invalid("izin tidak dikenal: %q", in.Permission)
	}
	if !parent.Permission.Covers(in.Permission) {
		return TempCredentials{}, invalid("izin %q melebihi izin token induk (%q)", in.Permission, parent.Permission)
	}
	buckets := in.Buckets
	if len(buckets) == 0 {
		buckets = parent.Buckets
	}
	for _, b := range buckets {
		if !parent.CanSeeBucket(b) {
			return TempCredentials{}, invalid("bucket %q di luar cakupan token induk", b)
		}
	}

	c := claims{
		AccessKey:  randomHex(16),
		Secret:     randomHex(32),
		Parent:     parent.TokenID,
		Permission: in.Permission,
		Buckets:    buckets,
		Prefixes:   in.Prefixes,
		Objects:    in.Objects,
	}
	expires := m.now().UTC().Add(in.TTL).Truncate(time.Second)
	if parent.TokenID != RootID {
		t, err := m.get(parent.TokenID)
		if err != nil {
			return TempCredentials{}, err
		}
		c.ParentGen = t.Gen
		if t.Expires != nil && t.Expires.Before(expires) {
			expires = *t.Expires
		}
	}
	c.Expires = expires.Unix()
	raw, err := json.Marshal(c)
	if err != nil {
		return TempCredentials{}, err
	}
	return TempCredentials{
		AccessKeyID:     c.AccessKey,
		SecretAccessKey: c.Secret,
		SessionToken:    base64.RawURLEncoding.EncodeToString(m.seal(raw, sessionAAD)),
		Expires:         time.Unix(c.Expires, 0).UTC(),
	}, nil
}

// ---- Verifikasi ----

var (
	errUnknownKey   = &sigv4.Error{Code: "InvalidAccessKeyId", Message: "The AWS Access Key Id you provided does not exist in our records"}
	errExpired      = &sigv4.Error{Code: "ExpiredToken", Message: "The provided token has expired"}
	errInvalidToken = &sigv4.Error{Code: "InvalidToken", Message: "The provided token is malformed or otherwise invalid"}
)

// activeToken mengambil token dan memastikan masih berlaku.
func (m *Manager) activeToken(id string) (Token, error) {
	t, err := m.get(id)
	if errors.Is(err, ErrNoSuchToken) {
		return t, errUnknownKey
	}
	if err != nil {
		return t, err
	}
	if t.Disabled {
		return t, errUnknownKey
	}
	if t.Expires != nil && !m.now().Before(*t.Expires) {
		return t, errExpired
	}
	return t, nil
}

// Lookup memenuhi sigv4.KeyLookup.
func (m *Manager) Lookup(accessKey, sessionToken string) (sigv4.Credential, error) {
	if sessionToken != "" {
		return m.lookupTemp(accessKey, sessionToken)
	}
	if accessKey == m.rootAccess {
		return sigv4.Credential{Secret: m.rootSecret, Identity: Identity{TokenID: RootID, Permission: AdminReadWrite}}, nil
	}
	t, err := m.activeToken(accessKey)
	if err != nil {
		return sigv4.Credential{}, err
	}
	secret, err := m.open(t.SecretEnc, secretAAD(t.ID))
	if err != nil {
		return sigv4.Credential{}, fmt.Errorf("secret token %s tidak bisa didekripsi (master key berubah?): %w", t.ID, err)
	}
	return sigv4.Credential{Secret: string(secret), Identity: t.identity()}, nil
}

func (m *Manager) lookupTemp(accessKey, sessionToken string) (sigv4.Credential, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(sessionToken)
	if err != nil {
		return sigv4.Credential{}, errInvalidToken
	}
	raw, err := m.open(sealed, sessionAAD)
	if err != nil {
		return sigv4.Credential{}, errInvalidToken
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil || c.AccessKey != accessKey {
		return sigv4.Credential{}, errInvalidToken
	}
	if !m.now().Before(time.Unix(c.Expires, 0)) {
		return sigv4.Credential{}, errExpired
	}
	// Induk yang dicabut, dinonaktifkan, kedaluwarsa, atau dirotasi
	// menggugurkan kredensial sementaranya.
	if c.Parent != RootID {
		t, err := m.activeToken(c.Parent)
		if err != nil {
			var se *sigv4.Error
			if errors.As(err, &se) {
				return sigv4.Credential{}, errInvalidToken
			}
			return sigv4.Credential{}, err
		}
		if t.Gen != c.ParentGen {
			return sigv4.Credential{}, errInvalidToken
		}
	}
	return sigv4.Credential{Secret: c.Secret, Identity: Identity{
		TokenID:    c.Parent,
		Permission: c.Permission,
		Buckets:    c.Buckets,
		Prefixes:   c.Prefixes,
		Objects:    c.Objects,
		Temporary:  true,
	}}, nil
}
