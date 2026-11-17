package s3api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"object-storage/internal/auth"
)

// API admin berbasis JSON di bawah AdminPrefix. Autentikasinya sama dengan
// API S3 (SigV4), jadi bisa dipanggil dengan kredensial root atau token.
//
//	GET    tokens                    daftar token
//	POST   tokens                    buat token (secret hanya muncul di sini)
//	GET    tokens/{id}               lihat satu token
//	DELETE tokens/{id}               cabut token
//	POST   tokens/{id}/rotate        ganti secret
//	POST   tokens/{id}/disable       nonaktifkan
//	POST   tokens/{id}/enable        aktifkan kembali
//	GET    buckets/{nama}            konfigurasi bucket
//	PUT    buckets/{nama}/public     atur akses publik dan custom domain
//	PUT    buckets/{nama}/lock       ganti seluruh aturan bucket lock
//	POST   temp-credentials          terbitkan kredensial sementara dari pemanggil
//	GET    whoami                    identitas pemanggil

type adminError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type tokenView struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Permission auth.Permission `json:"permission"`
	Buckets    []string        `json:"buckets"` // kosong berarti semua bucket
	Created    time.Time       `json:"created"`
	Expires    *time.Time      `json:"expires,omitempty"`
	Disabled   bool            `json:"disabled"`
	// Hanya terisi pada respons pembuatan dan rotasi.
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
}

func viewOf(t auth.Token, secret string) tokenView {
	v := tokenView{ID: t.ID, Name: t.Name, Permission: t.Permission, Buckets: t.Buckets,
		Created: t.Created, Expires: t.Expires, Disabled: t.Disabled}
	if v.Buckets == nil {
		v.Buckets = []string{}
	}
	if secret != "" {
		v.AccessKeyID, v.SecretAccessKey = t.ID, secret
	}
	return v
}

type createTokenRequest struct {
	Name       string          `json:"name"`
	Permission auth.Permission `json:"permission"`
	Buckets    []string        `json:"buckets"`
	TTLSeconds int64           `json:"ttl_seconds"`
}

type tempCredentialsRequest struct {
	TTLSeconds int64           `json:"ttl_seconds"`
	Permission auth.Permission `json:"permission"`
	Buckets    []string        `json:"buckets"`
	Prefixes   []string        `json:"prefixes"`
	Objects    []string        `json:"objects"`
}

type whoamiView struct {
	TokenID    string          `json:"token_id"`
	Permission auth.Permission `json:"permission"`
	Buckets    []string        `json:"buckets"`
	Prefixes   []string        `json:"prefixes,omitempty"`
	Objects    []string        `json:"objects,omitempty"`
	Temporary  bool            `json:"temporary"`
}

func (c *reqCtx) writeJSON(status int, v any) {
	c.w.Header().Set("Content-Type", "application/json")
	c.w.WriteHeader(status)
	if c.r.Method != http.MethodHead {
		json.NewEncoder(c.w).Encode(v)
	}
}

// readJSON membaca body JSON kecil sampai habis (supaya pemeriksaan
// integritas body berjalan) dan menolak field yang tidak dikenal.
func (c *reqCtx) readJSON(v any) error {
	body, _, err := c.verifiedBody(1 << 20)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errf("InvalidArgument", "body JSON tidak valid: "+err.Error())
	}
	return nil
}

// failAdmin memetakan error dari auth.Manager ke respons.
func (c *reqCtx) failAdmin(err error) {
	var inv *auth.InvalidError
	switch {
	case errors.As(err, &inv):
		c.fail(errf("InvalidArgument", inv.Msg))
	case errors.Is(err, auth.ErrNoSuchToken):
		c.fail(errf("NoSuchToken", "token tidak ditemukan"))
	default:
		c.fail(err)
	}
}

func (c *reqCtx) serveAdmin(path string) {
	tokens := c.srv.Tokens
	if tokens == nil {
		c.fail(errf("NoSuchResource", "API admin tidak aktif"))
		return
	}
	m := c.r.Method
	parts := strings.Split(strings.Trim(path, "/"), "/")

	switch {
	case len(parts) >= 2 && parts[0] == "buckets":
		c.serveAdminBucket(parts[1], parts[2:])

	case len(parts) == 1 && parts[0] == "whoami" && m == http.MethodGet:
		v := whoamiView{TokenID: c.id.TokenID, Permission: c.id.Permission, Buckets: c.id.Buckets,
			Prefixes: c.id.Prefixes, Objects: c.id.Objects, Temporary: c.id.Temporary}
		if v.Buckets == nil {
			v.Buckets = []string{}
		}
		c.writeJSON(http.StatusOK, v)

	case len(parts) == 1 && parts[0] == "temp-credentials" && m == http.MethodPost:
		var req tempCredentialsRequest
		if err := c.readJSON(&req); err != nil {
			c.fail(err)
			return
		}
		creds, err := tokens.IssueTemp(c.id, auth.TempInput{
			TTL:        time.Duration(req.TTLSeconds) * time.Second,
			Permission: req.Permission,
			Buckets:    req.Buckets,
			Prefixes:   req.Prefixes,
			Objects:    req.Objects,
		})
		if err != nil {
			c.failAdmin(err)
			return
		}
		c.writeJSON(http.StatusCreated, creds)

	case len(parts) == 1 && parts[0] == "tokens" && m == http.MethodGet:
		if !c.id.CanListTokens() {
			c.fail(errAccessDenied)
			return
		}
		list, err := tokens.List()
		if err != nil {
			c.fail(err)
			return
		}
		out := make([]tokenView, 0, len(list))
		for _, t := range list {
			out = append(out, viewOf(t, ""))
		}
		c.writeJSON(http.StatusOK, map[string]any{"tokens": out})

	case len(parts) == 1 && parts[0] == "tokens" && m == http.MethodPost:
		if !c.id.CanManageTokens() {
			c.fail(errAccessDenied)
			return
		}
		var req createTokenRequest
		if err := c.readJSON(&req); err != nil {
			c.fail(err)
			return
		}
		t, secret, err := tokens.Create(auth.CreateInput{Name: req.Name, Permission: req.Permission,
			Buckets: req.Buckets, TTL: time.Duration(req.TTLSeconds) * time.Second})
		if err != nil {
			c.failAdmin(err)
			return
		}
		c.writeJSON(http.StatusCreated, viewOf(t, secret))

	case len(parts) == 2 && parts[0] == "tokens" && m == http.MethodGet:
		if !c.id.CanListTokens() {
			c.fail(errAccessDenied)
			return
		}
		list, err := tokens.List()
		if err != nil {
			c.fail(err)
			return
		}
		for _, t := range list {
			if t.ID == parts[1] {
				c.writeJSON(http.StatusOK, viewOf(t, ""))
				return
			}
		}
		c.failAdmin(auth.ErrNoSuchToken)

	case len(parts) == 2 && parts[0] == "tokens" && m == http.MethodDelete:
		if !c.id.CanManageTokens() {
			c.fail(errAccessDenied)
			return
		}
		if err := tokens.Delete(parts[1]); err != nil {
			c.failAdmin(err)
			return
		}
		c.w.WriteHeader(http.StatusNoContent)

	case len(parts) == 3 && parts[0] == "tokens" && m == http.MethodPost:
		if !c.id.CanManageTokens() {
			c.fail(errAccessDenied)
			return
		}
		var (
			t      auth.Token
			secret string
			err    error
		)
		switch parts[2] {
		case "rotate":
			t, secret, err = tokens.Rotate(parts[1])
		case "disable":
			t, err = tokens.SetDisabled(parts[1], true)
		case "enable":
			t, err = tokens.SetDisabled(parts[1], false)
		default:
			c.fail(errf("NoSuchResource", "path API admin tidak dikenal"))
			return
		}
		if err != nil {
			c.failAdmin(err)
			return
		}
		c.writeJSON(http.StatusOK, viewOf(t, secret))

	default:
		c.fail(errf("NoSuchResource", "path API admin tidak dikenal"))
	}
}
