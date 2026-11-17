// Package sigv4 memverifikasi permintaan yang ditandatangani dengan
// AWS Signature Version 4, baik lewat header Authorization maupun
// presigned URL, termasuk body streaming (aws-chunked).
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	algorithm       = "AWS4-HMAC-SHA256"
	timeFormat      = "20060102T150405Z"
	maxSkew         = 15 * time.Minute
	maxExpires      = 7 * 24 * 60 * 60
	unsignedPayload = "UNSIGNED-PAYLOAD"
	emptySHA256     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	streamingSigned          = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingSignedTrailer   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamingUnsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// Error membawa kode error S3 supaya lapisan API bisa memetakannya ke respons.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func errf(code, msg string) *Error { return &Error{Code: code, Message: msg} }

// ErrAnonymous dikembalikan Verify untuk permintaan tanpa signature sama
// sekali, supaya pemanggil bisa membedakannya dari signature yang salah.
var ErrAnonymous = errf("AccessDenied", "permintaan anonim tidak diizinkan")

// Credential adalah hasil pencarian sebuah access key.
type Credential struct {
	Secret string
	// Identity adalah keterangan pemilik kunci; diteruskan apa adanya ke
	// Result supaya pemanggil bisa memutuskan otorisasi.
	Identity any
}

// KeyLookup mencari secret untuk sebuah access key. sessionToken terisi
// kalau permintaan membawa X-Amz-Security-Token (kredensial sementara).
// Kunci yang tidak dikenal atau tidak berlaku lagi dikembalikan sebagai
// *Error; error jenis lain diteruskan apa adanya dari Verify.
type KeyLookup interface {
	Lookup(accessKey, sessionToken string) (Credential, error)
}

// StaticKeys adalah KeyLookup untuk satu pasang kredensial tetap.
type StaticKeys struct {
	AccessKey string
	SecretKey string
}

func (s StaticKeys) Lookup(accessKey, sessionToken string) (Credential, error) {
	if accessKey != s.AccessKey || sessionToken != "" {
		return Credential{}, errf("InvalidAccessKeyId", "access key tidak dikenal")
	}
	return Credential{Secret: s.SecretKey}, nil
}

type Verifier struct {
	Keys KeyLookup
	Now  func() time.Time // nil berarti time.Now
}

// Result adalah hasil verifikasi yang berhasil.
type Result struct {
	// Identity adalah Credential.Identity milik kunci yang menandatangani.
	Identity any

	// Body adalah isi permintaan yang sudah di-decode. Integritasnya
	// (hash payload atau signature tiap chunk) diperiksa selagi dibaca,
	// dan kegagalan muncul sebagai *Error dari Read.
	Body io.Reader

	chunked *chunkReader
}

// Trailer mengembalikan nilai trailing header aws-chunked. Baru terisi
// setelah Body dibaca sampai habis.
func (r *Result) Trailer(name string) string {
	if r.chunked == nil {
		return ""
	}
	return r.chunked.trailers.Get(name)
}

type credential struct {
	accessKey, date, region, service string
}

func (c credential) scope() string {
	return c.date + "/" + c.region + "/" + c.service + "/aws4_request"
}

func parseCredential(s string) (credential, *Error) {
	p := strings.Split(s, "/")
	if len(p) != 5 || p[4] != "aws4_request" || p[3] != "s3" {
		return credential{}, errf("AuthorizationHeaderMalformed", "format Credential tidak valid")
	}
	return credential{accessKey: p[0], date: p[1], region: p[2], service: p[3]}, nil
}

// Verify memeriksa signature permintaan. Body belum dibaca di sini.
func (v *Verifier) Verify(r *http.Request) (*Result, error) {
	q := r.URL.Query()
	auth := r.Header.Get("Authorization")
	var (
		res *Result
		err error
	)
	switch {
	case q.Get("X-Amz-Algorithm") != "":
		res, err = v.verifyPresigned(r, q)
	case strings.HasPrefix(auth, algorithm):
		res, err = v.verifyHeader(r, auth)
	case auth == "" && q.Get("AWSAccessKeyId") != "":
		err = errf("InvalidRequest", "presigned URL Signature Version 2 tidak didukung; gunakan Signature Version 4")
	case auth == "":
		err = ErrAnonymous
	default:
		err = errf("InvalidRequest", "hanya AWS Signature Version 4 yang didukung")
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) verifyHeader(r *http.Request, auth string) (*Result, error) {
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimSpace(auth[len(algorithm):]), ",") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, errf("AuthorizationHeaderMalformed", "header Authorization tidak valid")
		}
		fields[k] = val
	}
	cred, e := parseCredential(fields["Credential"])
	if e != nil {
		return nil, e
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	sig := fields["Signature"]
	if fields["SignedHeaders"] == "" || sig == "" {
		return nil, errf("AuthorizationHeaderMalformed", "SignedHeaders atau Signature tidak ada")
	}
	owner, lerr := v.Keys.Lookup(cred.accessKey, r.Header.Get("X-Amz-Security-Token"))
	if lerr != nil {
		return nil, lerr
	}

	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		if t, err := http.ParseTime(r.Header.Get("Date")); err == nil {
			amzDate = t.UTC().Format(timeFormat)
		}
	}
	t, err := time.Parse(timeFormat, amzDate)
	if err != nil {
		return nil, errf("AccessDenied", "header X-Amz-Date tidak ada atau tidak valid")
	}
	if d := v.now().Sub(t); d > maxSkew || d < -maxSkew {
		return nil, errf("RequestTimeTooSkewed", "selisih waktu permintaan dengan server terlalu besar")
	}
	if cred.date != amzDate[:8] {
		return nil, errf("AuthorizationHeaderMalformed", "tanggal di Credential tidak cocok dengan X-Amz-Date")
	}
	if !contains(signed, "host") {
		return nil, errf("AccessDenied", "header host harus ikut ditandatangani")
	}

	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		return nil, errf("InvalidRequest", "header x-amz-content-sha256 wajib ada")
	}

	key := signingKey(owner.Secret, cred)
	want := signature(r, key, cred, amzDate, signed, payload, false)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return nil, errf("SignatureDoesNotMatch", "signature yang dihitung server tidak cocok dengan yang dikirim")
	}

	res := &Result{Body: r.Body, Identity: owner.Identity}
	switch payload {
	case unsignedPayload:
	case streamingSigned, streamingSignedTrailer, streamingUnsignedTrailer:
		res.chunked = newChunkReader(r.Body, chunkConfig{
			signed:  payload != streamingUnsignedTrailer,
			trailer: payload != streamingSigned,
			key:     key,
			date:    amzDate,
			scope:   cred.scope(),
			seed:    sig,
		})
		res.Body = res.chunked
	default:
		raw, err := hex.DecodeString(payload)
		if err != nil || len(raw) != sha256.Size {
			return nil, errf("InvalidRequest", "nilai x-amz-content-sha256 tidak valid")
		}
		res.Body = &hashReader{r: r.Body, h: sha256.New(), want: raw}
	}
	return res, nil
}

func (v *Verifier) verifyPresigned(r *http.Request, q url.Values) (*Result, error) {
	if q.Get("X-Amz-Algorithm") != algorithm {
		return nil, errf("InvalidRequest", "hanya AWS4-HMAC-SHA256 yang didukung")
	}
	cred, e := parseCredential(q.Get("X-Amz-Credential"))
	if e != nil {
		return nil, e
	}
	sig := q.Get("X-Amz-Signature")
	signed := strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	amzDate := q.Get("X-Amz-Date")
	if sig == "" || q.Get("X-Amz-SignedHeaders") == "" {
		return nil, errf("AuthorizationQueryParametersError", "parameter presigned URL tidak lengkap")
	}
	owner, lerr := v.Keys.Lookup(cred.accessKey, q.Get("X-Amz-Security-Token"))
	if lerr != nil {
		return nil, lerr
	}
	t, err := time.Parse(timeFormat, amzDate)
	if err != nil {
		return nil, errf("AuthorizationQueryParametersError", "X-Amz-Date tidak valid")
	}
	expires, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || expires < 1 || expires > maxExpires {
		return nil, errf("AuthorizationQueryParametersError", "X-Amz-Expires harus antara 1 dan 604800 detik")
	}
	now := v.now()
	if t.Sub(now) > maxSkew {
		return nil, errf("AccessDenied", "presigned URL belum berlaku")
	}
	if now.After(t.Add(time.Duration(expires) * time.Second)) {
		return nil, errf("AccessDenied", "presigned URL sudah kedaluwarsa")
	}
	if cred.date != amzDate[:8] {
		return nil, errf("AuthorizationQueryParametersError", "tanggal di X-Amz-Credential tidak cocok dengan X-Amz-Date")
	}
	if !contains(signed, "host") {
		return nil, errf("AccessDenied", "header host harus ikut ditandatangani")
	}

	payload := unsignedPayload
	if contains(signed, "x-amz-content-sha256") {
		payload = r.Header.Get("X-Amz-Content-Sha256")
	}
	key := signingKey(owner.Secret, cred)
	want := signature(r, key, cred, amzDate, signed, payload, true)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return nil, errf("SignatureDoesNotMatch", "signature yang dihitung server tidak cocok dengan yang dikirim")
	}
	return &Result{Body: r.Body, Identity: owner.Identity}, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func signingKey(secret string, c credential) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), c.date)
	k = hmacSHA256(k, c.region)
	k = hmacSHA256(k, c.service)
	return hmacSHA256(k, "aws4_request")
}

func signature(r *http.Request, key []byte, cred credential, amzDate string, signed []string, payload string, presigned bool) string {
	canonical := strings.Join([]string{
		r.Method,
		URIEncode(r.URL.Path, false),
		canonicalQuery(r.URL.RawQuery, presigned),
		canonicalHeaders(r, signed),
		strings.Join(signed, ";"),
		payload,
	}, "\n")
	stringToSign := strings.Join([]string{algorithm, amzDate, cred.scope(), sha256Hex(canonical)}, "\n")
	return hex.EncodeToString(hmacSHA256(key, stringToSign))
}

func canonicalHeaders(r *http.Request, signed []string) string {
	var b strings.Builder
	for _, name := range signed {
		var values []string
		switch name {
		case "host":
			values = []string{r.Host}
		case "content-length":
			// net/http bisa membuang header ini; ambil dari hasil parsing.
			if values = r.Header.Values(name); len(values) == 0 && r.ContentLength >= 0 {
				values = []string{strconv.FormatInt(r.ContentLength, 10)}
			}
		case "transfer-encoding":
			if values = r.Header.Values(name); len(values) == 0 {
				values = r.TransferEncoding
			}
		default:
			values = r.Header.Values(name)
		}
		for i, val := range values {
			values[i] = strings.Join(strings.Fields(val), " ")
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(values, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

func canonicalQuery(raw string, presigned bool) string {
	if raw == "" {
		return ""
	}
	var pairs []string
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, val, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(val); err == nil {
			val = dv
		}
		if presigned && k == "X-Amz-Signature" {
			continue
		}
		pairs = append(pairs, URIEncode(k, true)+"="+URIEncode(val, true))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// URIEncode meng-encode s menurut aturan SigV4: semua byte selain
// A-Z a-z 0-9 - _ . ~ menjadi %XX huruf besar. '/' dibiarkan kecuali
// encodeSlash bernilai true.
func URIEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}
