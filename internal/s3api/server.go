// Package s3api menerjemahkan permintaan HTTP gaya S3 menjadi operasi pada
// storage. Bucket dikenali dari path (path-style) atau, kalau Domain diisi,
// dari subdomain pada header Host (virtual-hosted-style).
package s3api

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"object-storage/internal/auth"
	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

// AdminPrefix adalah awalan path API admin (token dan kredensial sementara).
const AdminPrefix = "/-/admin/"

// HealthPath dilayani tanpa autentikasi. "-" bukan nama bucket yang valid,
// jadi path ini tidak bisa bertabrakan dengan bucket.
const HealthPath = "/-/healthz"

// Limits adalah batas ukuran permintaan. Nilai nol berarti pakai bawaan.
type Limits struct {
	MaxPutSize      int64 // PutObject sekali kirim; bawaan 5 GiB
	MaxPartSize     int64 // satu part multipart; bawaan 5 GiB
	MaxMetadataSize int   // total nama + nilai x-amz-meta-*; bawaan 8192 byte
}

func (l Limits) withDefaults() Limits {
	if l.MaxPutSize == 0 {
		l.MaxPutSize = 5 << 30
	}
	if l.MaxPartSize == 0 {
		l.MaxPartSize = 5 << 30
	}
	if l.MaxMetadataSize == 0 {
		l.MaxMetadataSize = 8192
	}
	return l
}

type Server struct {
	Store *storage.Store
	// Auth memverifikasi signature. Identitas yang dihasilkannya harus
	// bertipe auth.Identity; permintaan tanpa identitas seperti itu ditolak.
	Auth *sigv4.Verifier
	// Tokens melayani API admin; nil berarti API admin dimatikan.
	Tokens *auth.Manager
	Region string
	Logger *slog.Logger
	// Domain mengaktifkan virtual-hosted-style: permintaan ke
	// <bucket>.<Domain> diperlakukan sebagai permintaan ke bucket itu.
	Domain string
	Limits Limits
}

// reqCtx membawa keadaan satu permintaan.
type reqCtx struct {
	srv    *Server
	w      http.ResponseWriter
	r      *http.Request
	q      url.Values
	auth   *sigv4.Result
	id     auth.Identity
	admin  bool // permintaan ke API admin; error dijawab dalam JSON
	limits Limits
	bucket string
	key    string
	binfo  *storage.BucketInfo // nil kalau bucket tidak ada
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Subresource yang dikenal tetapi tidak didukung; dijawab NotImplemented
// supaya tidak salah dianggap operasi lain (misalnya PUT ?acl sebagai PutObject).
var (
	bucketSubresources = []string{"acl", "policy", "policyStatus", "tagging", "website",
		"notification", "replication", "encryption", "logging", "accelerate", "requestPayment", "object-lock",
		"analytics", "inventory", "metrics", "ownershipControls", "publicAccessBlock", "intelligent-tiering", "versions"}
	objectSubresources = []string{"acl", "tagging", "retention", "legal-hold", "torrent", "attributes", "restore", "select"}
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	var id [8]byte
	rand.Read(id[:])
	rec.Header().Set("x-amz-request-id", strings.ToUpper(hex.EncodeToString(id[:])))
	rec.Header().Set("Server", "objstore")

	c := &reqCtx{srv: s, w: rec, r: r, q: r.URL.Query(), limits: s.Limits.withDefaults()}
	c.route()
	if r.URL.Path == HealthPath {
		return // jangan penuhi log dengan pemeriksaan kesehatan
	}
	s.Logger.Info("request", "method", r.Method, "host", r.Host, "path", r.URL.Path, "query", r.URL.RawQuery,
		"status", rec.status, "dur", time.Since(start).Round(time.Microsecond))
}

// hostBucket mengembalikan nama bucket kalau host permintaan menunjuk
// langsung ke sebuah bucket: subdomain dari Domain, atau custom domain yang
// dipetakan ke bucket.
func (s *Server) hostBucket(host string) (string, bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if s.Domain != "" {
		if bucket, ok := strings.CutSuffix(host, "."+strings.ToLower(s.Domain)); ok && bucket != "" {
			return bucket, true
		}
	}
	return s.Store.BucketForDomain(host)
}

// publicRead melaporkan apakah permintaan boleh dilayani tanpa
// autentikasi: GET/HEAD satu object di bucket publik. Listing tidak termasuk.
func (c *reqCtx) publicRead() bool {
	m := c.r.Method
	return c.binfo != nil && c.binfo.Public && c.key != "" &&
		(m == http.MethodGet || m == http.MethodHead) && !c.q.Has("uploadId")
}

func (c *reqCtx) route() {
	m := c.r.Method
	path := strings.TrimPrefix(c.r.URL.Path, "/")
	vhostBucket, vhost := c.srv.hostBucket(c.r.Host)

	if !vhost && c.r.URL.Path == HealthPath && (m == http.MethodGet || m == http.MethodHead) {
		c.w.Header().Set("Content-Type", "text/plain")
		io.WriteString(c.w, "ok\n")
		return
	}

	c.admin = !vhost && strings.HasPrefix(c.r.URL.Path, AdminPrefix)
	if !c.admin {
		if vhost {
			c.bucket, c.key = vhostBucket, path
		} else {
			c.bucket, c.key, _ = strings.Cut(path, "/")
		}
		if c.bucket != "" {
			if info, err := c.srv.Store.HeadBucket(c.bucket); err == nil {
				c.binfo = &info
			}
		}
		if m == http.MethodOptions {
			c.preflight()
			return
		}
		c.applyCORS()
	}

	res, err := c.srv.Auth.Verify(c.r)
	switch {
	case err == nil:
		id, ok := res.Identity.(auth.Identity)
		if !ok {
			c.fail(errAccessDenied)
			return
		}
		c.auth, c.id = res, id
	case errors.Is(err, sigv4.ErrAnonymous) && c.publicRead():
		c.auth = &sigv4.Result{Body: c.r.Body}
		c.id = auth.Identity{TokenID: "anonymous", Permission: auth.ObjectRead, Buckets: []string{c.bucket}}
	default:
		c.fail(err)
		return
	}

	if c.admin {
		c.serveAdmin(strings.TrimPrefix(c.r.URL.Path, AdminPrefix))
		return
	}

	switch {
	case c.bucket == "":
		if m == http.MethodGet {
			c.listBuckets()
			return
		}
	case c.key == "":
		if c.unsupported(bucketSubresources) {
			return
		}
		prefix := c.q.Get("prefix")
		switch m {
		case http.MethodPut:
			switch {
			case c.q.Has("cors"):
				c.guard(auth.ActAdminWrite, "", c.putBucketCORS)
			case c.q.Has("lifecycle"):
				c.guard(auth.ActAdminWrite, "", c.putBucketLifecycle)
			default:
				c.guard(auth.ActAdminWrite, "", c.createBucket)
			}
			return
		case http.MethodHead:
			c.guard(auth.ActBucketInfo, "", c.headBucket)
			return
		case http.MethodDelete:
			switch {
			case c.q.Has("cors"):
				c.guard(auth.ActAdminWrite, "", c.deleteBucketCORS)
			case c.q.Has("lifecycle"):
				c.guard(auth.ActAdminWrite, "", c.deleteBucketLifecycle)
			default:
				c.guard(auth.ActAdminWrite, "", c.deleteBucket)
			}
			return
		case http.MethodGet:
			switch {
			case c.q.Has("cors"):
				c.guard(auth.ActAdminRead, "", c.getBucketCORS)
			case c.q.Has("lifecycle"):
				c.guard(auth.ActAdminRead, "", c.getBucketLifecycle)
			case c.q.Has("location"):
				c.guard(auth.ActBucketInfo, "", c.getBucketLocation)
			case c.q.Has("versioning"):
				c.guard(auth.ActBucketInfo, "", c.getBucketVersioning)
			case c.q.Has("uploads"):
				c.guard(auth.ActList, prefix, c.listUploads)
			case c.q.Get("list-type") == "2":
				c.guard(auth.ActList, prefix, func() { c.listObjects(true) })
			default:
				c.guard(auth.ActList, prefix, func() { c.listObjects(false) })
			}
			return
		case http.MethodPost:
			if c.q.Has("delete") {
				// Izin tulis diperiksa per key di dalam handler.
				c.guard(auth.ActBucketInfo, "", c.deleteObjects)
				return
			}
		}
	default:
		if c.unsupported(objectSubresources) {
			return
		}
		if len(c.key) > 1024 {
			c.fail(errf("KeyTooLongError", "Your key is too long"))
			return
		}
		hasUpload := c.q.Has("uploadId")
		switch m {
		case http.MethodGet, http.MethodHead:
			if hasUpload && m == http.MethodGet {
				c.guard(auth.ActRead, c.key, c.listParts)
			} else {
				c.guard(auth.ActRead, c.key, c.getObject)
			}
			return
		case http.MethodPut:
			switch {
			case hasUpload:
				c.guard(auth.ActWrite, c.key, c.uploadPart)
			case c.r.Header.Get("X-Amz-Copy-Source") != "":
				c.guard(auth.ActWrite, c.key, c.copyObject)
			default:
				c.guard(auth.ActWrite, c.key, c.putObject)
			}
			return
		case http.MethodDelete:
			if hasUpload {
				c.guard(auth.ActWrite, c.key, c.abortUpload)
			} else {
				c.guard(auth.ActWrite, c.key, c.deleteObject)
			}
			return
		case http.MethodPost:
			switch {
			case c.q.Has("uploads"):
				c.guard(auth.ActWrite, c.key, c.createUpload)
				return
			case hasUpload:
				c.guard(auth.ActWrite, c.key, c.completeUpload)
				return
			}
		}
	}
	c.fail(errf("MethodNotAllowed", "The specified method is not allowed against this resource"))
}

var errAccessDenied = errf("AccessDenied", "Access Denied")

// guard menjalankan fn hanya kalau identitas boleh melakukan action pada
// bucket permintaan. key adalah key object, atau prefix untuk ActList.
// Penolakan dijawab sebelum keberadaan bucket atau object diperiksa,
// supaya token di luar cakupan tidak bisa menebak isinya.
func (c *reqCtx) guard(action auth.Action, key string, fn func()) {
	if !c.id.Allows(action, c.bucket, key) {
		c.fail(errAccessDenied)
		return
	}
	fn()
}

func (c *reqCtx) unsupported(subresources []string) bool {
	for _, name := range subresources {
		if c.q.Has(name) {
			c.fail(errf("NotImplemented", "Subresource '"+name+"' is not supported"))
			return true
		}
	}
	return false
}

func (c *reqCtx) writeXML(status int, v any) {
	body, err := xml.Marshal(v)
	if err != nil {
		c.srv.Logger.Error("gagal membuat XML", "err", err)
		c.w.WriteHeader(http.StatusInternalServerError)
		return
	}
	c.w.Header().Set("Content-Type", "application/xml")
	c.w.WriteHeader(status)
	if c.r.Method != http.MethodHead {
		io.WriteString(c.w, xml.Header)
		c.w.Write(body)
	}
}

// readXML membaca body kecil berisi XML sampai habis, sehingga pemeriksaan
// integritas body ikut berjalan, lalu mem-parse-nya ke v.
func (c *reqCtx) readXML(v any) error {
	body, _, err := c.verifiedBody(4 << 20)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if err := xml.Unmarshal(data, v); err != nil {
		return errf("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema")
	}
	return nil
}

// ---- Pemeriksaan integritas dan ukuran body ----

var errTooLarge = errf("EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")

// limitReader menggagalkan pembacaan begitu isi melebihi max byte.
type limitReader struct {
	r      io.Reader
	remain int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if l.remain -= int64(n); l.remain < 0 {
		return n, errTooLarge
	}
	return n, err
}

// digestReader menghitung digest selagi body dibaca dan membandingkannya
// dengan nilai base64 yang diharapkan saat EOF.
type digestReader struct {
	r        io.Reader
	h        hash.Hash
	want     func() string
	verified string // terisi setelah digest terbukti cocok
}

func (d *digestReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.h.Write(p[:n])
	if err == io.EOF {
		got := base64.StdEncoding.EncodeToString(d.h.Sum(nil))
		if got != d.want() {
			return n, errf("BadDigest", "The Content-MD5 or checksum value that you specified did not match what the server received")
		}
		d.verified = got
	}
	return n, err
}

// verifiedBody mengembalikan body yang dibatasi max byte dan memeriksa
// Content-MD5 serta x-amz-checksum-* (dari header maupun trailer) selagi
// dibaca. Fungsi kedua mengembalikan checksum yang sudah terverifikasi
// setelah body habis dibaca, atau nil kalau klien tidak mengirimnya.
func (c *reqCtx) verifiedBody(max int64) (io.Reader, func() *storage.Checksum, error) {
	h := c.r.Header

	declared := c.r.ContentLength
	if v := h.Get("X-Amz-Decoded-Content-Length"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, nil, errf("InvalidArgument", "Invalid x-amz-decoded-content-length")
		}
		declared = n
	}
	if declared > max {
		return nil, nil, errTooLarge
	}
	var body io.Reader = &limitReader{r: c.auth.Body, remain: max}

	if v := h.Get("Content-MD5"); v != "" {
		if raw, err := base64.StdEncoding.DecodeString(v); err != nil || len(raw) != md5.Size {
			return nil, nil, errf("InvalidDigest", "The Content-MD5 you specified is not valid")
		}
		body = &digestReader{r: body, h: md5.New(), want: func() string { return v }}
	}

	trailers := map[string]bool{}
	for _, t := range strings.Split(h.Get("X-Amz-Trailer"), ",") {
		trailers[strings.ToLower(strings.TrimSpace(t))] = true
	}
	checksum := func() *storage.Checksum { return nil }
	for _, algo := range storage.ChecksumAlgos {
		name := "x-amz-checksum-" + algo
		var want func() string
		switch v := h.Get(name); {
		case v != "":
			want = func() string { return v }
		case trailers[name]:
			want = func() string { return c.auth.Trailer(name) }
		default:
			continue
		}
		dr := &digestReader{r: body, h: storage.NewChecksumHash(algo), want: want}
		body = dr
		checksum = func() *storage.Checksum {
			if dr.verified == "" {
				return nil
			}
			return &storage.Checksum{Algo: algo, Value: dr.verified}
		}
		break // S3 hanya menerima satu algoritma per permintaan
	}
	return body, checksum, nil
}

// setChecksumHeader menulis header x-amz-checksum-<algo> ke respons.
func setChecksumHeader(h http.Header, sum *storage.Checksum) {
	if sum != nil {
		h.Set("x-amz-checksum-"+sum.Algo, sum.Value)
		if sum.Type != "" {
			h.Set("x-amz-checksum-type", sum.Type)
		}
	}
}

// checksumFields adalah elemen checksum di respons XML.
type checksumFields struct {
	ChecksumCRC32     string `xml:",omitempty"`
	ChecksumCRC32C    string `xml:",omitempty"`
	ChecksumCRC64NVME string `xml:",omitempty"`
	ChecksumSHA1      string `xml:",omitempty"`
	ChecksumSHA256    string `xml:",omitempty"`
	ChecksumType      string `xml:",omitempty"`
}

func checksumXML(sum *storage.Checksum) checksumFields {
	var f checksumFields
	if sum == nil {
		return f
	}
	f.ChecksumType = sum.Type
	switch sum.Algo {
	case "crc32":
		f.ChecksumCRC32 = sum.Value
	case "crc32c":
		f.ChecksumCRC32C = sum.Value
	case "crc64nvme":
		f.ChecksumCRC64NVME = sum.Value
	case "sha1":
		f.ChecksumSHA1 = sum.Value
	case "sha256":
		f.ChecksumSHA256 = sum.Value
	}
	return f
}

// ---- Metadata object ----

var storedHeaders = []string{"Cache-Control", "Content-Disposition", "Content-Encoding", "Content-Language", "Expires"}

func (c *reqCtx) metaFromHeaders() (storage.Meta, error) {
	h := c.r.Header
	m := storage.Meta{ContentType: h.Get("Content-Type")}
	var err error
	if m.StorageClass, err = parseStorageClass(h); err != nil {
		return m, err
	}
	for _, name := range storedHeaders {
		v := h.Get(name)
		if name == "Content-Encoding" {
			v = stripAWSChunked(v)
		}
		if v != "" {
			if m.Headers == nil {
				m.Headers = map[string]string{}
			}
			m.Headers[name] = v
		}
	}
	size := 0
	for name, vals := range h {
		if rest, ok := strings.CutPrefix(strings.ToLower(name), "x-amz-meta-"); ok && rest != "" {
			if m.UserMeta == nil {
				m.UserMeta = map[string]string{}
			}
			m.UserMeta[rest] = strings.Join(vals, ",")
			size += len(rest) + len(m.UserMeta[rest])
		}
	}
	if size > c.limits.MaxMetadataSize {
		return m, errf("MetadataTooLarge", "Your metadata headers exceed the maximum allowed metadata size")
	}
	return m, nil
}

// stripAWSChunked membuang "aws-chunked", yang merupakan encoding transfer
// milik SigV4 dan bukan bagian dari isi object.
func stripAWSChunked(v string) string {
	var keep []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" && !strings.EqualFold(p, "aws-chunked") {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, ",")
}

func quote(etag string) string { return `"` + etag + `"` }

func unquote(etag string) string {
	return strings.Trim(strings.TrimPrefix(strings.TrimSpace(etag), "W/"), `"`)
}

const xmlTime = "2006-01-02T15:04:05.000Z"

func fmtTime(t time.Time) string { return t.UTC().Format(xmlTime) }
