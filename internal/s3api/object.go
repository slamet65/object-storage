package s3api

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"object-storage/internal/auth"
	"object-storage/internal/storage"
)

var errPrecondition = errf("PreconditionFailed", "At least one of the pre-conditions you specified did not hold")

// writeCheck menerjemahkan If-None-Match dan If-Match pada permintaan tulis
// menjadi pemeriksaan terhadap object yang sekarang ada di key tujuan.
// Hasilnya nil kalau permintaan tidak bersyarat.
func (c *reqCtx) writeCheck() (func(*storage.ObjectInfo) error, error) {
	ifMatch, ifNoneMatch := c.r.Header.Get("If-Match"), c.r.Header.Get("If-None-Match")
	if ifMatch == "" && ifNoneMatch == "" {
		return nil, nil
	}
	if ifNoneMatch != "" && strings.TrimSpace(ifNoneMatch) != "*" {
		return nil, errf("NotImplemented", "If-None-Match on writes only supports the value '*'")
	}
	return func(existing *storage.ObjectInfo) error {
		if ifNoneMatch != "" && existing != nil {
			return errPrecondition
		}
		if ifMatch != "" {
			if existing == nil {
				return storage.ErrNoSuchKey
			}
			if !etagMatches(ifMatch, existing.ETag) {
				return errPrecondition
			}
		}
		return nil
	}, nil
}

func (c *reqCtx) putObject() {
	meta, err := c.metaFromHeaders()
	if err != nil {
		c.fail(err)
		return
	}
	check, err := c.writeCheck()
	if err != nil {
		c.fail(err)
		return
	}
	body, checksum, err := c.verifiedBody(c.limits.MaxPutSize)
	if err != nil {
		c.fail(err)
		return
	}
	info, err := c.srv.Store.PutObject(c.bucket, c.key, body, storage.PutInput{Meta: meta, Check: check, Checksum: checksum})
	if err != nil {
		c.fail(err)
		return
	}
	c.w.Header().Set("ETag", quote(info.ETag))
	setChecksumHeader(c.w.Header(), info.Checksum)
	c.w.WriteHeader(http.StatusOK)
}

func (c *reqCtx) deleteObject() {
	if err := c.srv.Store.DeleteObject(c.bucket, c.key); err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusNoContent)
}

// Parameter query yang boleh menimpa header respons GetObject.
var responseOverrides = map[string]string{
	"response-content-type":        "Content-Type",
	"response-content-language":    "Content-Language",
	"response-expires":             "Expires",
	"response-cache-control":       "Cache-Control",
	"response-content-disposition": "Content-Disposition",
	"response-content-encoding":    "Content-Encoding",
}

func setObjectHeaders(h http.Header, info storage.ObjectInfo) {
	h.Set("ETag", quote(info.ETag))
	h.Set("Last-Modified", info.ModTime.UTC().Format(http.TimeFormat))
	h.Set("Accept-Ranges", "bytes")
	ct := info.ContentType
	if ct == "" {
		ct = "binary/octet-stream"
	}
	h.Set("Content-Type", ct)
	for k, v := range info.Headers {
		h.Set(k, v)
	}
	for k, v := range info.UserMeta {
		h.Set("x-amz-meta-"+k, v)
	}
	if info.StorageClass != "" {
		h.Set("x-amz-storage-class", info.StorageClass)
	}
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		if candidate = strings.TrimSpace(candidate); candidate == "*" || unquote(candidate) == etag {
			return true
		}
	}
	return false
}

// conditions adalah empat syarat baca standar HTTP.
type conditions struct {
	ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince string
}

// check mengevaluasi syarat terhadap object. Hasilnya 0 kalau permintaan
// boleh dilanjutkan, atau status 304/412.
func (cond conditions) check(info storage.ObjectInfo) int {
	mod := info.ModTime.Truncate(time.Second)
	if cond.ifMatch != "" {
		if !etagMatches(cond.ifMatch, info.ETag) {
			return http.StatusPreconditionFailed
		}
	} else if t, err := http.ParseTime(cond.ifUnmodifiedSince); err == nil && mod.After(t) {
		return http.StatusPreconditionFailed
	}
	if cond.ifNoneMatch != "" {
		if etagMatches(cond.ifNoneMatch, info.ETag) {
			return http.StatusNotModified
		}
	} else if t, err := http.ParseTime(cond.ifModifiedSince); err == nil && !mod.After(t) {
		return http.StatusNotModified
	}
	return 0
}

// conditionsFrom membaca syarat dari header berawalan prefix ("" untuk
// GET/HEAD, "X-Amz-Copy-Source-" untuk sumber salinan).
func conditionsFrom(h http.Header, prefix string) conditions {
	return conditions{
		ifMatch:           h.Get(prefix + "If-Match"),
		ifNoneMatch:       h.Get(prefix + "If-None-Match"),
		ifModifiedSince:   h.Get(prefix + "If-Modified-Since"),
		ifUnmodifiedSince: h.Get(prefix + "If-Unmodified-Since"),
	}
}

// parseRange mem-parse header Range berisi satu rentang. ok=false berarti
// header diabaikan (tidak ada, lebih dari satu rentang, atau tidak valid);
// satisfiable=false berarti rentang berada di luar object.
func parseRange(header string, size int64) (off, length int64, ok, satisfiable bool) {
	spec, found := strings.CutPrefix(header, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false, true
	}
	first, last, found := strings.Cut(strings.TrimSpace(spec), "-")
	if !found {
		return 0, 0, false, true
	}
	if first == "" { // suffix: N byte terakhir
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n < 0 {
			return 0, 0, false, true
		}
		if n == 0 || size == 0 {
			return 0, 0, true, false
		}
		n = min(n, size)
		return size - n, n, true, true
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false, true
	}
	end := size - 1
	if last != "" {
		e, err := strconv.ParseInt(last, 10, 64)
		if err != nil || e < start {
			return 0, 0, false, true
		}
		end = min(e, size-1)
	}
	if start >= size {
		return 0, 0, true, false
	}
	return start, end - start + 1, true, true
}

// getObject melayani GET dan HEAD.
func (c *reqCtx) getObject() {
	info, err := c.srv.Store.GetObject(c.bucket, c.key)
	if err != nil {
		c.fail(err)
		return
	}
	h := c.w.Header()
	switch conditionsFrom(c.r.Header, "").check(info) {
	case http.StatusNotModified:
		h.Set("ETag", quote(info.ETag))
		h.Set("Last-Modified", info.ModTime.UTC().Format(http.TimeFormat))
		c.w.WriteHeader(http.StatusNotModified)
		return
	case http.StatusPreconditionFailed:
		c.fail(errPrecondition)
		return
	}

	off, length, status := int64(0), info.Size, http.StatusOK
	rng := c.r.Header.Get("Range")
	switch pn := c.q.Get("partNumber"); {
	case pn != "":
		// Satu part dari object multipart; part dihitung menurut urutannya.
		n, err := strconv.Atoi(pn)
		if err != nil || n < 1 {
			c.fail(errf("InvalidArgument", "Part number must be a positive integer"))
			return
		}
		if rng != "" {
			c.fail(errf("InvalidRequest", "Cannot specify both Range header and partNumber query parameter"))
			return
		}
		if n > len(info.Segments) {
			c.fail(errf("InvalidPartNumber", "The requested partnumber is not satisfiable"))
			return
		}
		for _, seg := range info.Segments[:n-1] {
			off += seg.Size
		}
		length = info.Segments[n-1].Size
		if strings.Contains(info.ETag, "-") {
			h.Set("x-amz-mp-parts-count", strconv.Itoa(len(info.Segments)))
		}
		if length > 0 {
			status = http.StatusPartialContent
			h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, off+length-1, info.Size))
		}
	case rng != "":
		o, l, ok, satisfiable := parseRange(rng, info.Size)
		if !satisfiable {
			h.Set("Content-Range", fmt.Sprintf("bytes */%d", info.Size))
			c.fail(errf("InvalidRange", "The requested range is not satisfiable"))
			return
		}
		if ok {
			off, length, status = o, l, http.StatusPartialContent
			h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, off+length-1, info.Size))
		}
	}

	setObjectHeaders(h, info)
	// Checksum hanya berlaku untuk isi utuh, jadi tidak dikirim untuk rentang.
	if status == http.StatusOK && strings.EqualFold(c.r.Header.Get("X-Amz-Checksum-Mode"), "ENABLED") {
		setChecksumHeader(h, info.Checksum)
	}
	for param, header := range responseOverrides {
		if v := c.q.Get(param); v != "" {
			h.Set(header, v)
		}
	}
	h.Set("Content-Length", strconv.FormatInt(length, 10))
	c.w.WriteHeader(status)
	if c.r.Method == http.MethodHead {
		return
	}
	rc := c.srv.Store.OpenRange(info, off, length)
	defer rc.Close()
	if _, err := io.Copy(c.w, rc); err != nil {
		// Header sudah terkirim; yang bisa dilakukan hanya memutus respons.
		c.srv.Logger.Warn("pengiriman object terputus", "bucket", c.bucket, "key", c.key, "err", err)
	}
}

// parseCopySource mem-parse header x-amz-copy-source ("/bucket/key" atau
// "bucket/key", ter-encode URL).
func parseCopySource(v string) (bucket, key string, err error) {
	v, _, _ = strings.Cut(v, "?") // versionId tidak didukung
	if v, err = url.PathUnescape(v); err != nil {
		return "", "", errf("InvalidArgument", "Invalid copy source encoding")
	}
	bucket, key, ok := strings.Cut(strings.TrimPrefix(v, "/"), "/")
	if !ok || bucket == "" || key == "" {
		return "", "", errf("InvalidArgument", "Copy Source must mention the source bucket and key: sourcebucket/sourcekey")
	}
	return bucket, key, nil
}

// copySource mengambil object sumber salinan dan memeriksa syarat
// x-amz-copy-source-if-*. Syarat yang tidak terpenuhi selalu menjadi 412.
func (c *reqCtx) copySource() (bucket, key string, info storage.ObjectInfo, err error) {
	bucket, key, err = parseCopySource(c.r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		return
	}
	if !c.id.Allows(auth.ActRead, bucket, key) {
		err = errAccessDenied
		return
	}
	if info, err = c.srv.Store.GetObject(bucket, key); err != nil {
		return
	}
	if conditionsFrom(c.r.Header, "X-Amz-Copy-Source-").check(info) != 0 {
		err = errPrecondition
	}
	return
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	LastModified string
	ETag         string
	checksumFields
}

func (c *reqCtx) copyObject() {
	srcBucket, srcKey, src, err := c.copySource()
	if err != nil {
		c.fail(err)
		return
	}
	meta := src.Meta
	switch strings.ToUpper(c.r.Header.Get("X-Amz-Metadata-Directive")) {
	case "", "COPY":
		if srcBucket == c.bucket && srcKey == c.key {
			c.fail(errf("InvalidRequest", "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata"))
			return
		}
	case "REPLACE":
		if meta, err = c.metaFromHeaders(); err != nil {
			c.fail(err)
			return
		}
	default:
		c.fail(errf("InvalidArgument", "Unknown metadata directive"))
		return
	}
	// Seperti S3, storage class salinan ditentukan permintaan, bukan sumbernya.
	if meta.StorageClass, err = parseStorageClass(c.r.Header); err != nil {
		c.fail(err)
		return
	}
	check, err := c.writeCheck()
	if err != nil {
		c.fail(err)
		return
	}
	in := storage.PutInput{Meta: meta, Check: check}
	// Isi salinan identik dengan sumber, jadi checksum seluruh-object ikut
	// berlaku. Checksum gabungan multipart tidak, karena salinan bukan multipart.
	if sum := src.Checksum; sum != nil && sum.Type == storage.ChecksumFullObject {
		in.Checksum = func() *storage.Checksum { return &storage.Checksum{Algo: sum.Algo, Value: sum.Value} }
	}
	rc := c.srv.Store.OpenRange(src, 0, src.Size)
	defer rc.Close()
	info, err := c.srv.Store.PutObject(c.bucket, c.key, rc, in)
	if err != nil {
		c.fail(err)
		return
	}
	c.writeXML(http.StatusOK, copyObjectResult{LastModified: fmtTime(info.ModTime), ETag: quote(info.ETag),
		checksumFields: checksumXML(info.Checksum)})
}
