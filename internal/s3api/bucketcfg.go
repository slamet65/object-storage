package s3api

import (
	"encoding/xml"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"object-storage/internal/storage"
)

// ---- CORS ----

type corsRuleXML struct {
	ID             string   `xml:"ID,omitempty"`
	AllowedOrigins []string `xml:"AllowedOrigin"`
	AllowedMethods []string `xml:"AllowedMethod"`
	AllowedHeaders []string `xml:"AllowedHeader"`
	ExposeHeaders  []string `xml:"ExposeHeader"`
	MaxAgeSeconds  int      `xml:"MaxAgeSeconds,omitempty"`
}

type corsConfiguration struct {
	XMLName xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CORSConfiguration"`
	Rules   []corsRuleXML `xml:"CORSRule"`
}

var corsMethods = []string{"GET", "PUT", "POST", "DELETE", "HEAD"}

func (c *reqCtx) putBucketCORS() {
	var req corsConfiguration
	if err := c.readXML(&req); err != nil {
		c.fail(err)
		return
	}
	if len(req.Rules) == 0 || len(req.Rules) > 100 {
		c.fail(errf("MalformedXML", "The CORS configuration must contain between 1 and 100 rules"))
		return
	}
	rules := make([]storage.CORSRule, 0, len(req.Rules))
	for _, r := range req.Rules {
		if len(r.AllowedOrigins) == 0 || len(r.AllowedMethods) == 0 {
			c.fail(errf("MalformedXML", "Each CORSRule needs at least one AllowedOrigin and one AllowedMethod"))
			return
		}
		for _, m := range r.AllowedMethods {
			if !slices.Contains(corsMethods, m) {
				c.fail(errf("InvalidRequest", "Found unsupported HTTP method in CORS config. Unsupported method is "+m))
				return
			}
		}
		for _, pattern := range append(slices.Clone(r.AllowedOrigins), r.AllowedHeaders...) {
			if strings.Count(pattern, "*") > 1 {
				c.fail(errf("InvalidRequest", "AllowedOrigin and AllowedHeader can contain at most one * wildcard"))
				return
			}
		}
		if r.MaxAgeSeconds < 0 {
			c.fail(errf("InvalidRequest", "MaxAgeSeconds must not be negative"))
			return
		}
		rules = append(rules, storage.CORSRule(r))
	}
	_, err := c.srv.Store.UpdateBucket(c.bucket, func(b *storage.BucketInfo) error {
		b.CORS = rules
		return nil
	})
	if err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusOK)
}

func (c *reqCtx) getBucketCORS() {
	info, err := c.srv.Store.HeadBucket(c.bucket)
	if err != nil {
		c.fail(err)
		return
	}
	if len(info.CORS) == 0 {
		c.fail(errf("NoSuchCORSConfiguration", "The CORS configuration does not exist"))
		return
	}
	var res corsConfiguration
	for _, r := range info.CORS {
		res.Rules = append(res.Rules, corsRuleXML(r))
	}
	c.writeXML(http.StatusOK, res)
}

func (c *reqCtx) deleteBucketCORS() {
	_, err := c.srv.Store.UpdateBucket(c.bucket, func(b *storage.BucketInfo) error {
		b.CORS = nil
		return nil
	})
	if err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusNoContent)
}

// wildcardMatch mencocokkan s dengan pattern yang boleh berisi satu '*'.
func wildcardMatch(pattern, s string) bool {
	prefix, suffix, wild := strings.Cut(pattern, "*")
	if !wild {
		return pattern == s
	}
	return len(s) >= len(prefix)+len(suffix) && strings.HasPrefix(s, prefix) && strings.HasSuffix(s, suffix)
}

// corsRule mencari aturan CORS pertama yang mengizinkan origin memakai
// method dengan header permintaan headers.
func (c *reqCtx) corsRule(origin, method string, headers []string) *storage.CORSRule {
	if c.binfo == nil {
		return nil
	}
	for i := range c.binfo.CORS {
		r := &c.binfo.CORS[i]
		if !slices.Contains(r.AllowedMethods, method) ||
			!slices.ContainsFunc(r.AllowedOrigins, func(p string) bool { return wildcardMatch(p, origin) }) {
			continue
		}
		allowed := func(h string) bool {
			return slices.ContainsFunc(r.AllowedHeaders, func(p string) bool {
				return wildcardMatch(strings.ToLower(p), strings.ToLower(h))
			})
		}
		if !slices.ContainsFunc(headers, func(h string) bool { return !allowed(h) }) {
			return r
		}
	}
	return nil
}

func (c *reqCtx) setCORSHeaders(r *storage.CORSRule, origin string) {
	h := c.w.Header()
	if slices.Contains(r.AllowedOrigins, "*") {
		h.Set("Access-Control-Allow-Origin", "*")
	} else {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Add("Vary", "Origin")
	}
	if len(r.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(r.ExposeHeaders, ", "))
	}
}

// applyCORS menambahkan header CORS ke respons permintaan biasa kalau
// origin-nya diizinkan. Dipanggil sebelum autentikasi supaya respons error
// pun bisa dibaca skrip di browser.
func (c *reqCtx) applyCORS() {
	origin := c.r.Header.Get("Origin")
	if origin == "" {
		return
	}
	if r := c.corsRule(origin, c.r.Method, nil); r != nil {
		c.setCORSHeaders(r, origin)
	}
}

// preflight menjawab permintaan OPTIONS dari browser. Tidak butuh
// autentikasi, karena browser tidak pernah menyertakan kredensial di sini.
func (c *reqCtx) preflight() {
	origin := c.r.Header.Get("Origin")
	method := c.r.Header.Get("Access-Control-Request-Method")
	if origin == "" || method == "" {
		c.fail(errf("BadRequest", "Insufficient information. Origin and Access-Control-Request-Method request headers are needed."))
		return
	}
	var headers []string
	for _, h := range strings.Split(c.r.Header.Get("Access-Control-Request-Headers"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			headers = append(headers, h)
		}
	}
	r := c.corsRule(origin, method, headers)
	if r == nil {
		c.fail(errf("AccessForbidden", "CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec."))
		return
	}
	c.setCORSHeaders(r, origin)
	h := c.w.Header()
	h.Set("Access-Control-Allow-Methods", strings.Join(r.AllowedMethods, ", "))
	if len(headers) > 0 {
		h.Set("Access-Control-Allow-Headers", strings.Join(headers, ", "))
	}
	if r.MaxAgeSeconds > 0 {
		h.Set("Access-Control-Max-Age", strconv.Itoa(r.MaxAgeSeconds))
	}
	h.Add("Vary", "Access-Control-Request-Headers")
	h.Add("Vary", "Access-Control-Request-Method")
	c.w.WriteHeader(http.StatusOK)
}

// ---- Lifecycle ----

type lifecycleFilterXML struct {
	Prefix *string `xml:"Prefix"`
	// Filter berikut dikenali supaya bisa ditolak dengan jelas.
	And                   *struct{} `xml:"And"`
	Tag                   *struct{} `xml:"Tag"`
	ObjectSizeGreaterThan *int64    `xml:"ObjectSizeGreaterThan"`
	ObjectSizeLessThan    *int64    `xml:"ObjectSizeLessThan"`
}

type lifecycleExpirationXML struct {
	Days                      int    `xml:"Days,omitempty"`
	Date                      string `xml:"Date,omitempty"`
	ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker"`
}

type lifecycleTransitionXML struct {
	Days         int    `xml:"Days,omitempty"`
	Date         string `xml:"Date,omitempty"`
	StorageClass string `xml:"StorageClass"`
}

type lifecycleAbortXML struct {
	DaysAfterInitiation int `xml:"DaysAfterInitiation"`
}

type lifecycleRuleXML struct {
	ID          string                   `xml:"ID,omitempty"`
	Status      string                   `xml:"Status"`
	Prefix      *string                  `xml:"Prefix"` // bentuk lama, tanpa Filter
	Filter      *lifecycleFilterXML      `xml:"Filter"`
	Expiration  *lifecycleExpirationXML  `xml:"Expiration"`
	Transitions []lifecycleTransitionXML `xml:"Transition"`
	Abort       *lifecycleAbortXML       `xml:"AbortIncompleteMultipartUpload"`
	// Aksi versioning dikenali supaya bisa ditolak dengan jelas.
	NoncurrentExpiration *struct{} `xml:"NoncurrentVersionExpiration"`
	NoncurrentTransition *struct{} `xml:"NoncurrentVersionTransition"`
}

type lifecycleConfiguration struct {
	XMLName xml.Name           `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LifecycleConfiguration"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

func parseLifecycleDate(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t, nil
		}
	}
	return nil, errf("InvalidArgument", "Date must be in ISO 8601 format")
}

func lifecycleRuleFromXML(x lifecycleRuleXML, index int) (storage.LifecycleRule, error) {
	r := storage.LifecycleRule{ID: x.ID}
	if r.ID == "" {
		r.ID = "rule-" + strconv.Itoa(index+1)
	}
	if len(r.ID) > 255 {
		return r, errf("InvalidArgument", "ID length should not exceed allowed limit of 255")
	}
	switch x.Status {
	case "Enabled":
		r.Enabled = true
	case "Disabled":
	default:
		return r, errf("MalformedXML", "Rule Status must be Enabled or Disabled")
	}
	if x.NoncurrentExpiration != nil || x.NoncurrentTransition != nil {
		return r, errf("NotImplemented", "Noncurrent version actions are not supported (no versioning)")
	}
	if f := x.Filter; f != nil {
		if f.And != nil || f.Tag != nil || f.ObjectSizeGreaterThan != nil || f.ObjectSizeLessThan != nil {
			return r, errf("NotImplemented", "Only prefix filters are supported in lifecycle rules")
		}
		if f.Prefix != nil {
			r.Prefix = *f.Prefix
		}
	} else if x.Prefix != nil {
		r.Prefix = *x.Prefix
	}

	var err error
	if e := x.Expiration; e != nil {
		if e.ExpiredObjectDeleteMarker != nil {
			return r, errf("NotImplemented", "ExpiredObjectDeleteMarker is not supported (no versioning)")
		}
		if r.ExpireDate, err = parseLifecycleDate(e.Date); err != nil {
			return r, err
		}
		r.ExpireDays = e.Days
		if (e.Days > 0) == (r.ExpireDate != nil) || e.Days < 0 {
			return r, errf("InvalidArgument", "Expiration needs exactly one of a positive Days or a Date")
		}
	}
	if len(x.Transitions) > 1 {
		return r, errf("NotImplemented", "Only one Transition per rule is supported")
	}
	for _, t := range x.Transitions {
		if t.StorageClass != storage.ClassIA {
			return r, errf("InvalidStorageClass", "Transition is only supported to STANDARD_IA")
		}
		if r.TransitionDate, err = parseLifecycleDate(t.Date); err != nil {
			return r, err
		}
		r.TransitionDays, r.TransitionClass = t.Days, t.StorageClass
		if (t.Days > 0) == (r.TransitionDate != nil) || t.Days < 0 {
			return r, errf("InvalidArgument", "Transition needs exactly one of a positive Days or a Date")
		}
	}
	if a := x.Abort; a != nil {
		if a.DaysAfterInitiation <= 0 {
			return r, errf("InvalidArgument", "DaysAfterInitiation must be a positive integer")
		}
		r.AbortUploadDays = a.DaysAfterInitiation
	}
	if x.Expiration == nil && len(x.Transitions) == 0 && x.Abort == nil {
		return r, errf("MalformedXML", "At least one action needs to be specified in a rule")
	}
	return r, nil
}

func lifecycleRuleToXML(r storage.LifecycleRule) lifecycleRuleXML {
	date := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	prefix := r.Prefix
	x := lifecycleRuleXML{ID: r.ID, Status: "Disabled", Filter: &lifecycleFilterXML{Prefix: &prefix}}
	if r.Enabled {
		x.Status = "Enabled"
	}
	if r.ExpireDays > 0 || r.ExpireDate != nil {
		x.Expiration = &lifecycleExpirationXML{Days: r.ExpireDays, Date: date(r.ExpireDate)}
	}
	if r.TransitionClass != "" {
		x.Transitions = []lifecycleTransitionXML{{Days: r.TransitionDays, Date: date(r.TransitionDate), StorageClass: r.TransitionClass}}
	}
	if r.AbortUploadDays > 0 {
		x.Abort = &lifecycleAbortXML{DaysAfterInitiation: r.AbortUploadDays}
	}
	return x
}

func (c *reqCtx) putBucketLifecycle() {
	var req lifecycleConfiguration
	if err := c.readXML(&req); err != nil {
		c.fail(err)
		return
	}
	if len(req.Rules) == 0 || len(req.Rules) > 1000 {
		c.fail(errf("MalformedXML", "The lifecycle configuration must contain between 1 and 1000 rules"))
		return
	}
	rules := make([]storage.LifecycleRule, 0, len(req.Rules))
	seen := map[string]bool{}
	for i, x := range req.Rules {
		r, err := lifecycleRuleFromXML(x, i)
		if err != nil {
			c.fail(err)
			return
		}
		if seen[r.ID] {
			c.fail(errf("InvalidArgument", "Rule ID must be unique. Found same ID for more than one rule"))
			return
		}
		seen[r.ID] = true
		rules = append(rules, r)
	}
	_, err := c.srv.Store.UpdateBucket(c.bucket, func(b *storage.BucketInfo) error {
		b.Lifecycle = rules
		return nil
	})
	if err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusOK)
}

func (c *reqCtx) getBucketLifecycle() {
	info, err := c.srv.Store.HeadBucket(c.bucket)
	if err != nil {
		c.fail(err)
		return
	}
	if len(info.Lifecycle) == 0 {
		c.fail(errf("NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist"))
		return
	}
	var res lifecycleConfiguration
	for _, r := range info.Lifecycle {
		res.Rules = append(res.Rules, lifecycleRuleToXML(r))
	}
	c.writeXML(http.StatusOK, res)
}

func (c *reqCtx) deleteBucketLifecycle() {
	_, err := c.srv.Store.UpdateBucket(c.bucket, func(b *storage.BucketInfo) error {
		b.Lifecycle = nil
		return nil
	})
	if err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusNoContent)
}

// ---- Storage class ----

// parseStorageClass membaca x-amz-storage-class. Hasil kosong berarti STANDARD.
func parseStorageClass(h http.Header) (string, error) {
	switch sc := h.Get("X-Amz-Storage-Class"); sc {
	case "", storage.ClassStandard:
		return "", nil
	case storage.ClassIA:
		return sc, nil
	}
	return "", errf("InvalidStorageClass", "The storage class you specified is not valid")
}

func storageClassOf(class string) string {
	if class == "" {
		return storage.ClassStandard
	}
	return class
}
