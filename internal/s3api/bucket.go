package s3api

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"regexp"
	"strconv"

	"object-storage/internal/auth"
	"object-storage/internal/sigv4"
)

const xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

type owner struct {
	ID          string
	DisplayName string
}

var defaultOwner = owner{ID: "objstore", DisplayName: "objstore"}

var bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type bucketEntry struct {
	Name         string
	CreationDate string
}

type listBucketsResult struct {
	XMLName xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   owner         `xml:"Owner"`
	Buckets []bucketEntry `xml:"Buckets>Bucket"`
}

func (c *reqCtx) listBuckets() {
	buckets, err := c.srv.Store.ListBuckets()
	if err != nil {
		c.fail(err)
		return
	}
	res := listBucketsResult{Owner: defaultOwner}
	for _, b := range buckets {
		if !c.id.CanSeeBucket(b.Name) {
			continue
		}
		res.Buckets = append(res.Buckets, bucketEntry{Name: b.Name, CreationDate: fmtTime(b.Created)})
	}
	c.writeXML(http.StatusOK, res)
}

func (c *reqCtx) createBucket() {
	if !bucketNameRE.MatchString(c.bucket) {
		c.fail(errf("InvalidBucketName", "The specified bucket is not valid"))
		return
	}
	if err := c.srv.Store.CreateBucket(c.bucket); err != nil {
		c.fail(err)
		return
	}
	c.w.Header().Set("Location", "/"+c.bucket)
	c.w.WriteHeader(http.StatusOK)
}

func (c *reqCtx) headBucket() {
	if _, err := c.srv.Store.HeadBucket(c.bucket); err != nil {
		c.fail(err)
		return
	}
	c.w.Header().Set("x-amz-bucket-region", c.srv.Region)
	c.w.WriteHeader(http.StatusOK)
}

func (c *reqCtx) deleteBucket() {
	if err := c.srv.Store.DeleteBucket(c.bucket); err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusNoContent)
}

type locationConstraint struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
	Region  string   `xml:",chardata"`
}

func (c *reqCtx) getBucketLocation() {
	if _, err := c.srv.Store.HeadBucket(c.bucket); err != nil {
		c.fail(err)
		return
	}
	region := c.srv.Region
	if region == "us-east-1" {
		region = "" // S3 mengembalikan nilai kosong untuk us-east-1
	}
	c.writeXML(http.StatusOK, locationConstraint{Region: region})
}

type versioningConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
}

// getBucketVersioning selalu menjawab "belum pernah diaktifkan"; sebagian
// klien menanyakannya sebelum bekerja.
func (c *reqCtx) getBucketVersioning() {
	if _, err := c.srv.Store.HeadBucket(c.bucket); err != nil {
		c.fail(err)
		return
	}
	c.writeXML(http.StatusOK, versioningConfiguration{})
}

type objectEntry struct {
	Key          string
	LastModified string
	ETag         string
	Size         int64
	StorageClass string
	Owner        *owner `xml:",omitempty"`
}

type commonPrefix struct {
	Prefix string
}

type listObjectsResult struct {
	XMLName        xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name           string
	Prefix         string
	Delimiter      string `xml:",omitempty"`
	MaxKeys        int
	EncodingType   string `xml:",omitempty"`
	IsTruncated    bool
	Contents       []objectEntry
	CommonPrefixes []commonPrefix

	// Khusus V2
	KeyCount              *int   `xml:",omitempty"`
	ContinuationToken     string `xml:",omitempty"`
	NextContinuationToken string `xml:",omitempty"`
	StartAfter            string `xml:",omitempty"`

	// Khusus V1
	Marker     *string
	NextMarker string `xml:",omitempty"`
}

func (c *reqCtx) listObjects(v2 bool) {
	q := c.q
	maxKeys := 1000
	if s := q.Get("max-keys"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			c.fail(errf("InvalidArgument", "Argument max-keys must be an integer between 0 and 2147483647"))
			return
		}
		maxKeys = min(n, 1000)
	}
	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")

	enc := func(s string) string { return s }
	if et := q.Get("encoding-type"); et == "url" {
		enc = func(s string) string { return sigv4.URIEncode(s, false) }
	} else if et != "" {
		c.fail(errf("InvalidArgument", "Invalid Encoding Method specified in Request"))
		return
	}

	res := listObjectsResult{
		Name:         c.bucket,
		Prefix:       enc(prefix),
		Delimiter:    enc(delimiter),
		MaxKeys:      maxKeys,
		EncodingType: q.Get("encoding-type"),
	}

	var marker string
	if v2 {
		marker = q.Get("start-after")
		res.StartAfter = enc(marker)
		if token := q.Get("continuation-token"); token != "" {
			raw, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				c.fail(errf("InvalidArgument", "The continuation token provided is incorrect"))
				return
			}
			marker = string(raw)
			res.ContinuationToken = token
		}
	} else {
		marker = q.Get("marker")
		m := enc(marker)
		res.Marker = &m
	}

	list, err := c.srv.Store.List(c.bucket, prefix, delimiter, marker, maxKeys)
	if err != nil {
		c.fail(err)
		return
	}

	withOwner := !v2 || q.Get("fetch-owner") == "true"
	for _, o := range list.Objects {
		e := objectEntry{
			Key:          enc(o.Key),
			LastModified: fmtTime(o.ModTime),
			ETag:         quote(o.ETag),
			Size:         o.Size,
			StorageClass: storageClassOf(o.StorageClass),
		}
		if withOwner {
			e.Owner = &defaultOwner
		}
		res.Contents = append(res.Contents, e)
	}
	for _, p := range list.CommonPrefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefix{Prefix: enc(p)})
	}
	res.IsTruncated = list.IsTruncated
	if v2 {
		n := len(res.Contents) + len(res.CommonPrefixes)
		res.KeyCount = &n
		if list.IsTruncated {
			res.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(list.NextMarker))
		}
	} else if list.IsTruncated {
		res.NextMarker = enc(list.NextMarker)
	}
	c.writeXML(http.StatusOK, res)
}

type deleteRequest struct {
	Quiet   bool
	Objects []struct {
		Key string
	} `xml:"Object"`
}

type deletedEntry struct {
	Key string
}

type deleteErrorEntry struct {
	Key     string
	Code    string
	Message string
}

type deleteResult struct {
	XMLName xml.Name           `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []deletedEntry     `xml:"Deleted"`
	Errors  []deleteErrorEntry `xml:"Error"`
}

func (c *reqCtx) deleteObjects() {
	var req deleteRequest
	if err := c.readXML(&req); err != nil {
		c.fail(err)
		return
	}
	if len(req.Objects) == 0 || len(req.Objects) > 1000 {
		c.fail(errf("MalformedXML", "The request must contain between 1 and 1000 keys"))
		return
	}
	if _, err := c.srv.Store.HeadBucket(c.bucket); err != nil {
		c.fail(err)
		return
	}
	var res deleteResult
	for _, o := range req.Objects {
		if !c.id.Allows(auth.ActWrite, c.bucket, o.Key) {
			res.Errors = append(res.Errors, deleteErrorEntry{Key: o.Key, Code: errAccessDenied.Code, Message: errAccessDenied.Message})
			continue
		}
		if err := c.srv.Store.DeleteObject(c.bucket, o.Key); err != nil {
			ae := toAPIError(err)
			res.Errors = append(res.Errors, deleteErrorEntry{Key: o.Key, Code: ae.Code, Message: ae.Message})
		} else if !req.Quiet {
			res.Deleted = append(res.Deleted, deletedEntry{Key: o.Key})
		}
	}
	c.writeXML(http.StatusOK, res)
}
