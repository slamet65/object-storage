package s3api

import (
	"encoding/xml"
	"net/http"
	"strconv"

	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

type initiateUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string
	Key      string
	UploadId string
}

func (c *reqCtx) createUpload() {
	meta, err := c.metaFromHeaders()
	if err != nil {
		c.fail(err)
		return
	}
	u, err := c.srv.Store.CreateUpload(c.bucket, c.key, meta)
	if err != nil {
		c.fail(err)
		return
	}
	c.writeXML(http.StatusOK, initiateUploadResult{Bucket: c.bucket, Key: c.key, UploadId: u.ID})
}

type copyPartResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
	LastModified string
	ETag         string
}

// uploadPart melayani UploadPart dan UploadPartCopy.
func (c *reqCtx) uploadPart() {
	number, err := strconv.Atoi(c.q.Get("partNumber"))
	if err != nil || number < 1 || number > 10000 {
		c.fail(errf("InvalidArgument", "Part number must be an integer between 1 and 10000, inclusive"))
		return
	}
	id := c.q.Get("uploadId")

	if c.r.Header.Get("X-Amz-Copy-Source") != "" {
		_, _, src, err := c.copySource()
		if err != nil {
			c.fail(err)
			return
		}
		off, length := int64(0), src.Size
		if rng := c.r.Header.Get("X-Amz-Copy-Source-Range"); rng != "" {
			o, l, ok, satisfiable := parseRange(rng, src.Size)
			if !ok || !satisfiable {
				c.fail(errf("InvalidArgument", "The x-amz-copy-source-range value must be of the form bytes=first-last"))
				return
			}
			off, length = o, l
		}
		if length > c.limits.MaxPartSize {
			c.fail(errTooLarge)
			return
		}
		rc := c.srv.Store.OpenRange(src, off, length)
		defer rc.Close()
		part, err := c.srv.Store.PutPart(c.bucket, c.key, id, number, rc, nil)
		if err != nil {
			c.fail(err)
			return
		}
		c.writeXML(http.StatusOK, copyPartResult{LastModified: fmtTime(part.ModTime), ETag: quote(part.ETag)})
		return
	}

	body, checksum, err := c.verifiedBody(c.limits.MaxPartSize)
	if err != nil {
		c.fail(err)
		return
	}
	part, err := c.srv.Store.PutPart(c.bucket, c.key, id, number, body, checksum)
	if err != nil {
		c.fail(err)
		return
	}
	c.w.Header().Set("ETag", quote(part.ETag))
	setChecksumHeader(c.w.Header(), part.Checksum)
	c.w.WriteHeader(http.StatusOK)
}

type completeUploadRequest struct {
	Parts []struct {
		PartNumber int
		ETag       string
	} `xml:"Part"`
}

type completeUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string
	Bucket   string
	Key      string
	ETag     string
	checksumFields
}

func (c *reqCtx) completeUpload() {
	check, err := c.writeCheck()
	if err != nil {
		c.fail(err)
		return
	}
	var req completeUploadRequest
	if err := c.readXML(&req); err != nil {
		c.fail(err)
		return
	}
	parts := make([]storage.CompletedPart, len(req.Parts))
	for i, p := range req.Parts {
		parts[i] = storage.CompletedPart{Number: p.PartNumber, ETag: unquote(p.ETag)}
	}
	info, err := c.srv.Store.CompleteUpload(c.bucket, c.key, c.q.Get("uploadId"), parts, check)
	if err != nil {
		c.fail(err)
		return
	}
	c.w.Header().Set("ETag", quote(info.ETag))
	c.writeXML(http.StatusOK, completeUploadResult{
		Location:       "http://" + c.r.Host + c.r.URL.EscapedPath(),
		Bucket:         c.bucket,
		Key:            c.key,
		ETag:           quote(info.ETag),
		checksumFields: checksumXML(info.Checksum),
	})
}

func (c *reqCtx) abortUpload() {
	if err := c.srv.Store.AbortUpload(c.bucket, c.key, c.q.Get("uploadId")); err != nil {
		c.fail(err)
		return
	}
	c.w.WriteHeader(http.StatusNoContent)
}

type partEntry struct {
	PartNumber   int
	LastModified string
	ETag         string
	Size         int64
	checksumFields
}

type listPartsResult struct {
	XMLName              xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket               string
	Key                  string
	UploadId             string
	StorageClass         string
	PartNumberMarker     int
	NextPartNumberMarker int `xml:",omitempty"`
	MaxParts             int
	IsTruncated          bool
	Parts                []partEntry `xml:"Part"`
}

func (c *reqCtx) listParts() {
	id := c.q.Get("uploadId")
	_, parts, err := c.srv.Store.ListParts(c.bucket, c.key, id)
	if err != nil {
		c.fail(err)
		return
	}
	maxParts := 1000
	if n, err := strconv.Atoi(c.q.Get("max-parts")); err == nil && n > 0 && n < maxParts {
		maxParts = n
	}
	marker, _ := strconv.Atoi(c.q.Get("part-number-marker"))

	res := listPartsResult{Bucket: c.bucket, Key: c.key, UploadId: id, StorageClass: "STANDARD",
		PartNumberMarker: marker, MaxParts: maxParts}
	for _, p := range parts {
		if p.Number <= marker {
			continue
		}
		if len(res.Parts) == maxParts {
			res.IsTruncated = true
			res.NextPartNumberMarker = res.Parts[len(res.Parts)-1].PartNumber
			break
		}
		res.Parts = append(res.Parts, partEntry{PartNumber: p.Number, LastModified: fmtTime(p.ModTime),
			ETag: quote(p.ETag), Size: p.Size, checksumFields: checksumXML(p.Checksum)})
	}
	c.writeXML(http.StatusOK, res)
}

type uploadEntry struct {
	Key          string
	UploadId     string
	Initiated    string
	StorageClass string
}

type listUploadsResult struct {
	XMLName            xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
	Bucket             string
	KeyMarker          string
	UploadIdMarker     string
	NextKeyMarker      string `xml:",omitempty"`
	NextUploadIdMarker string `xml:",omitempty"`
	Prefix             string
	Delimiter          string `xml:",omitempty"`
	EncodingType       string `xml:",omitempty"`
	MaxUploads         int
	IsTruncated        bool
	Uploads            []uploadEntry  `xml:"Upload"`
	CommonPrefixes     []commonPrefix `xml:"CommonPrefixes"`
}

func (c *reqCtx) listUploads() {
	q := c.q
	maxUploads := 1000
	if s := q.Get("max-uploads"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			c.fail(errf("InvalidArgument", "Argument max-uploads must be an integer between 0 and 2147483647"))
			return
		}
		maxUploads = min(n, 1000)
	}
	enc := func(s string) string { return s }
	if et := q.Get("encoding-type"); et == "url" {
		enc = func(s string) string { return sigv4.URIEncode(s, false) }
	} else if et != "" {
		c.fail(errf("InvalidArgument", "Invalid Encoding Method specified in Request"))
		return
	}
	prefix, delimiter := q.Get("prefix"), q.Get("delimiter")
	keyMarker, idMarker := q.Get("key-marker"), q.Get("upload-id-marker")

	list, err := c.srv.Store.ListUploads(c.bucket, prefix, delimiter, keyMarker, idMarker, maxUploads)
	if err != nil {
		c.fail(err)
		return
	}
	res := listUploadsResult{
		Bucket:             c.bucket,
		KeyMarker:          enc(keyMarker),
		UploadIdMarker:     idMarker,
		NextKeyMarker:      enc(list.NextKeyMarker),
		NextUploadIdMarker: list.NextUploadIDMarker,
		Prefix:             enc(prefix),
		Delimiter:          enc(delimiter),
		EncodingType:       q.Get("encoding-type"),
		MaxUploads:         maxUploads,
		IsTruncated:        list.IsTruncated,
	}
	for _, u := range list.Uploads {
		res.Uploads = append(res.Uploads, uploadEntry{Key: enc(u.Key), UploadId: u.ID,
			Initiated: fmtTime(u.Initiated), StorageClass: "STANDARD"})
	}
	for _, p := range list.CommonPrefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefix{Prefix: enc(p)})
	}
	c.writeXML(http.StatusOK, res)
}
