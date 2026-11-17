package s3api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"object-storage/internal/auth"
	"object-storage/internal/s3api"
	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

const (
	accessKey = "testaccess"
	secretKey = "testsecret"
)

var ctx = context.Background()

type env struct {
	url    string
	http   *http.Client
	client *s3.Client // memakai kredensial root
	// clockOffset (nanodetik) memajukan jam pengelola token, untuk menguji
	// kedaluwarsa tanpa menunggu.
	clockOffset *atomic.Int64
	store       *storage.Store
}

func newClient(e *env, ak, sk string) *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(e.url),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(ak, sk, ""),
		HTTPClient:   e.http,
	})
}

func setup(t *testing.T, tls bool, opts ...func(*s3api.Server)) *env {
	t.Helper()
	store, err := storage.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.NewManager(store, bytes.Repeat([]byte{7}, 32), accessKey, secretKey)
	if err != nil {
		t.Fatal(err)
	}
	offset := new(atomic.Int64)
	tokens.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	store.Now = tokens.Now
	handler := &s3api.Server{
		Store:  store,
		Auth:   &sigv4.Verifier{Keys: tokens},
		Tokens: tokens,
		Region: "us-east-1",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, opt := range opts {
		opt(handler)
	}
	var ts *httptest.Server
	if tls {
		ts = httptest.NewTLSServer(handler)
	} else {
		ts = httptest.NewServer(handler)
	}
	t.Cleanup(func() {
		ts.Close()
		store.Close()
	})
	e := &env{url: ts.URL, http: ts.Client(), clockOffset: offset, store: store}
	e.client = newClient(e, accessKey, secretKey)
	if _, err := e.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("uji")}); err != nil {
		t.Fatal(err)
	}
	return e
}

// Setiap skenario dijalankan lewat HTTP dan HTTPS, karena SDK memilih cara
// mengirim body yang berbeda (payload ber-hash vs aws-chunked dengan trailer).
func each(t *testing.T, fn func(t *testing.T, e *env)) {
	for _, tls := range []bool{false, true} {
		name := "http"
		if tls {
			name = "https"
		}
		t.Run(name, func(t *testing.T) { fn(t, setup(t, tls)) })
	}
}

func errCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return fmt.Sprint(err)
}

func put(t *testing.T, e *env, key, data string) {
	t.Helper()
	_, err := e.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String(key), Body: strings.NewReader(data)})
	if err != nil {
		t.Fatalf("put %q: %v", key, err)
	}
}

func get(t *testing.T, e *env, in *s3.GetObjectInput) (*s3.GetObjectOutput, string) {
	t.Helper()
	in.Bucket = aws.String("uji")
	out, err := e.client.GetObject(ctx, in)
	if err != nil {
		t.Fatalf("get %q: %v", *in.Key, err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	return out, string(data)
}

func TestBuckets(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("uji")}); errCode(err) != "BucketAlreadyOwnedByYou" {
			t.Fatalf("err = %v", err)
		}
		if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("Nama_Salah")}); errCode(err) != "InvalidBucketName" {
			t.Fatalf("err = %v", err)
		}
		list, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil || len(list.Buckets) != 1 || *list.Buckets[0].Name != "uji" {
			t.Fatalf("list = %+v, err = %v", list, err)
		}
		if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("uji")}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("tidak-ada")}); err == nil {
			t.Fatal("harus 404")
		}
		put(t, e, "k", "x")
		if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String("uji")}); errCode(err) != "BucketNotEmpty" {
			t.Fatalf("err = %v", err)
		}
		c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("uji"), Key: aws.String("k")})
		if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String("uji")}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestObjects(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		const key = "folder/berkas uji +é.txt"
		_, err := c.PutObject(ctx, &s3.PutObjectInput{
			Bucket:       aws.String("uji"),
			Key:          aws.String(key),
			Body:         strings.NewReader("hello world"),
			ContentType:  aws.String("text/plain"),
			CacheControl: aws.String("max-age=60"),
			Metadata:     map[string]string{"pemilik": "saya"},
		})
		if err != nil {
			t.Fatal(err)
		}

		out, data := get(t, e, &s3.GetObjectInput{Key: aws.String(key)})
		if data != "hello world" || *out.ETag != `"5eb63bbbe01eeed093cb22bb8f5acdc3"` ||
			*out.ContentType != "text/plain" || *out.CacheControl != "max-age=60" || out.Metadata["pemilik"] != "saya" {
			t.Fatalf("get salah: data=%q out=%+v", data, out)
		}

		head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String(key)})
		if err != nil || *head.ContentLength != 11 {
			t.Fatalf("head = %+v, err = %v", head, err)
		}

		for rng, want := range map[string]string{"bytes=0-4": "hello", "bytes=6-": "world", "bytes=-3": "rld", "bytes=6-999": "world"} {
			out, data := get(t, e, &s3.GetObjectInput{Key: aws.String(key), Range: aws.String(rng)})
			if data != want || out.ContentRange == nil {
				t.Errorf("range %s = %q", rng, data)
			}
		}
		_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String(key), Range: aws.String("bytes=50-60")})
		if errCode(err) != "InvalidRange" {
			t.Fatalf("err = %v", err)
		}

		_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String(key), IfMatch: aws.String(`"salah"`)})
		if errCode(err) != "PreconditionFailed" {
			t.Fatalf("err = %v", err)
		}
		_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String(key), IfNoneMatch: out.ETag})
		var re interface{ HTTPStatusCode() int }
		if !errors.As(err, &re) || re.HTTPStatusCode() != http.StatusNotModified {
			t.Fatalf("err = %v", err)
		}

		_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String("tidak-ada")})
		if errCode(err) != "NoSuchKey" {
			t.Fatalf("err = %v", err)
		}
		_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("tidak-ada"), Key: aws.String("k")})
		if errCode(err) != "NoSuchBucket" {
			t.Fatalf("err = %v", err)
		}

		// Salin dengan metadata baru, lalu salin apa adanya.
		_, err = c.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: aws.String("uji"), Key: aws.String("salinan"),
			CopySource:        aws.String("uji/" + sigv4.URIEncode(key, false)),
			MetadataDirective: types.MetadataDirectiveReplace,
			ContentType:       aws.String("application/json"),
		})
		if err != nil {
			t.Fatal(err)
		}
		out, data = get(t, e, &s3.GetObjectInput{Key: aws.String("salinan")})
		if data != "hello world" || *out.ContentType != "application/json" || len(out.Metadata) != 0 {
			t.Fatalf("salinan salah: %q %+v", data, out)
		}
		_, err = c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("salinan2"),
			CopySource: aws.String("/uji/" + sigv4.URIEncode(key, false))})
		if err != nil {
			t.Fatal(err)
		}
		out, _ = get(t, e, &s3.GetObjectInput{Key: aws.String("salinan2")})
		if out.Metadata["pemilik"] != "saya" {
			t.Fatalf("metadata tidak ikut tersalin: %+v", out.Metadata)
		}

		// Object kosong.
		put(t, e, "kosong", "")
		if out, data := get(t, e, &s3.GetObjectInput{Key: aws.String("kosong")}); data != "" || *out.ContentLength != 0 {
			t.Fatalf("object kosong salah")
		}

		// Hapus massal, termasuk key yang tidak ada.
		del, err := c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String("uji"), Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{{Key: aws.String(key)}, {Key: aws.String("salinan")}, {Key: aws.String("tidak-ada")}},
		}})
		if err != nil || len(del.Deleted) != 3 || len(del.Errors) != 0 {
			t.Fatalf("delete = %+v, err = %v", del, err)
		}
		if _, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String(key)}); err == nil {
			t.Fatal("object masih ada setelah dihapus")
		}
	})
}

func TestList(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		for _, k := range []string{"a", "foto/2024/a.jpg", "foto/2025/b.jpg", "foto/c d.jpg", "z"} {
			put(t, e, k, "x")
		}
		collect := func(in *s3.ListObjectsV2Input) (keys, prefixes []string) {
			in.Bucket = aws.String("uji")
			p := s3.NewListObjectsV2Paginator(e.client, in)
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if int(*page.KeyCount) > 2 {
					t.Fatalf("halaman berisi %d entri", *page.KeyCount)
				}
				for _, o := range page.Contents {
					keys = append(keys, *o.Key)
				}
				for _, cp := range page.CommonPrefixes {
					prefixes = append(prefixes, *cp.Prefix)
				}
			}
			return
		}

		keys, _ := collect(&s3.ListObjectsV2Input{MaxKeys: aws.Int32(2)})
		if want := []string{"a", "foto/2024/a.jpg", "foto/2025/b.jpg", "foto/c d.jpg", "z"}; !reflect.DeepEqual(keys, want) {
			t.Fatalf("keys = %v", keys)
		}
		keys, prefixes := collect(&s3.ListObjectsV2Input{MaxKeys: aws.Int32(2), Delimiter: aws.String("/")})
		if !reflect.DeepEqual(keys, []string{"a", "z"}) || !reflect.DeepEqual(prefixes, []string{"foto/"}) {
			t.Fatalf("keys = %v, prefixes = %v", keys, prefixes)
		}
		keys, prefixes = collect(&s3.ListObjectsV2Input{MaxKeys: aws.Int32(2), Delimiter: aws.String("/"),
			Prefix: aws.String("foto/"), EncodingType: types.EncodingTypeUrl})
		// SDK Go tidak men-decode key kalau encoding-type diminta eksplisit.
		if !reflect.DeepEqual(keys, []string{"foto/c%20d.jpg"}) || !reflect.DeepEqual(prefixes, []string{"foto/2024/", "foto/2025/"}) {
			t.Fatalf("keys = %v, prefixes = %v", keys, prefixes)
		}
		keys, _ = collect(&s3.ListObjectsV2Input{MaxKeys: aws.Int32(2), StartAfter: aws.String("foto/2025/b.jpg")})
		if !reflect.DeepEqual(keys, []string{"foto/c d.jpg", "z"}) {
			t.Fatalf("keys = %v", keys)
		}

		// V1 dengan marker.
		v1, err := e.client.ListObjects(ctx, &s3.ListObjectsInput{Bucket: aws.String("uji"), MaxKeys: aws.Int32(2)})
		if err != nil || !*v1.IsTruncated || *v1.NextMarker != "foto/2024/a.jpg" {
			t.Fatalf("v1 = %+v, err = %v", v1, err)
		}
		v1, err = e.client.ListObjects(ctx, &s3.ListObjectsInput{Bucket: aws.String("uji"), Marker: v1.NextMarker})
		if err != nil || len(v1.Contents) != 3 || *v1.IsTruncated {
			t.Fatalf("v1 halaman 2 = %+v, err = %v", v1, err)
		}
	})
}

func TestMultipart(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		data := make([]byte, 12<<20+123)
		rand.Read(data)

		up := manager.NewUploader(c, func(u *manager.Uploader) { u.PartSize = 5 << 20 })
		res, err := up.Upload(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("besar.bin"),
			Body: bytes.NewReader(data), ContentType: aws.String("application/x-uji")})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(strings.Trim(*res.ETag, `"`), "-3") {
			t.Fatalf("etag = %s", *res.ETag)
		}
		out, got := get(t, e, &s3.GetObjectInput{Key: aws.String("besar.bin")})
		if got != string(data) || *out.ContentType != "application/x-uji" {
			t.Fatal("isi atau content-type hasil multipart tidak cocok")
		}
		// Range yang melintasi batas part.
		_, got = get(t, e, &s3.GetObjectInput{Key: aws.String("besar.bin"), Range: aws.String(fmt.Sprintf("bytes=%d-%d", 5<<20-10, 5<<20+9))})
		if got != string(data[5<<20-10:5<<20+10]) {
			t.Fatal("range lintas part tidak cocok")
		}

		// Alur manual: list, salin part dari object lain, abort.
		mp, err := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("manual")})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("uji"), Key: aws.String("manual"),
			UploadId: mp.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("kecil")})
		if err != nil {
			t.Fatal(err)
		}
		cp, err := c.UploadPartCopy(ctx, &s3.UploadPartCopyInput{Bucket: aws.String("uji"), Key: aws.String("manual"),
			UploadId: mp.UploadId, PartNumber: aws.Int32(2), CopySource: aws.String("uji/besar.bin"),
			CopySourceRange: aws.String("bytes=0-99")})
		if err != nil || cp.CopyPartResult.ETag == nil {
			t.Fatalf("upload part copy: %v", err)
		}
		parts, err := c.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String("uji"), Key: aws.String("manual"), UploadId: mp.UploadId})
		if err != nil || len(parts.Parts) != 2 || *parts.Parts[0].Size != 5 || *parts.Parts[1].Size != 100 {
			t.Fatalf("parts = %+v, err = %v", parts, err)
		}
		uploads, err := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String("uji")})
		if err != nil || len(uploads.Uploads) != 1 || *uploads.Uploads[0].Key != "manual" {
			t.Fatalf("uploads = %+v, err = %v", uploads, err)
		}
		// Part pertama terlalu kecil untuk bukan part terakhir.
		_, err = c.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("manual"),
			UploadId: mp.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
				{PartNumber: aws.Int32(1), ETag: parts.Parts[0].ETag}, {PartNumber: aws.Int32(2), ETag: parts.Parts[1].ETag}}}})
		if errCode(err) != "EntityTooSmall" {
			t.Fatalf("err = %v", err)
		}
		if _, err := c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("manual"), UploadId: mp.UploadId}); err != nil {
			t.Fatal(err)
		}
		_, err = c.ListParts(ctx, &s3.ListPartsInput{Bucket: aws.String("uji"), Key: aws.String("manual"), UploadId: mp.UploadId})
		if errCode(err) != "NoSuchUpload" {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestPresigned(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ps := s3.NewPresignClient(e.client)

		putReq, err := ps.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("via url.txt")},
			s3.WithPresignExpires(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(putReq.Method, putReq.URL, strings.NewReader("lewat presigned"))
		resp, err := e.http.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("presigned put: %v %v", resp, err)
		}
		resp.Body.Close()

		getReq, err := ps.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String("via url.txt")},
			s3.WithPresignExpires(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		resp, err = e.http.Get(getReq.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "lewat presigned" {
			t.Fatalf("presigned get: %d %q", resp.StatusCode, body)
		}

		// URL yang diubah harus ditolak.
		resp, err = e.http.Get(strings.Replace(getReq.URL, "via%20url.txt", "lain.txt", 1))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("URL yang diubah mendapat status %d", resp.StatusCode)
		}
	})
}

func TestAuthRejected(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		in := &s3.ListBucketsInput{}
		if _, err := newClient(e, accessKey, "salah").ListBuckets(ctx, in); errCode(err) != "SignatureDoesNotMatch" {
			t.Fatalf("err = %v", err)
		}
		if _, err := newClient(e, "siapa", secretKey).ListBuckets(ctx, in); errCode(err) != "InvalidAccessKeyId" {
			t.Fatalf("err = %v", err)
		}
		resp, err := e.http.Get(e.url + "/uji")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("permintaan anonim mendapat status %d", resp.StatusCode)
		}
		// Secret salah tidak boleh bisa menulis.
		_, err = newClient(e, accessKey, "salah").PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"),
			Key: aws.String("gelap"), Body: strings.NewReader("x")})
		if errCode(err) != "SignatureDoesNotMatch" {
			t.Fatalf("err = %v", err)
		}
		if _, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("gelap")}); err == nil {
			t.Fatal("object tertulis walau signature salah")
		}
	})
}

// Checksum yang salah harus menggagalkan upload dan tidak meninggalkan object.
func TestBadChecksum(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		_, err := e.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("rusak"),
			Body: strings.NewReader("hello world"), ChecksumCRC32: aws.String("AAAAAA==")})
		if errCode(err) != "BadDigest" {
			t.Fatalf("err = %v", err)
		}
		_, err = e.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("rusak"),
			Body: strings.NewReader("hello world"), ContentMD5: aws.String("AAAAAAAAAAAAAAAAAAAAAA==")})
		if errCode(err) != "BadDigest" {
			t.Fatalf("err = %v", err)
		}
		if _, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("rusak")}); err == nil {
			t.Fatal("object tersimpan walau checksum salah")
		}
		// Checksum yang benar diterima, untuk tiap algoritma.
		for _, algo := range []types.ChecksumAlgorithm{types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmCrc32c,
			types.ChecksumAlgorithmCrc64nvme, types.ChecksumAlgorithmSha1, types.ChecksumAlgorithmSha256} {
			_, err := e.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("baik"),
				Body: strings.NewReader("hello world"), ChecksumAlgorithm: algo})
			if err != nil {
				t.Fatalf("%s: %v", algo, err)
			}
		}
	})
}
