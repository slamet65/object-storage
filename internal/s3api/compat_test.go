package s3api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"object-storage/internal/s3api"
)

func TestConditionalWrite(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		putIf := func(key, data string, ifNoneMatch, ifMatch *string) error {
			_, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String(key),
				Body: strings.NewReader(data), IfNoneMatch: ifNoneMatch, IfMatch: ifMatch})
			return err
		}

		// If-None-Match: * hanya berhasil kalau object belum ada.
		if err := putIf("k", "v1", aws.String("*"), nil); err != nil {
			t.Fatal(err)
		}
		if err := putIf("k", "v2", aws.String("*"), nil); errCode(err) != "PreconditionFailed" {
			t.Fatalf("err = %v", err)
		}
		out, data := get(t, e, &s3.GetObjectInput{Key: aws.String("k")})
		if data != "v1" {
			t.Fatalf("object tertimpa: %q", data)
		}

		// If-Match hanya berhasil kalau ETag masih sama.
		if err := putIf("k", "v3", nil, aws.String(`"salah"`)); errCode(err) != "PreconditionFailed" {
			t.Fatalf("err = %v", err)
		}
		if err := putIf("k", "v3", nil, out.ETag); err != nil {
			t.Fatal(err)
		}
		if err := putIf("k", "v4", nil, out.ETag); errCode(err) != "PreconditionFailed" {
			t.Fatalf("ETag lama masih diterima: %v", err)
		}
		if err := putIf("belum-ada", "x", nil, out.ETag); errCode(err) != "NoSuchKey" {
			t.Fatalf("err = %v", err)
		}
		if _, data := get(t, e, &s3.GetObjectInput{Key: aws.String("k")}); data != "v3" {
			t.Fatalf("isi akhir = %q", data)
		}

		// CompleteMultipartUpload juga menghormati If-None-Match.
		mp, _ := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("k")})
		part, err := c.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("uji"), Key: aws.String("k"),
			UploadId: mp.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("mp")})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("k"),
			UploadId: mp.UploadId, IfNoneMatch: aws.String("*"),
			MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag}}}})
		if errCode(err) != "PreconditionFailed" {
			t.Fatalf("err = %v", err)
		}
		if _, data := get(t, e, &s3.GetObjectInput{Key: aws.String("k")}); data != "v3" {
			t.Fatalf("isi setelah complete yang ditolak = %q", data)
		}
	})
}

func TestCopyConditions(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		put(t, e, "sumber", "isi")
		head, _ := e.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("sumber")})

		_, err := e.client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("tujuan"),
			CopySource: aws.String("uji/sumber"), CopySourceIfMatch: aws.String(`"salah"`)})
		if errCode(err) != "PreconditionFailed" {
			t.Fatalf("err = %v", err)
		}
		_, err = e.client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("tujuan"),
			CopySource: aws.String("uji/sumber"), CopySourceIfNoneMatch: head.ETag})
		if errCode(err) != "PreconditionFailed" {
			t.Fatalf("err = %v", err)
		}
		if _, err := e.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("tujuan")}); err == nil {
			t.Fatal("salinan terbuat walau syarat gagal")
		}
		_, err = e.client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("tujuan"),
			CopySource: aws.String("uji/sumber"), CopySourceIfMatch: head.ETag})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestStoredChecksums(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		const crc32Hello = "DUoRhQ==" // CRC32 dari "hello world"

		putOut, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("k"),
			Body: strings.NewReader("hello world"), ChecksumAlgorithm: types.ChecksumAlgorithmCrc32})
		if err != nil {
			t.Fatal(err)
		}
		if aws.ToString(putOut.ChecksumCRC32) != crc32Hello {
			t.Fatalf("checksum di respons put = %q", aws.ToString(putOut.ChecksumCRC32))
		}

		head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("k"),
			ChecksumMode: types.ChecksumModeEnabled})
		if err != nil || aws.ToString(head.ChecksumCRC32) != crc32Hello || head.ChecksumType != types.ChecksumTypeFullObject {
			t.Fatalf("head = %+v, err = %v", head, err)
		}
		// Tanpa checksum mode, header tidak dikirim.
		head, _ = c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("k")})
		if head.ChecksumCRC32 != nil {
			t.Fatal("checksum dikirim tanpa diminta")
		}
		// SDK memvalidasi checksum ini terhadap isi yang diterima; kalau salah, pembacaan gagal.
		out, data := get(t, e, &s3.GetObjectInput{Key: aws.String("k"), ChecksumMode: types.ChecksumModeEnabled})
		if data != "hello world" || aws.ToString(out.ChecksumCRC32) != crc32Hello {
			t.Fatalf("get: %q %q", data, aws.ToString(out.ChecksumCRC32))
		}
		// Untuk rentang, checksum seluruh object tidak boleh dikirim.
		out, _ = get(t, e, &s3.GetObjectInput{Key: aws.String("k"), Range: aws.String("bytes=0-4"), ChecksumMode: types.ChecksumModeEnabled})
		if out.ChecksumCRC32 != nil {
			t.Fatal("checksum dikirim untuk rentang")
		}

		// Salinan membawa checksum sumbernya.
		if _, err := c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("salinan"), CopySource: aws.String("uji/k")}); err != nil {
			t.Fatal(err)
		}
		head, _ = c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("salinan"), ChecksumMode: types.ChecksumModeEnabled})
		if aws.ToString(head.ChecksumCRC32) != crc32Hello {
			t.Fatalf("checksum salinan = %q", aws.ToString(head.ChecksumCRC32))
		}

		// Multipart: checksum tiap part tersimpan, object mendapat checksum gabungan.
		data2 := make([]byte, 6<<20)
		rand.Read(data2)
		up := manager.NewUploader(c, func(u *manager.Uploader) { u.PartSize = 5 << 20 })
		if _, err := up.Upload(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("mp"),
			Body: bytes.NewReader(data2), ChecksumAlgorithm: types.ChecksumAlgorithmSha256}); err != nil {
			t.Fatal(err)
		}
		head, err = c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("mp"), ChecksumMode: types.ChecksumModeEnabled})
		if err != nil || !strings.HasSuffix(aws.ToString(head.ChecksumSHA256), "-2") || head.ChecksumType != types.ChecksumTypeComposite {
			t.Fatalf("head multipart = %+v, err = %v", head, err)
		}
		if _, got := get(t, e, &s3.GetObjectInput{Key: aws.String("mp"), ChecksumMode: types.ChecksumModeEnabled}); got != string(data2) {
			t.Fatal("isi multipart tidak cocok")
		}
	})
}

func TestPartNumber(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		data := make([]byte, 5<<20+1000)
		rand.Read(data)
		up := manager.NewUploader(c, func(u *manager.Uploader) { u.PartSize = 5 << 20 })
		if _, err := up.Upload(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("mp"), Body: bytes.NewReader(data)}); err != nil {
			t.Fatal(err)
		}
		out, got := get(t, e, &s3.GetObjectInput{Key: aws.String("mp"), PartNumber: aws.Int32(2)})
		if got != string(data[5<<20:]) || aws.ToInt32(out.PartsCount) != 2 ||
			aws.ToString(out.ContentRange) != fmt.Sprintf("bytes %d-%d/%d", 5<<20, len(data)-1, len(data)) {
			t.Fatalf("part 2: panjang %d, parts %d, range %q", len(got), aws.ToInt32(out.PartsCount), aws.ToString(out.ContentRange))
		}
		head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("mp"), PartNumber: aws.Int32(1)})
		if err != nil || aws.ToInt64(head.ContentLength) != 5<<20 {
			t.Fatalf("head part 1 = %+v, err = %v", head, err)
		}
		_, err = c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String("mp"), PartNumber: aws.Int32(3)})
		if errCode(err) != "InvalidPartNumber" {
			t.Fatalf("err = %v", err)
		}

		// Object biasa dianggap punya satu part.
		put(t, e, "biasa", "abc")
		if _, got := get(t, e, &s3.GetObjectInput{Key: aws.String("biasa"), PartNumber: aws.Int32(1)}); got != "abc" {
			t.Fatalf("part 1 object biasa = %q", got)
		}
	})
}

func TestLimits(t *testing.T) {
	small := func(s *s3api.Server) {
		s.Limits = s3api.Limits{MaxPutSize: 1 << 20, MaxPartSize: 6 << 20, MaxMetadataSize: 100}
		s.Store.MaxBuckets = 2
	}
	for _, tls := range []bool{false, true} {
		t.Run(fmt.Sprint("tls=", tls), func(t *testing.T) {
			e := setup(t, tls, small)
			c := e.client

			big := make([]byte, 1<<20+1)
			_, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("besar"), Body: bytes.NewReader(big)})
			if errCode(err) != "EntityTooLarge" {
				t.Fatalf("err = %v", err)
			}
			if _, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("besar")}); err == nil {
				t.Fatal("object terlalu besar tetap tersimpan")
			}
			if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("pas"), Body: bytes.NewReader(big[:1<<20])}); err != nil {
				t.Fatalf("object tepat di batas ditolak: %v", err)
			}

			_, err = c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("meta"),
				Body: strings.NewReader("x"), Metadata: map[string]string{"catatan": strings.Repeat("a", 100)}})
			if errCode(err) != "MetadataTooLarge" {
				t.Fatalf("err = %v", err)
			}

			if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("kedua")}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("ketiga")}); errCode(err) != "TooManyBuckets" {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestListUploadsPagination(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		for _, k := range []string{"a", "a", "dir/x", "dir/y", "z"} {
			if _, err := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String(k)}); err != nil {
				t.Fatal(err)
			}
		}
		var keys, prefixes []string
		p := s3.NewListMultipartUploadsPaginator(c, &s3.ListMultipartUploadsInput{Bucket: aws.String("uji"),
			MaxUploads: aws.Int32(2), Delimiter: aws.String("/")})
		pages := 0
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pages++
			for _, u := range page.Uploads {
				keys = append(keys, *u.Key)
			}
			for _, cp := range page.CommonPrefixes {
				prefixes = append(prefixes, *cp.Prefix)
			}
		}
		if strings.Join(keys, ",") != "a,a,z" || strings.Join(prefixes, ",") != "dir/" || pages != 2 {
			t.Fatalf("keys = %v, prefixes = %v, halaman = %d", keys, prefixes, pages)
		}
	})
}

func TestHealth(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		resp, err := e.http.Get(e.url + s3api.HealthPath)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
			t.Fatalf("status %d, body %q", resp.StatusCode, body)
		}
	})
}

// Virtual-hosted-style: bucket diambil dari subdomain. Semua nama host
// diarahkan ke server test lewat dialer khusus, jadi tidak perlu DNS.
func TestVirtualHost(t *testing.T) {
	e := setup(t, false, func(s *s3api.Server) { s.Domain = "s3.contoh.test" })
	u, _ := url.Parse(e.url)
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, u.Host)
		},
	}}
	c := s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String("http://s3.contoh.test:" + u.Port()),
		Credentials:  credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		HTTPClient:   hc,
	})

	if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("dir/berkas.txt"), Body: strings.NewReader("lewat vhost")}); err != nil {
		t.Fatal(err)
	}
	out, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String("dir/berkas.txt")})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if string(data) != "lewat vhost" {
		t.Fatalf("data = %q", data)
	}
	list, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("uji")})
	if err != nil || len(list.Contents) != 1 || *list.Contents[0].Key != "dir/berkas.txt" {
		t.Fatalf("list = %+v, err = %v", list, err)
	}
	// Object yang sama terlihat lewat path-style.
	if _, got := get(t, e, &s3.GetObjectInput{Key: aws.String("dir/berkas.txt")}); got != "lewat vhost" {
		t.Fatalf("path-style = %q", got)
	}
	// Daftar bucket tetap lewat host dasar.
	buckets, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil || len(buckets.Buckets) != 1 {
		t.Fatalf("buckets = %+v, err = %v", buckets, err)
	}
}
