package s3api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"object-storage/internal/auth"
	"object-storage/internal/s3api"
	"object-storage/internal/sigv4"
)

type creds struct{ access, secret, session string }

var root = creds{access: accessKey, secret: secretKey}

func (e *env) as(c creds) *s3.Client {
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(e.url),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(c.access, c.secret, c.session),
		HTTPClient:   e.http,
	})
}

// admin memanggil API admin dengan kredensial c dan mengembalikan status
// serta body JSON yang sudah di-parse.
func (e *env) admin(t *testing.T, c creds, method, path string, in any) (int, map[string]any) {
	t.Helper()
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	req, err := http.NewRequest(method, e.url+s3api.AdminPrefix+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	sigv4.SignRequest(req, c.access, c.secret, c.session, "us-east-1", sigv4.HashPayload(body), time.Now())
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("respons bukan JSON: %q", raw)
		}
	}
	return resp.StatusCode, out
}

func (e *env) newToken(t *testing.T, perm auth.Permission, buckets ...string) creds {
	t.Helper()
	status, out := e.admin(t, root, "POST", "tokens", map[string]any{"name": "uji", "permission": perm, "buckets": buckets})
	if status != http.StatusCreated {
		t.Fatalf("buat token: status %d %v", status, out)
	}
	return creds{access: out["access_key_id"].(string), secret: out["secret_access_key"].(string)}
}

func (e *env) tempCreds(t *testing.T, parent creds, in map[string]any) creds {
	t.Helper()
	status, out := e.admin(t, parent, "POST", "temp-credentials", in)
	if status != http.StatusCreated {
		t.Fatalf("kredensial sementara: status %d %v", status, out)
	}
	return creds{access: out["access_key_id"].(string), secret: out["secret_access_key"].(string), session: out["session_token"].(string)}
}

func putAs(c *s3.Client, bucket, key string) error {
	_, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader("x")})
	return err
}

func getAs(c *s3.Client, bucket, key string) error {
	out, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err == nil {
		out.Body.Close()
	}
	return err
}

func TestPermissions(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		put(t, e, "k", "isi")
		ro := e.as(e.newToken(t, auth.ObjectRead))
		rw := e.as(e.newToken(t, auth.ObjectReadWrite))
		adminRO := e.as(e.newToken(t, auth.AdminRead))
		adminRW := e.as(e.newToken(t, auth.AdminReadWrite))

		// Baca: semua tingkat boleh.
		for name, c := range map[string]*s3.Client{"ro": ro, "rw": rw, "adminRO": adminRO, "adminRW": adminRW} {
			if err := getAs(c, "uji", "k"); err != nil {
				t.Errorf("%s get: %v", name, err)
			}
			if _, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("uji")}); err != nil {
				t.Errorf("%s list: %v", name, err)
			}
		}

		// Tulis object: hanya yang baca-tulis.
		for name, c := range map[string]*s3.Client{"ro": ro, "adminRO": adminRO} {
			if err := putAs(c, "uji", "baru"); errCode(err) != "AccessDenied" {
				t.Errorf("%s put: %v", name, err)
			}
			_, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("uji"), Key: aws.String("k")})
			if errCode(err) != "AccessDenied" {
				t.Errorf("%s delete: %v", name, err)
			}
			_, err = c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("mp")})
			if errCode(err) != "AccessDenied" {
				t.Errorf("%s multipart: %v", name, err)
			}
			del, err := c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String("uji"),
				Delete: &types.Delete{Objects: []types.ObjectIdentifier{{Key: aws.String("k")}}}})
			if err != nil || len(del.Errors) != 1 || aws.ToString(del.Errors[0].Code) != "AccessDenied" {
				t.Errorf("%s delete massal: %+v %v", name, del, err)
			}
		}
		if err := getAs(ro, "uji", "k"); err != nil {
			t.Fatalf("object terhapus oleh token baca-saja: %v", err)
		}
		if err := putAs(rw, "uji", "baru"); err != nil {
			t.Errorf("rw put: %v", err)
		}

		// Operasi bucket: hanya admin baca-tulis.
		for name, c := range map[string]*s3.Client{"ro": ro, "rw": rw, "adminRO": adminRO} {
			if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("bucket-baru")}); errCode(err) != "AccessDenied" {
				t.Errorf("%s create bucket: %v", name, err)
			}
			if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String("uji")}); errCode(err) != "AccessDenied" {
				t.Errorf("%s delete bucket: %v", name, err)
			}
		}
		if _, err := adminRW.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("bucket-baru")}); err != nil {
			t.Errorf("adminRW create bucket: %v", err)
		}
	})
}

func TestBucketScope(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		e.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("lain")})
		put(t, e, "k", "isi")
		e.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("lain"), Key: aws.String("rahasia"), Body: strings.NewReader("x")})

		c := e.as(e.newToken(t, auth.AdminReadWrite, "uji"))
		if err := getAs(c, "uji", "k"); err != nil {
			t.Fatal(err)
		}
		// Bucket di luar cakupan: semua ditolak, termasuk untuk yang tidak ada,
		// supaya keberadaannya tidak bisa ditebak.
		if err := getAs(c, "lain", "rahasia"); errCode(err) != "AccessDenied" {
			t.Errorf("get: %v", err)
		}
		if err := getAs(c, "tidak-ada", "k"); errCode(err) != "AccessDenied" {
			t.Errorf("get bucket tak ada: %v", err)
		}
		if err := putAs(c, "lain", "k"); errCode(err) != "AccessDenied" {
			t.Errorf("put: %v", err)
		}
		if _, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("lain")}); errCode(err) != "AccessDenied" {
			t.Errorf("list: %v", err)
		}
		if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("lain")}); err == nil {
			t.Error("head bucket di luar cakupan berhasil")
		}
		if _, err := c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String("lain")}); errCode(err) != "AccessDenied" {
			t.Errorf("delete bucket: %v", err)
		}
		// Menyalin dari bucket di luar cakupan juga ditolak.
		_, err := c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("curian"), CopySource: aws.String("lain/rahasia")})
		if errCode(err) != "AccessDenied" {
			t.Errorf("copy: %v", err)
		}
		// Daftar bucket hanya menampilkan yang ada dalam cakupan.
		list, err := c.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil || len(list.Buckets) != 1 || *list.Buckets[0].Name != "uji" {
			t.Errorf("list buckets = %+v, err = %v", list.Buckets, err)
		}
	})
}

func TestTempCredentialsEndToEnd(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		for _, k := range []string{"foto/a.jpg", "foto/b.jpg", "dok/satu.txt", "dok/dua.txt"} {
			put(t, e, k, "isi")
		}
		parent := e.newToken(t, auth.ObjectReadWrite, "uji")

		tmp := e.tempCreds(t, parent, map[string]any{"ttl_seconds": 600, "permission": "object-read",
			"prefixes": []string{"foto/"}, "objects": []string{"dok/satu.txt"}})
		c := e.as(tmp)

		if err := getAs(c, "uji", "foto/a.jpg"); err != nil {
			t.Errorf("get dalam prefix: %v", err)
		}
		if err := getAs(c, "uji", "dok/satu.txt"); err != nil {
			t.Errorf("get object yang diizinkan: %v", err)
		}
		if err := getAs(c, "uji", "dok/dua.txt"); errCode(err) != "AccessDenied" {
			t.Errorf("get di luar cakupan: %v", err)
		}
		if err := putAs(c, "uji", "foto/c.jpg"); errCode(err) != "AccessDenied" {
			t.Errorf("put dengan izin baca: %v", err)
		}
		if _, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("uji"), Prefix: aws.String("foto/")}); err != nil {
			t.Errorf("list dalam prefix: %v", err)
		}
		if _, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("uji")}); errCode(err) != "AccessDenied" {
			t.Errorf("list seluruh bucket: %v", err)
		}

		// Presigned URL dari kredensial sementara membawa session token di query.
		ps := s3.NewPresignClient(c)
		req, err := ps.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String("foto/a.jpg")})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := e.http.Get(req.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("presigned dengan kredensial sementara: status %d", resp.StatusCode)
		}

		// Session token wajib: tanpa token, access key sementara tidak dikenal.
		if err := getAs(e.as(creds{access: tmp.access, secret: tmp.secret}), "uji", "foto/a.jpg"); errCode(err) != "InvalidAccessKeyId" {
			t.Errorf("tanpa session token: %v", err)
		}

		// Permintaan yang melebihi induk ditolak.
		if status, out := e.admin(t, parent, "POST", "temp-credentials", map[string]any{"ttl_seconds": 600, "permission": "admin-read"}); status != http.StatusBadRequest {
			t.Errorf("izin melebihi induk: status %d %v", status, out)
		}
		if status, out := e.admin(t, parent, "POST", "temp-credentials", map[string]any{"ttl_seconds": 600, "permission": "object-read", "buckets": []string{"lain"}}); status != http.StatusBadRequest {
			t.Errorf("bucket di luar induk: status %d %v", status, out)
		}
		// Kredensial sementara tidak bisa menerbitkan kredensial lain.
		if status, _ := e.admin(t, tmp, "POST", "temp-credentials", map[string]any{"ttl_seconds": 60, "permission": "object-read"}); status != http.StatusBadRequest {
			t.Errorf("penerbitan berantai: status %d", status)
		}

		// Kedaluwarsa: majukan jam server melewati TTL.
		e.clockOffset.Store(int64(11 * time.Minute))
		if err := getAs(c, "uji", "foto/a.jpg"); errCode(err) != "ExpiredToken" {
			t.Errorf("setelah TTL: %v", err)
		}
		e.clockOffset.Store(0)

		// Mencabut induk langsung menggugurkan kredensial sementara.
		if status, _ := e.admin(t, root, "DELETE", "tokens/"+parent.access, nil); status != http.StatusNoContent {
			t.Fatalf("hapus token: status %d", status)
		}
		if err := getAs(c, "uji", "foto/a.jpg"); errCode(err) != "InvalidToken" {
			t.Errorf("setelah induk dicabut: %v", err)
		}
		if err := getAs(e.as(parent), "uji", "foto/a.jpg"); errCode(err) != "InvalidAccessKeyId" {
			t.Errorf("token yang dicabut: %v", err)
		}
	})
}

func TestAdminAPI(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		tok := e.newToken(t, auth.ObjectReadWrite, "uji")

		// Daftar tidak pernah memuat secret.
		status, out := e.admin(t, root, "GET", "tokens", nil)
		list := out["tokens"].([]any)
		if status != http.StatusOK || len(list) != 1 {
			t.Fatalf("list: status %d %v", status, out)
		}
		entry := list[0].(map[string]any)
		if entry["id"] != tok.access || entry["secret_access_key"] != nil || entry["secret_enc"] != nil {
			t.Fatalf("entri daftar = %v", entry)
		}

		status, out = e.admin(t, root, "GET", "whoami", nil)
		if status != http.StatusOK || out["token_id"] != "root" || out["permission"] != "admin-read-write" {
			t.Fatalf("whoami root: %d %v", status, out)
		}
		status, out = e.admin(t, tok, "GET", "whoami", nil)
		if status != http.StatusOK || out["token_id"] != tok.access || out["permission"] != "object-read-write" {
			t.Fatalf("whoami token: %d %v", status, out)
		}

		// Token non-admin, admin baca-saja, dan admin berlingkup bucket tidak boleh mengelola token.
		adminRO := e.newToken(t, auth.AdminRead)
		scopedAdmin := e.newToken(t, auth.AdminReadWrite, "uji")
		for name, c := range map[string]creds{"object": tok, "adminRO": adminRO, "scopedAdmin": scopedAdmin} {
			if status, _ := e.admin(t, c, "POST", "tokens", map[string]any{"permission": "admin-read-write"}); status != http.StatusForbidden {
				t.Errorf("%s membuat token: status %d", name, status)
			}
			if status, _ := e.admin(t, c, "DELETE", "tokens/"+tok.access, nil); status != http.StatusForbidden {
				t.Errorf("%s menghapus token: status %d", name, status)
			}
		}
		if status, _ := e.admin(t, tok, "GET", "tokens", nil); status != http.StatusForbidden {
			t.Errorf("token object melihat daftar: status %d", status)
		}
		if status, _ := e.admin(t, adminRO, "GET", "tokens", nil); status != http.StatusOK {
			t.Errorf("admin baca-saja melihat daftar: status %d", status)
		}

		// Masukan tidak valid.
		if status, _ := e.admin(t, root, "POST", "tokens", map[string]any{"permission": "ngawur"}); status != http.StatusBadRequest {
			t.Errorf("izin tak dikenal: status %d", status)
		}
		if status, _ := e.admin(t, root, "POST", "tokens", map[string]any{"permission": "object-read", "salah_ketik": 1}); status != http.StatusBadRequest {
			t.Errorf("field tak dikenal: status %d", status)
		}
		if status, _ := e.admin(t, root, "DELETE", "tokens/tidak-ada", nil); status != http.StatusNotFound {
			t.Errorf("hapus token tak ada: status %d", status)
		}
		// Tanpa signature, API admin tertutup.
		resp, err := e.http.Get(e.url + s3api.AdminPrefix + "tokens")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("anonim: status %d", resp.StatusCode)
		}

		// Nonaktifkan, aktifkan lagi, rotasi.
		c := e.as(tok)
		e.admin(t, root, "POST", "tokens/"+tok.access+"/disable", nil)
		if err := getAs(c, "uji", "x"); errCode(err) != "InvalidAccessKeyId" {
			t.Errorf("token nonaktif: %v", err)
		}
		e.admin(t, root, "POST", "tokens/"+tok.access+"/enable", nil)
		if err := putAs(c, "uji", "x"); err != nil {
			t.Errorf("token aktif lagi: %v", err)
		}
		status, out = e.admin(t, root, "POST", "tokens/"+tok.access+"/rotate", nil)
		if status != http.StatusOK || out["secret_access_key"] == nil || out["secret_access_key"] == tok.secret {
			t.Fatalf("rotate: %d %v", status, out)
		}
		if err := getAs(c, "uji", "x"); errCode(err) != "SignatureDoesNotMatch" {
			t.Errorf("secret lama setelah rotasi: %v", err)
		}
		rotated := creds{access: tok.access, secret: out["secret_access_key"].(string)}
		if err := getAs(e.as(rotated), "uji", "x"); err != nil {
			t.Errorf("secret baru: %v", err)
		}
	})
}
