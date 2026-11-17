package s3api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"object-storage/internal/auth"
	"object-storage/internal/lifecycle"
)

// do mengirim permintaan mentah (tanpa signature) dengan header tambahan.
func (e *env) do(t *testing.T, method, url string, headers map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestCORS(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		const origin = "https://app.contoh.test"

		if _, err := c.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: aws.String("uji")}); errCode(err) != "NoSuchCORSConfiguration" {
			t.Fatalf("err = %v", err)
		}
		_, err := c.PutBucketCors(ctx, &s3.PutBucketCorsInput{Bucket: aws.String("uji"), CORSConfiguration: &types.CORSConfiguration{
			CORSRules: []types.CORSRule{{
				AllowedOrigins: []string{"https://*.contoh.test"},
				AllowedMethods: []string{"GET", "PUT"},
				AllowedHeaders: []string{"content-type", "x-amz-*"},
				ExposeHeaders:  []string{"ETag"},
				MaxAgeSeconds:  aws.Int32(600),
			}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: aws.String("uji")})
		if err != nil || len(got.CORSRules) != 1 || got.CORSRules[0].AllowedMethods[1] != "PUT" || aws.ToInt32(got.CORSRules[0].MaxAgeSeconds) != 600 {
			t.Fatalf("cors = %+v, err = %v", got, err)
		}
		_, err = c.PutBucketCors(ctx, &s3.PutBucketCorsInput{Bucket: aws.String("uji"), CORSConfiguration: &types.CORSConfiguration{
			CORSRules: []types.CORSRule{{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"PATCH"}}}}})
		if errCode(err) != "InvalidRequest" {
			t.Fatalf("method tak dikenal: %v", err)
		}

		// Preflight yang diizinkan, tanpa autentikasi.
		resp := e.do(t, "OPTIONS", e.url+"/uji/foto.jpg", map[string]string{
			"Origin": origin, "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "Content-Type, X-Amz-Date"}, "")
		h := resp.Header
		if resp.StatusCode != 200 || h.Get("Access-Control-Allow-Origin") != origin || h.Get("Access-Control-Allow-Methods") != "GET, PUT" ||
			h.Get("Access-Control-Allow-Headers") != "Content-Type, X-Amz-Date" || h.Get("Access-Control-Max-Age") != "600" {
			t.Fatalf("preflight: %d %v", resp.StatusCode, h)
		}
		// Preflight yang ditolak: origin lain, method lain, header lain, bucket lain.
		denied := []map[string]string{
			{"Origin": "https://jahat.test", "Access-Control-Request-Method": "PUT"},
			{"Origin": origin, "Access-Control-Request-Method": "DELETE"},
			{"Origin": origin, "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "Authorization"},
		}
		for i, headers := range denied {
			if resp := e.do(t, "OPTIONS", e.url+"/uji/foto.jpg", headers, ""); resp.StatusCode != 403 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("preflight %d seharusnya ditolak: %d", i, resp.StatusCode)
			}
		}
		if resp := e.do(t, "OPTIONS", e.url+"/tidak-ada/k", map[string]string{"Origin": origin, "Access-Control-Request-Method": "GET"}, ""); resp.StatusCode != 403 {
			t.Errorf("preflight ke bucket tak ada: %d", resp.StatusCode)
		}

		// Upload dari browser lewat presigned URL: respons membawa header CORS.
		ps := s3.NewPresignClient(c)
		putReq, _ := ps.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("foto.jpg")})
		resp = e.do(t, "PUT", putReq.URL, map[string]string{"Origin": origin}, "isi foto")
		if resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != origin ||
			resp.Header.Get("Access-Control-Expose-Headers") != "ETag" || resp.Header.Get("ETag") == "" {
			t.Fatalf("presigned put dari browser: %d %v", resp.StatusCode, resp.Header)
		}
		getReq, _ := ps.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("uji"), Key: aws.String("foto.jpg")})
		// Origin yang tidak diizinkan tetap dilayani, tetapi tanpa header CORS,
		// sehingga browser menolak membacanya.
		if resp := e.do(t, "GET", getReq.URL, map[string]string{"Origin": "https://jahat.test"}, ""); resp.StatusCode != 200 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("origin lain: %d %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
		// Respons error pun membawa header CORS, supaya skrip bisa membaca pesannya.
		if resp := e.do(t, "GET", e.url+"/uji/foto.jpg", map[string]string{"Origin": origin}, ""); resp.StatusCode != 403 || resp.Header.Get("Access-Control-Allow-Origin") != origin {
			t.Errorf("error dengan CORS: %d %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}

		if _, err := c.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: aws.String("uji")}); err != nil {
			t.Fatal(err)
		}
		if resp := e.do(t, "OPTIONS", e.url+"/uji/foto.jpg", map[string]string{"Origin": origin, "Access-Control-Request-Method": "PUT"}, ""); resp.StatusCode != 403 {
			t.Errorf("preflight setelah CORS dihapus: %d", resp.StatusCode)
		}
	})
}

func TestPublicBucket(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		put(t, e, "dir/halo.txt", "halo dunia")
		body := func(resp *http.Response) string {
			b, _ := io.ReadAll(resp.Body)
			return string(b)
		}

		// Bucket privat: semua akses anonim ditolak.
		if resp := e.do(t, "GET", e.url+"/uji/dir/halo.txt", nil, ""); resp.StatusCode != 403 {
			t.Fatalf("bucket privat: %d", resp.StatusCode)
		}

		status, out := e.admin(t, root, "PUT", "buckets/uji/public", map[string]any{"public": true, "domains": []string{"CDN.Contoh.Test"}})
		if status != 200 || out["public"] != true {
			t.Fatalf("set public: %d %v", status, out)
		}

		// Baca object anonim: boleh, lewat path-style maupun custom domain.
		resp := e.do(t, "GET", e.url+"/uji/dir/halo.txt", nil, "")
		if resp.StatusCode != 200 || body(resp) != "halo dunia" {
			t.Fatalf("get anonim: %d", resp.StatusCode)
		}
		if resp := e.do(t, "HEAD", e.url+"/uji/dir/halo.txt", nil, ""); resp.StatusCode != 200 || resp.Header.Get("Content-Length") != "10" {
			t.Errorf("head anonim: %d", resp.StatusCode)
		}
		resp = e.do(t, "GET", e.url+"/dir/halo.txt", map[string]string{"Host": "cdn.contoh.test"}, "")
		if resp.StatusCode != 200 || body(resp) != "halo dunia" {
			t.Errorf("custom domain: %d", resp.StatusCode)
		}
		if resp := e.do(t, "GET", e.url+"/uji/dir/halo.txt", map[string]string{"Range": "bytes=0-3"}, ""); resp.StatusCode != 206 || body(resp) != "halo" {
			t.Errorf("range anonim: %d", resp.StatusCode)
		}
		if resp := e.do(t, "GET", e.url+"/uji/tidak-ada", nil, ""); resp.StatusCode != 404 {
			t.Errorf("object tak ada: %d", resp.StatusCode)
		}

		// Yang tetap tertutup untuk anonim: listing, tulis, hapus, multipart, bucket lain.
		closed := []struct{ method, url string }{
			{"GET", e.url + "/uji"},
			{"GET", e.url + "/uji?list-type=2"},
			{"GET", e.url + "/uji?uploads"},
			{"GET", e.url + "/"},
			{"PUT", e.url + "/uji/baru.txt"},
			{"DELETE", e.url + "/uji/dir/halo.txt"},
			{"POST", e.url + "/uji/mp?uploads"},
			{"GET", e.url + "/uji/dir/halo.txt?uploadId=x"},
		}
		for _, c := range closed {
			if resp := e.do(t, c.method, c.url, nil, "x"); resp.StatusCode != 403 {
				t.Errorf("%s %s anonim: %d", c.method, c.url, resp.StatusCode)
			}
		}
		if resp := e.do(t, "GET", e.url+"/", map[string]string{"Host": "cdn.contoh.test"}, ""); resp.StatusCode != 403 {
			t.Errorf("listing lewat custom domain: %d", resp.StatusCode)
		}
		if _, data := get(t, e, &s3.GetObjectInput{Key: aws.String("dir/halo.txt")}); data != "halo dunia" {
			t.Error("object berubah oleh permintaan anonim")
		}

		// Domain yang sama tidak bisa dipakai bucket lain; nama tidak valid ditolak.
		e.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("lain")})
		if status, _ := e.admin(t, root, "PUT", "buckets/lain/public", map[string]any{"public": true, "domains": []string{"cdn.contoh.test"}}); status != 409 {
			t.Errorf("domain ganda: %d", status)
		}
		if status, _ := e.admin(t, root, "PUT", "buckets/lain/public", map[string]any{"public": true, "domains": []string{"bukan domain"}}); status != 400 {
			t.Errorf("domain tidak valid: %d", status)
		}
		// Token object dan admin di luar cakupan tidak boleh mengubahnya.
		for name, c := range map[string]creds{"object": e.newToken(t, auth.ObjectReadWrite), "adminLain": e.newToken(t, auth.AdminReadWrite, "lain")} {
			if status, _ := e.admin(t, c, "PUT", "buckets/uji/public", map[string]any{"public": false}); status != 403 {
				t.Errorf("%s mengubah akses publik: %d", name, status)
			}
		}

		// Menutup lagi berlaku seketika, termasuk lewat custom domain yang dilepas.
		e.admin(t, root, "PUT", "buckets/uji/public", map[string]any{"public": false})
		if resp := e.do(t, "GET", e.url+"/uji/dir/halo.txt", nil, ""); resp.StatusCode != 403 {
			t.Errorf("setelah ditutup: %d", resp.StatusCode)
		}
		if resp := e.do(t, "GET", e.url+"/dir/halo.txt", map[string]string{"Host": "cdn.contoh.test"}, ""); resp.StatusCode == 200 {
			t.Error("custom domain masih melayani setelah dilepas")
		}
	})
}

func TestLifecycleAPI(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		if _, err := c.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String("uji")}); errCode(err) != "NoSuchLifecycleConfiguration" {
			t.Fatalf("err = %v", err)
		}
		putRules := func(rules ...types.LifecycleRule) error {
			_, err := c.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{Bucket: aws.String("uji"),
				LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: rules}})
			return err
		}
		err := putRules(
			types.LifecycleRule{ID: aws.String("log"), Status: types.ExpirationStatusEnabled,
				Filter:     &types.LifecycleRuleFilter{Prefix: aws.String("log/")},
				Expiration: &types.LifecycleExpiration{Days: aws.Int32(7)}},
			types.LifecycleRule{ID: aws.String("ia"), Status: types.ExpirationStatusEnabled,
				Filter:                         &types.LifecycleRuleFilter{Prefix: aws.String("")},
				Transitions:                    []types.Transition{{Days: aws.Int32(30), StorageClass: types.TransitionStorageClassStandardIa}},
				AbortIncompleteMultipartUpload: &types.AbortIncompleteMultipartUpload{DaysAfterInitiation: aws.Int32(3)}},
		)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String("uji")})
		if err != nil || len(got.Rules) != 2 {
			t.Fatalf("rules = %+v, err = %v", got, err)
		}
		r0, r1 := got.Rules[0], got.Rules[1]
		if *r0.ID != "log" || aws.ToString(r0.Filter.Prefix) != "log/" || aws.ToInt32(r0.Expiration.Days) != 7 ||
			len(r1.Transitions) != 1 || r1.Transitions[0].StorageClass != types.TransitionStorageClassStandardIa ||
			aws.ToInt32(r1.AbortIncompleteMultipartUpload.DaysAfterInitiation) != 3 {
			t.Fatalf("aturan tidak kembali utuh: %+v %+v", r0, r1)
		}

		// Aturan yang tidak didukung atau tidak valid ditolak dan tidak mengubah konfigurasi.
		bad := map[string]types.LifecycleRule{
			"NotImplemented": {ID: aws.String("x"), Status: types.ExpirationStatusEnabled,
				Filter:     &types.LifecycleRuleFilter{Tag: &types.Tag{Key: aws.String("a"), Value: aws.String("b")}},
				Expiration: &types.LifecycleExpiration{Days: aws.Int32(1)}},
			"InvalidStorageClass": {ID: aws.String("x"), Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{Prefix: aws.String("")},
				Transitions: []types.Transition{{Days: aws.Int32(1), StorageClass: types.TransitionStorageClassGlacier}}},
			"MalformedXML": {ID: aws.String("x"), Status: types.ExpirationStatusEnabled, Filter: &types.LifecycleRuleFilter{Prefix: aws.String("")}},
		}
		for want, rule := range bad {
			if err := putRules(rule); errCode(err) != want {
				t.Errorf("mau %s, dapat %v", want, err)
			}
		}
		if got, _ := c.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String("uji")}); len(got.Rules) != 2 {
			t.Fatal("konfigurasi berubah oleh permintaan yang ditolak")
		}

		// Jalankan pekerja lifecycle dengan jam yang dimajukan.
		put(t, e, "log/a", "x")
		put(t, e, "data/b", "x")
		worker := &lifecycle.Worker{Store: e.store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: e.store.Now}
		e.clockOffset.Store(int64(8 * 24 * time.Hour))
		stats, err := worker.RunOnce(context.Background())
		if err != nil || stats.Expired != 1 {
			t.Fatalf("stats = %+v, err = %v", stats, err)
		}
		if err := getAs(c, "uji", "log/a"); errCode(err) != "NoSuchKey" {
			t.Errorf("object kedaluwarsa masih ada: %v", err)
		}
		e.clockOffset.Store(int64(31 * 24 * time.Hour))
		if stats, _ := worker.RunOnce(context.Background()); stats.Transitioned != 1 {
			t.Fatalf("stats = %+v", stats)
		}
		e.clockOffset.Store(0)
		head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("data/b")})
		if err != nil || head.StorageClass != types.StorageClassStandardIa {
			t.Fatalf("storage class setelah transisi = %q, err = %v", head.StorageClass, err)
		}

		if _, err := c.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{Bucket: aws.String("uji")}); err != nil {
			t.Fatal(err)
		}
		// Token object tidak boleh menyentuh konfigurasi bucket.
		obj := e.as(e.newToken(t, auth.ObjectReadWrite))
		if _, err := obj.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String("uji")}); errCode(err) != "AccessDenied" {
			t.Errorf("token object membaca lifecycle: %v", err)
		}
		if _, err := obj.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: aws.String("uji")}); errCode(err) != "AccessDenied" {
			t.Errorf("token object menghapus CORS: %v", err)
		}
	})
}

func TestStorageClass(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		_, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("dingin"),
			Body: strings.NewReader("x"), StorageClass: types.StorageClassStandardIa})
		if err != nil {
			t.Fatal(err)
		}
		put(t, e, "biasa", "x")
		_, err = c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("uji"), Key: aws.String("salah"),
			Body: strings.NewReader("x"), StorageClass: types.StorageClassGlacier})
		if errCode(err) != "InvalidStorageClass" {
			t.Fatalf("err = %v", err)
		}

		list, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("uji")})
		if err != nil || len(list.Contents) != 2 {
			t.Fatalf("list = %+v, err = %v", list, err)
		}
		classes := map[string]types.ObjectStorageClass{}
		for _, o := range list.Contents {
			classes[*o.Key] = o.StorageClass
		}
		if classes["dingin"] != types.ObjectStorageClassStandardIa || classes["biasa"] != types.ObjectStorageClassStandard {
			t.Fatalf("classes = %v", classes)
		}
		head, _ := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("dingin")})
		if head.StorageClass != types.StorageClassStandardIa {
			t.Fatalf("head class = %q", head.StorageClass)
		}

		// Salinan memakai class dari permintaan, bukan dari sumber.
		c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("salinan"), CopySource: aws.String("uji/dingin")})
		head, _ = c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("salinan")})
		if head.StorageClass != "" {
			t.Fatalf("class salinan = %q", head.StorageClass)
		}
		// Multipart membawa class dari CreateMultipartUpload.
		mp, _ := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("mp"), StorageClass: types.StorageClassStandardIa})
		part, _ := c.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("uji"), Key: aws.String("mp"), UploadId: mp.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("x")})
		c.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String("uji"), Key: aws.String("mp"), UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag}}}})
		head, _ = c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("uji"), Key: aws.String("mp")})
		if head.StorageClass != types.StorageClassStandardIa {
			t.Fatalf("class multipart = %q", head.StorageClass)
		}
	})
}

func TestBucketLockAPI(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		c := e.client
		put(t, e, "arsip/a", "v1")
		put(t, e, "bebas/b", "v1")

		status, out := e.admin(t, root, "PUT", "buckets/uji/lock", map[string]any{"rules": []map[string]any{
			{"id": "retensi", "enabled": true, "prefix": "arsip/", "mode": "age", "days": 30}}})
		if status != 200 {
			t.Fatalf("set lock: %d %v", status, out)
		}
		for i, bad := range []map[string]any{
			{"id": "", "enabled": true, "mode": "indefinite"},
			{"id": "x", "enabled": true, "mode": "age"},
			{"id": "x", "enabled": true, "mode": "date"},
			{"id": "x", "enabled": true, "mode": "ngawur"},
		} {
			if status, _ := e.admin(t, root, "PUT", "buckets/uji/lock", map[string]any{"rules": []map[string]any{bad}}); status != 400 {
				t.Errorf("aturan tidak valid %d: status %d", i, status)
			}
		}
		status, out = e.admin(t, root, "GET", "buckets/uji", nil)
		if locks, _ := out["locks"].([]any); status != 200 || len(locks) != 1 {
			t.Fatalf("show bucket: %d %v", status, out)
		}

		// Bahkan root tidak bisa menghapus atau menimpa object terkunci.
		if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("uji"), Key: aws.String("arsip/a")}); errCode(err) != "AccessDenied" {
			t.Fatalf("hapus object terkunci: %v", err)
		}
		if err := putAs(c, "uji", "arsip/a"); errCode(err) != "AccessDenied" {
			t.Fatalf("timpa object terkunci: %v", err)
		}
		_, err := c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String("uji"), Key: aws.String("arsip/a"), CopySource: aws.String("uji/bebas/b")})
		if errCode(err) != "AccessDenied" {
			t.Fatalf("salin ke object terkunci: %v", err)
		}
		del, err := c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String("uji"), Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{{Key: aws.String("arsip/a")}, {Key: aws.String("bebas/b")}}}})
		if err != nil || len(del.Deleted) != 1 || len(del.Errors) != 1 || *del.Errors[0].Key != "arsip/a" {
			t.Fatalf("hapus massal: %+v %v", del, err)
		}
		if _, data := get(t, e, &s3.GetObjectInput{Key: aws.String("arsip/a")}); data != "v1" {
			t.Fatalf("object terkunci berubah: %q", data)
		}

		// Setelah masa retensi, penghapusan berhasil.
		e.clockOffset.Store(int64(31 * 24 * time.Hour))
		_, err = c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("uji"), Key: aws.String("arsip/a")})
		e.clockOffset.Store(0)
		if err != nil {
			t.Fatalf("hapus setelah retensi: %v", err)
		}
	})
}
