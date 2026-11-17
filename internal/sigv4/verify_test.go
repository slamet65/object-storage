package sigv4

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Contoh dari dokumentasi AWS "Signature Calculations for the Authorization Header".
const (
	exAccess = "AKIAIOSFODNN7EXAMPLE"
	exSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	exScope  = "20130524/us-east-1/s3/aws4_request"
)

func verifier() *Verifier {
	return &Verifier{
		Keys: StaticKeys{AccessKey: exAccess, SecretKey: exSecret},
		Now:  func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) },
	}
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprint(err)
}

func getObjectRequest(sig string) *http.Request {
	r := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Header.Set("Range", "bytes=0-9")
	r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exAccess+"/"+exScope+
		",SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature="+sig)
	return r
}

func TestHeaderAuth(t *testing.T) {
	const sig = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if _, err := verifier().Verify(getObjectRequest(sig)); err != nil {
		t.Fatal(err)
	}

	bad := getObjectRequest(strings.Replace(sig, "f0", "00", 1))
	if _, err := verifier().Verify(bad); code(err) != "SignatureDoesNotMatch" {
		t.Fatalf("err = %v", err)
	}

	tampered := getObjectRequest(sig)
	tampered.Header.Set("Range", "bytes=0-99")
	if _, err := verifier().Verify(tampered); code(err) != "SignatureDoesNotMatch" {
		t.Fatalf("err = %v", err)
	}

	late := verifier()
	late.Now = func() time.Time { return time.Date(2013, 5, 24, 0, 16, 0, 0, time.UTC) }
	if _, err := late.Verify(getObjectRequest(sig)); code(err) != "RequestTimeTooSkewed" {
		t.Fatalf("err = %v", err)
	}

	other := verifier()
	other.Keys = StaticKeys{AccessKey: "LAIN", SecretKey: exSecret}
	if _, err := other.Verify(getObjectRequest(sig)); code(err) != "InvalidAccessKeyId" {
		t.Fatalf("err = %v", err)
	}

	anon := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
	if _, err := verifier().Verify(anon); code(err) != "AccessDenied" {
		t.Fatalf("err = %v", err)
	}
}

func TestQueryCanonicalization(t *testing.T) {
	// Contoh "GET Bucket (List Objects)" dari dokumentasi AWS.
	r := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exAccess+"/"+exScope+
		",SignedHeaders=host;x-amz-content-sha256;x-amz-date,"+
		"Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
	if _, err := verifier().Verify(r); err != nil {
		t.Fatal(err)
	}
}

func TestPresigned(t *testing.T) {
	const u = "http://examplebucket.s3.amazonaws.com/test.txt" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	if _, err := verifier().Verify(httptest.NewRequest("GET", u, nil)); err != nil {
		t.Fatal(err)
	}

	expired := verifier()
	expired.Now = func() time.Time { return time.Date(2013, 5, 25, 0, 0, 1, 0, time.UTC) }
	if _, err := expired.Verify(httptest.NewRequest("GET", u, nil)); code(err) != "AccessDenied" {
		t.Fatalf("err = %v", err)
	}

	// Method lain dengan URL yang sama harus ditolak.
	if _, err := verifier().Verify(httptest.NewRequest("PUT", u, nil)); code(err) != "SignatureDoesNotMatch" {
		t.Fatalf("err = %v", err)
	}
}

// Contoh "Signature Calculations: Transferring Payload in Multiple Chunks".
func chunkedRequest(body string) *http.Request {
	r := httptest.NewRequest("PUT", "http://s3.amazonaws.com/examplebucket/chunkObject.txt", strings.NewReader(body))
	r.ContentLength = 66824
	r.Header.Set("Content-Length", "66824")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Content-Sha256", streamingSigned)
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("X-Amz-Decoded-Content-Length", "66560")
	r.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+exAccess+"/"+exScope+
		",SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;"+
		"x-amz-decoded-content-length;x-amz-storage-class,"+
		"Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
	return r
}

func chunkedBody() string {
	return "10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n" +
		strings.Repeat("a", 65536) + "\r\n" +
		"400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n" +
		strings.Repeat("a", 1024) + "\r\n" +
		"0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n"
}

func TestSignedChunks(t *testing.T) {
	body := chunkedBody()
	if len(body) != 66824 {
		t.Fatalf("panjang body contoh = %d", len(body))
	}
	res, err := verifier().Verify(chunkedRequest(body))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != strings.Repeat("a", 66560) {
		t.Fatalf("hasil decode salah, panjang %d", len(data))
	}

	// Isi chunk diubah: signature chunk harus gagal.
	tampered := strings.Replace(body, "\r\naaaa", "\r\nbaaa", 1)
	res, _ = verifier().Verify(chunkedRequest(tampered))
	if _, err := io.ReadAll(res.Body); code(err) != "SignatureDoesNotMatch" {
		t.Fatalf("err = %v", err)
	}

	// Body terpotong sebelum chunk penutup: tidak boleh dianggap selesai.
	cut := body[:strings.Index(body, "400;")]
	res, _ = verifier().Verify(chunkedRequest(cut))
	if _, err := io.ReadAll(res.Body); code(err) != "IncompleteBody" {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsignedTrailerChunks(t *testing.T) {
	r := newChunkReader(strings.NewReader("5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n"),
		chunkConfig{trailer: true})
	data, err := io.ReadAll(r)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if got := r.trailers.Get("x-amz-checksum-crc32"); got != "DUoRhQ==" {
		t.Fatalf("trailer = %q", got)
	}
}

func TestPayloadHash(t *testing.T) {
	hr := &hashReader{r: strings.NewReader("abc"), h: sha256.New(), want: make([]byte, 32)}
	if _, err := io.ReadAll(hr); code(err) != "XAmzContentSHA256Mismatch" {
		t.Fatalf("err = %v", err)
	}
}

func TestURIEncode(t *testing.T) {
	if got := URIEncode("a b/ü+~*", false); got != "a%20b/%C3%BC%2B~%2A" {
		t.Fatal(got)
	}
	if got := URIEncode("a/b", true); got != "a%2Fb" {
		t.Fatal(got)
	}
}
