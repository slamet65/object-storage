package sigv4

import (
	"net/http"
	"strings"
	"time"
)

// SignRequest menandatangani r dengan SigV4 lewat header Authorization,
// untuk dipakai klien (CLI admin dan test). payloadHash adalah SHA-256 hex
// dari body (lihat HashPayload) atau "UNSIGNED-PAYLOAD". sessionToken boleh
// kosong.
func SignRequest(r *http.Request, accessKey, secretKey, sessionToken, region, payloadHash string, now time.Time) {
	if r.Host == "" {
		r.Host = r.URL.Host
	}
	amzDate := now.UTC().Format(timeFormat)
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if sessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", sessionToken)
		signed = append(signed, "x-amz-security-token")
	}
	cred := credential{accessKey: accessKey, date: amzDate[:8], region: region, service: "s3"}
	sig := signature(r, signingKey(secretKey, cred), cred, amzDate, signed, payloadHash, false)
	r.Header.Set("Authorization", algorithm+" Credential="+accessKey+"/"+cred.scope()+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}

// HashPayload mengembalikan SHA-256 hex dari body, untuk SignRequest.
func HashPayload(body []byte) string {
	return sha256Hex(string(body))
}
