package s3api

import (
	"encoding/xml"
	"errors"
	"net/http"

	"object-storage/internal/sigv4"
	"object-storage/internal/storage"
)

// apiError adalah error dengan kode S3.
type apiError struct {
	Code    string
	Message string
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func errf(code, msg string) *apiError { return &apiError{Code: code, Message: msg} }

var statusByCode = map[string]int{
	"AccessDenied":                      http.StatusForbidden,
	"InvalidAccessKeyId":                http.StatusForbidden,
	"SignatureDoesNotMatch":             http.StatusForbidden,
	"RequestTimeTooSkewed":              http.StatusForbidden,
	"NoSuchBucket":                      http.StatusNotFound,
	"NoSuchKey":                         http.StatusNotFound,
	"NoSuchUpload":                      http.StatusNotFound,
	"NoSuchToken":                       http.StatusNotFound,
	"NoSuchCORSConfiguration":           http.StatusNotFound,
	"NoSuchLifecycleConfiguration":      http.StatusNotFound,
	"AccessForbidden":                   http.StatusForbidden,
	"DomainAlreadyInUse":                http.StatusConflict,
	"NoSuchResource":                    http.StatusNotFound,
	"BucketAlreadyOwnedByYou":           http.StatusConflict,
	"BucketNotEmpty":                    http.StatusConflict,
	"MethodNotAllowed":                  http.StatusMethodNotAllowed,
	"PreconditionFailed":                http.StatusPreconditionFailed,
	"InvalidRange":                      http.StatusRequestedRangeNotSatisfiable,
	"InvalidPartNumber":                 http.StatusRequestedRangeNotSatisfiable,
	"NotImplemented":                    http.StatusNotImplemented,
	"InternalError":                     http.StatusInternalServerError,
	"AuthorizationHeaderMalformed":      http.StatusBadRequest,
	"AuthorizationQueryParametersError": http.StatusBadRequest,
}

var storageErrors = []struct {
	err  error
	code string
	msg  string
}{
	{storage.ErrNoSuchBucket, "NoSuchBucket", "The specified bucket does not exist"},
	{storage.ErrBucketExists, "BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it"},
	{storage.ErrBucketNotEmpty, "BucketNotEmpty", "The bucket you tried to delete is not empty"},
	{storage.ErrNoSuchKey, "NoSuchKey", "The specified key does not exist"},
	{storage.ErrNoSuchUpload, "NoSuchUpload", "The specified multipart upload does not exist"},
	{storage.ErrInvalidPart, "InvalidPart", "One or more of the specified parts could not be found or its ETag did not match"},
	{storage.ErrInvalidPartOrder, "InvalidPartOrder", "The list of parts was not in ascending order"},
	{storage.ErrEntityTooLarge, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size"},
	{storage.ErrTooManyBuckets, "TooManyBuckets", "You have attempted to create more buckets than allowed"},
	{storage.ErrObjectLocked, "AccessDenied", "Access Denied: the object is protected by a bucket lock rule"},
	{storage.ErrDomainTaken, "DomainAlreadyInUse", "The domain is already mapped to another bucket"},
	{storage.ErrEntityTooSmall, "EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size"},
}

// toAPIError memetakan error apa pun ke kode S3. Error tak dikenal menjadi
// InternalError tanpa membocorkan detailnya ke klien.
func toAPIError(err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	var se *sigv4.Error
	if errors.As(err, &se) {
		return &apiError{Code: se.Code, Message: se.Message}
	}
	for _, m := range storageErrors {
		if errors.Is(err, m.err) {
			return &apiError{Code: m.code, Message: m.msg}
		}
	}
	return &apiError{Code: "InternalError", Message: "We encountered an internal error. Please try again."}
}

type errorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string
	Message   string
	Resource  string
	RequestId string
}

func (c *reqCtx) fail(err error) {
	ae := toAPIError(err)
	status, ok := statusByCode[ae.Code]
	if !ok {
		status = http.StatusBadRequest
	}
	if ae.Code == "InternalError" {
		c.srv.Logger.Error("kesalahan internal", "err", err, "method", c.r.Method, "path", c.r.URL.Path)
	}
	if c.admin {
		c.writeJSON(status, adminError{Code: ae.Code, Message: ae.Message, RequestID: c.w.Header().Get("x-amz-request-id")})
		return
	}
	c.writeXML(status, errorResponse{
		Code:      ae.Code,
		Message:   ae.Message,
		Resource:  c.r.URL.Path,
		RequestId: c.w.Header().Get("x-amz-request-id"),
	})
}
