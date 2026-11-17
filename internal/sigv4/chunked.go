package sigv4

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// hashReader memeriksa hash seluruh body saat pembacaan mencapai EOF.
type hashReader struct {
	r    io.Reader
	h    hash.Hash
	want []byte
}

func (hr *hashReader) Read(p []byte) (int, error) {
	n, err := hr.r.Read(p)
	hr.h.Write(p[:n])
	if err == io.EOF && !bytes.Equal(hr.h.Sum(nil), hr.want) {
		return n, errf("XAmzContentSHA256Mismatch", "isi body tidak cocok dengan x-amz-content-sha256")
	}
	return n, err
}

type chunkConfig struct {
	signed  bool   // tiap chunk membawa chunk-signature
	trailer bool   // ada trailing header setelah chunk terakhir
	key     []byte // signing key
	date    string
	scope   string
	seed    string // signature permintaan, dasar rantai signature chunk
}

// chunkReader men-decode body aws-chunked:
//
//	<hex ukuran>[;chunk-signature=<sig>]\r\n<data>\r\n ... 0[;chunk-signature=<sig>]\r\n
//	[<trailer>:<nilai>\r\n ...][x-amz-trailer-signature:<sig>\r\n]\r\n
type chunkReader struct {
	chunkConfig
	br       *bufio.Reader
	prevSig  string
	curSig   string
	remain   int64
	hash     hash.Hash
	trailers http.Header
	err      error
}

func newChunkReader(r io.Reader, cfg chunkConfig) *chunkReader {
	return &chunkReader{
		chunkConfig: cfg,
		br:          bufio.NewReaderSize(r, 64<<10),
		prevSig:     cfg.seed,
		hash:        sha256.New(),
		trailers:    http.Header{},
	}
}

var errIncomplete = errf("IncompleteBody", "body aws-chunked terpotong atau tidak valid")

func (c *chunkReader) readLine() (string, error) {
	line, err := c.br.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.read(p)
	if err != nil {
		if err != io.EOF {
			if _, ok := err.(*Error); !ok {
				err = errIncomplete
			}
		}
		c.err = err
	}
	return n, err
}

func (c *chunkReader) read(p []byte) (int, error) {
	if c.remain == 0 {
		line, err := c.readLine()
		if err != nil {
			// EOF sebelum chunk berukuran nol berarti body terpotong.
			return 0, errIncomplete
		}
		sizeHex, ext, _ := strings.Cut(line, ";")
		size, err := strconv.ParseInt(strings.TrimSpace(sizeHex), 16, 64)
		if err != nil || size < 0 {
			return 0, errIncomplete
		}
		c.curSig = strings.TrimPrefix(ext, "chunk-signature=")
		c.hash.Reset()
		if size == 0 {
			if err := c.verifyChunk(); err != nil {
				return 0, err
			}
			if err := c.readTrailers(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		c.remain = size
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > c.remain {
		p = p[:c.remain]
	}
	n, err := c.br.Read(p)
	c.hash.Write(p[:n])
	c.remain -= int64(n)
	if err != nil {
		return n, errIncomplete
	}
	if c.remain == 0 {
		if line, err := c.readLine(); err != nil || line != "" {
			return n, errIncomplete
		}
		if err := c.verifyChunk(); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (c *chunkReader) verifyChunk() error {
	if !c.signed {
		return nil
	}
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD", c.date, c.scope, c.prevSig, emptySHA256,
		hex.EncodeToString(c.hash.Sum(nil)),
	}, "\n")
	want := hex.EncodeToString(hmacSHA256(c.key, stringToSign))
	if !hmac.Equal([]byte(want), []byte(c.curSig)) {
		return errf("SignatureDoesNotMatch", "signature chunk tidak cocok")
	}
	c.prevSig = want
	return nil
}

func (c *chunkReader) readTrailers() error {
	var canonical strings.Builder
	trailerSig := ""
	for {
		line, err := c.readLine()
		if err == io.EOF {
			break // sebagian klien tidak mengirim CRLF penutup
		}
		if err != nil {
			return err
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !c.trailer {
			return errIncomplete
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if name == "x-amz-trailer-signature" {
			trailerSig = value
			continue
		}
		c.trailers.Set(name, value)
		canonical.WriteString(name + ":" + value + "\n")
	}
	if c.signed && c.trailer {
		stringToSign := strings.Join([]string{
			"AWS4-HMAC-SHA256-TRAILER", c.date, c.scope, c.prevSig, sha256Hex(canonical.String()),
		}, "\n")
		want := hex.EncodeToString(hmacSHA256(c.key, stringToSign))
		if !hmac.Equal([]byte(want), []byte(trailerSig)) {
			return errf("SignatureDoesNotMatch", "signature trailer tidak cocok")
		}
	}
	return nil
}
