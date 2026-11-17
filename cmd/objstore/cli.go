package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"object-storage/internal/s3api"
	"object-storage/internal/sigv4"
)

const cliUsage = `Pemakaian:
  objstore [serve] [flag]                      jalankan server
  objstore token create --permission P [--name N] [--bucket B]... [--ttl DURASI]
  objstore token list
  objstore token show|delete|rotate|disable|enable ID
  objstore bucket show NAMA
  objstore bucket public NAMA --enable|--disable [--domain D]...
  objstore bucket lock NAMA --file ATURAN.json | --clear
  objstore temp-credentials --permission P --ttl DURASI [--bucket B]... [--prefix P]... [--object K]...
  objstore whoami

Izin: admin-read-write, admin-read, object-read-write, object-read.

Flag umum perintah klien:
  --endpoint URL   alamat server (bawaan: $OBJSTORE_ENDPOINT atau http://localhost:9000)
  --region R       region untuk signature (bawaan us-east-1)
  --ca-cert FILE   sertifikat CA (PEM) untuk server HTTPS bersertifikat sendiri

Kredensial dibaca dari OBJSTORE_ACCESS_KEY, OBJSTORE_SECRET_KEY, dan
OBJSTORE_SESSION_TOKEN (opsional).
`

// stringList adalah flag yang boleh diulang.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

type client struct {
	endpoint string
	region   string
	http     *http.Client
}

// call mengirim permintaan bertanda tangan ke API admin dan mengembalikan
// body respons. Respons error dari server dikembalikan sebagai error.
func (c *client) call(method, path string, in any) ([]byte, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	url := strings.TrimRight(c.endpoint, "/") + s3api.AdminPrefix + path
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	sigv4.SignRequest(req, os.Getenv("OBJSTORE_ACCESS_KEY"), os.Getenv("OBJSTORE_SECRET_KEY"),
		os.Getenv("OBJSTORE_SESSION_TOKEN"), c.region, sigv4.HashPayload(body), time.Now())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		var e struct{ Code, Message string }
		if json.Unmarshal(out, &e) == nil && e.Code != "" {
			return nil, fmt.Errorf("%s: %s", e.Code, e.Message)
		}
		return nil, fmt.Errorf("server menjawab status %d", resp.StatusCode)
	}
	return out, nil
}

// runCLI menjalankan perintah klien dan mengembalikan kode keluar.
func runCLI(args []string, stdout, stderr io.Writer) int {
	out, err := cli(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stderr, cliUsage)
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "objstore:", err)
		return 1
	}
	// Rapikan JSON dari server supaya enak dibaca dan tetap bisa di-pipe.
	var buf bytes.Buffer
	if len(out) > 0 && json.Indent(&buf, bytes.TrimSpace(out), "", "  ") == nil {
		fmt.Fprintln(stdout, buf.String())
	}
	return 0
}

func usageErr(format string, args ...any) error {
	return fmt.Errorf(format+"\n\n%s", append(args, cliUsage)...)
}

func cli(args []string) ([]byte, error) {
	cmd, args := args[0], args[1:]
	sub := ""
	if cmd == "token" || cmd == "bucket" {
		if len(args) == 0 {
			return nil, usageErr("perintah %s butuh subperintah", cmd)
		}
		sub, args = args[0], args[1:]
	}
	// ID token atau nama bucket boleh ditulis sebelum flag.
	id := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("objstore "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	endpoint := os.Getenv("OBJSTORE_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:9000"
	}
	fs.StringVar(&endpoint, "endpoint", endpoint, "")
	region := fs.String("region", "us-east-1", "")
	caCert := fs.String("ca-cert", "", "")
	name := fs.String("name", "", "")
	permission := fs.String("permission", "", "")
	ttl := fs.Duration("ttl", 0, "")
	enable := fs.Bool("enable", false, "")
	disable := fs.Bool("disable", false, "")
	file := fs.String("file", "", "")
	clear := fs.Bool("clear", false, "")
	var buckets, prefixes, objects, domains stringList
	fs.Var(&domains, "domain", "")
	fs.Var(&buckets, "bucket", "")
	fs.Var(&prefixes, "prefix", "")
	fs.Var(&objects, "object", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, err
		}
		return nil, usageErr("%v", err)
	}
	if fs.NArg() > 0 {
		return nil, usageErr("argumen tidak dikenal: %s", fs.Arg(0))
	}
	if os.Getenv("OBJSTORE_ACCESS_KEY") == "" || os.Getenv("OBJSTORE_SECRET_KEY") == "" {
		return nil, errors.New("OBJSTORE_ACCESS_KEY dan OBJSTORE_SECRET_KEY wajib diisi")
	}

	c := &client{endpoint: endpoint, region: *region, http: &http.Client{Timeout: 30 * time.Second}}
	if *caCert != "" {
		pem, err := os.ReadFile(*caCert)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s tidak berisi sertifikat PEM", *caCert)
		}
		c.http.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	}

	needID := func() error {
		if id == "" {
			return usageErr("perintah ini butuh ID token atau nama bucket")
		}
		return nil
	}
	switch cmd + " " + sub {
	case "bucket show":
		if err := needID(); err != nil {
			return nil, err
		}
		return c.call(http.MethodGet, "buckets/"+id, nil)
	case "bucket public":
		if err := needID(); err != nil {
			return nil, err
		}
		if *enable == *disable {
			return nil, usageErr("pilih tepat satu dari --enable atau --disable")
		}
		if domains == nil {
			domains = stringList{}
		}
		return c.call(http.MethodPut, "buckets/"+id+"/public", map[string]any{"public": *enable, "domains": domains})
	case "bucket lock":
		if err := needID(); err != nil {
			return nil, err
		}
		if (*file == "") == !*clear {
			return nil, usageErr("pilih tepat satu dari --file atau --clear")
		}
		rules := json.RawMessage("[]")
		if *file != "" {
			data, err := os.ReadFile(*file)
			if err != nil {
				return nil, err
			}
			if !json.Valid(data) {
				return nil, fmt.Errorf("%s bukan JSON yang valid", *file)
			}
			rules = data
		}
		return c.call(http.MethodPut, "buckets/"+id+"/lock", map[string]any{"rules": rules})
	case "whoami ":
		return c.call(http.MethodGet, "whoami", nil)
	case "temp-credentials ":
		return c.call(http.MethodPost, "temp-credentials", map[string]any{
			"ttl_seconds": int64(ttl.Seconds()), "permission": *permission,
			"buckets": buckets, "prefixes": prefixes, "objects": objects,
		})
	case "token create":
		return c.call(http.MethodPost, "tokens", map[string]any{
			"name": *name, "permission": *permission, "buckets": buckets, "ttl_seconds": int64(ttl.Seconds()),
		})
	case "token list":
		return c.call(http.MethodGet, "tokens", nil)
	case "token show":
		if err := needID(); err != nil {
			return nil, err
		}
		return c.call(http.MethodGet, "tokens/"+id, nil)
	case "token delete":
		if err := needID(); err != nil {
			return nil, err
		}
		return c.call(http.MethodDelete, "tokens/"+id, nil)
	case "token rotate", "token disable", "token enable":
		if err := needID(); err != nil {
			return nil, err
		}
		return c.call(http.MethodPost, "tokens/"+id+"/"+sub, nil)
	}
	return nil, usageErr("perintah tidak dikenal: %s %s", cmd, sub)
}
