package s3api

import (
	"net/http"
	"regexp"
	"strings"

	"object-storage/internal/auth"
	"object-storage/internal/storage"
)

type publicRequest struct {
	Public  bool     `json:"public"`
	Domains []string `json:"domains"`
}

type lockRequest struct {
	Rules []storage.LockRule `json:"rules"`
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validDomains menormalkan dan memeriksa daftar custom domain.
func (c *reqCtx) validDomains(domains []string) ([]string, error) {
	out := make([]string, 0, len(domains))
	base := strings.ToLower(c.srv.Domain)
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if len(d) > 253 || !domainRE.MatchString(d) {
			return nil, errf("InvalidArgument", "nama domain tidak valid: "+d)
		}
		if base != "" && (d == base || strings.HasSuffix(d, "."+base)) {
			return nil, errf("InvalidArgument", "domain "+d+" bertabrakan dengan domain dasar server")
		}
		out = append(out, d)
	}
	return out, nil
}

func validLockRules(rules []storage.LockRule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || seen[r.ID] {
			return errf("InvalidArgument", "setiap aturan lock butuh id yang unik")
		}
		seen[r.ID] = true
		switch r.Mode {
		case storage.LockIndefinite:
		case storage.LockAge:
			if r.Days <= 0 {
				return errf("InvalidArgument", "aturan lock mode age butuh days lebih dari 0")
			}
		case storage.LockDate:
			if r.Until == nil {
				return errf("InvalidArgument", "aturan lock mode date butuh until")
			}
		default:
			return errf("InvalidArgument", "mode aturan lock harus age, date, atau indefinite")
		}
	}
	return nil
}

func (c *reqCtx) serveAdminBucket(name string, rest []string) {
	m := c.r.Method
	action := auth.ActAdminWrite
	if m == http.MethodGet {
		action = auth.ActAdminRead
	}
	if !c.id.Allows(action, name, "") {
		c.fail(errAccessDenied)
		return
	}

	switch {
	case len(rest) == 0 && m == http.MethodGet:
		info, err := c.srv.Store.HeadBucket(name)
		if err != nil {
			c.fail(err)
			return
		}
		c.writeJSON(http.StatusOK, info)

	case len(rest) == 1 && rest[0] == "public" && m == http.MethodPut:
		var req publicRequest
		if err := c.readJSON(&req); err != nil {
			c.fail(err)
			return
		}
		domains, err := c.validDomains(req.Domains)
		if err != nil {
			c.fail(err)
			return
		}
		info, err := c.srv.Store.UpdateBucket(name, func(b *storage.BucketInfo) error {
			b.Public, b.Domains = req.Public, domains
			return nil
		})
		if err != nil {
			c.fail(err)
			return
		}
		c.writeJSON(http.StatusOK, info)

	case len(rest) == 1 && rest[0] == "lock" && m == http.MethodPut:
		var req lockRequest
		if err := c.readJSON(&req); err != nil {
			c.fail(err)
			return
		}
		if err := validLockRules(req.Rules); err != nil {
			c.fail(err)
			return
		}
		info, err := c.srv.Store.UpdateBucket(name, func(b *storage.BucketInfo) error {
			b.Locks = req.Rules
			return nil
		})
		if err != nil {
			c.fail(err)
			return
		}
		c.writeJSON(http.StatusOK, info)

	default:
		c.fail(errf("NoSuchResource", "path API admin tidak dikenal"))
	}
}
