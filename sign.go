package objectstorage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Requests are signed with HTTP Message Signatures (RFC 9421), HMAC-SHA256
// keyed with the secret access key, so the secret itself is never sent:
//
//	Content-Digest: sha-256=:<base64 SHA-256 of the body>:        (RFC 9530)
//	Signature-Input: th=("@method" "@authority" "@path" "@query" "content-digest");created=1767225600;keyid="<access key id>";alg="hmac-sha256"
//	Signature: th=:<base64 HMAC-SHA256 of the signature base>:
//
// content-digest is covered whenever the request has a body, which ties the
// body to the signature: the service checks the digest against the bytes as
// they arrive and stores nothing that does not match.

// contentDigest is the Content-Digest (and Repr-Digest) value of data.
func contentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return digestField(sum[:])
}

func digestField(sum []byte) string {
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum) + ":"
}

// readerDigest hashes what r yields, for bodies that can be read again
// (files, seekable readers) so the digest is known before the headers go.
func readerDigest(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return digestField(h.Sum(nil)), nil
}

// sigAuthority is the @authority component: the host, lower case, without
// a default port.
func sigAuthority(req *http.Request) string {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host = strings.ToLower(host)
	return strings.TrimSuffix(strings.TrimSuffix(host, ":443"), ":80")
}

// signatureBase builds the signed bytes (RFC 9421 section 2.5) of req for
// the given Signature-Input member value (after "th=").
func signatureBase(req *http.Request, params string, digest bool) string {
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString(`"@method": ` + req.Method + "\n")
	b.WriteString(`"@authority": ` + sigAuthority(req) + "\n")
	b.WriteString(`"@path": ` + path + "\n")
	b.WriteString(`"@query": ?` + req.URL.RawQuery + "\n")
	if digest {
		b.WriteString(`"content-digest": ` + req.Header.Get("Content-Digest") + "\n")
	}
	b.WriteString(`"@signature-params": ` + params)
	return b.String()
}

// signRequest adds Signature-Input and Signature to req. It covers
// content-digest when req carries a Content-Digest header (set it first
// for every request with a body).
func signRequest(req *http.Request, keyID, secret string, now time.Time) {
	components := `"@method" "@authority" "@path" "@query"`
	digest := req.Header.Get("Content-Digest") != ""
	if digest {
		components += ` "content-digest"`
	}
	params := "(" + components + ");created=" + strconv.FormatInt(now.Unix(), 10) +
		`;keyid="` + sfEscape(keyID) + `";alg="hmac-sha256"`
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signatureBase(req, params, digest)))
	req.Header.Set("Signature-Input", "th="+params)
	req.Header.Set("Signature", "th=:"+base64.StdEncoding.EncodeToString(mac.Sum(nil))+":")
}

// sfEscape escapes a Structured Fields string's contents (RFC 8941).
func sfEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// ErrDigestMismatch is returned (wrapped) when a downloaded object does not
// match the Repr-Digest the service sent with it: the data was damaged on
// the way and must not be used.
var ErrDigestMismatch = errors.New("objectstorage: the downloaded data does not match its Repr-Digest")

// sha256Of returns the SHA-256 in a Content-Digest / Repr-Digest field
// value ("sha-256=:<base64>:", possibly among other algorithms), or nil.
func sha256Of(field string) []byte {
	for _, m := range strings.Split(field, ",") {
		alg, v, ok := strings.Cut(strings.TrimSpace(m), "=")
		if !ok || strings.ToLower(strings.TrimSpace(alg)) != "sha-256" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) < 2 || v[0] != ':' || v[len(v)-1] != ':' {
			return nil
		}
		sum, err := base64.StdEncoding.DecodeString(v[1 : len(v)-1])
		if err != nil || len(sum) != sha256.Size {
			return nil
		}
		return sum
	}
	return nil
}

// verifyingReader hashes a full download and fails its last Read with
// ErrDigestMismatch when the bytes do not match the Repr-Digest.
type verifyingReader struct {
	io.ReadCloser
	h    hash.Hash
	want []byte
	key  string
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.ReadCloser.Read(p)
	v.h.Write(p[:n])
	if errors.Is(err, io.EOF) {
		if got := v.h.Sum(nil); !hmac.Equal(got, v.want) {
			return n, fmt.Errorf("%w (%s: got sha-256 %s)", ErrDigestMismatch, v.key, base64.StdEncoding.EncodeToString(got))
		}
	}
	return n, err
}
