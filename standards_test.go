package objectstorage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder sits in front of the fake and keeps every request's headers.
type recorder struct {
	next http.Handler
	mu   sync.Mutex
	seen []http.Header
	// tamper flips a body byte on its way, after it was signed.
	tamper bool
	paths  []string
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.seen = append(rec.seen, r.Header.Clone())
	rec.paths = append(rec.paths, r.Method+" "+r.URL.Path)
	rec.mu.Unlock()
	if rec.tamper && r.ContentLength > 0 {
		body, _ := io.ReadAll(r.Body)
		body[0] ^= 1
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	rec.next.ServeHTTP(w, r)
}

func newRecordedClient(t *testing.T, f *fakeService) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{next: f}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, AccessKeyID: "KEY", SecretAccessKey: testSecret, PartSize: minPartSize, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	return c, rec
}

// The base and signature below were computed independently (Python's hmac
// over the RFC 9421 base) from the service's reference algorithm.
func TestSignatureGolden(t *testing.T) {
	body := []byte(`{"hello": "world"}`)
	req, _ := http.NewRequest(http.MethodPut, "https://objects.th-bkk-1.thailandhosting.com/v1/buckets/photos/objects/a%20b.jpg", bytes.NewReader(body))
	req.Header.Set("Content-Digest", contentDigest(body))
	if got := req.Header.Get("Content-Digest"); got != "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:" {
		t.Fatalf("Content-Digest %s", got)
	}
	signRequest(req, "AKID", "SECRET", time.Unix(1767225600, 0))
	params := `("@method" "@authority" "@path" "@query" "content-digest");created=1767225600;keyid="AKID";alg="hmac-sha256"`
	wantBase := `"@method": PUT
"@authority": objects.th-bkk-1.thailandhosting.com
"@path": /v1/buckets/photos/objects/a%20b.jpg
"@query": ?
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@signature-params": ` + params
	if got := signatureBase(req, params, true); got != wantBase {
		t.Fatalf("base:\n%s\nwant:\n%s", got, wantBase)
	}
	if got := req.Header.Get("Signature-Input"); got != "th="+params {
		t.Fatalf("Signature-Input %s", got)
	}
	if got := req.Header.Get("Signature"); got != "th=:4+RX5eGfUEKmFgBZzJIlXsCIW/mtKnZ+3v3GX4r7z7o=:" {
		t.Fatalf("Signature %s", got)
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("Authorization sent")
	}

	// No body: no content-digest; the authority is lower-cased without its
	// default port, and the query goes as sent.
	req, _ = http.NewRequest(http.MethodGet, "https://Objects.TH-BKK-1.thailandhosting.com:443/v1/buckets/photos/objects?prefix=a%2Fb&limit=10", nil)
	signRequest(req, "AKID", "SECRET", time.Unix(1767225600, 0))
	if got := req.Header.Get("Signature-Input"); got != `th=("@method" "@authority" "@path" "@query");created=1767225600;keyid="AKID";alg="hmac-sha256"` {
		t.Fatalf("Signature-Input %s", got)
	}
	if req.Header.Get("Content-Digest") != "" {
		t.Fatal("Content-Digest on a request without a body")
	}
	if got := req.Header.Get("Signature"); got != "th=:QogF7tpNEzBlMIg8uZbtsfu8imaHyA4+0aCxMmYDtM0=:" {
		t.Fatalf("Signature %s", got)
	}
}

func TestSecretNeverSent(t *testing.T) {
	f := newFake()
	c, rec := newRecordedClient(t, f)
	ctx := context.Background()
	b := c.Bucket("b")
	if _, err := b.PutBytes(ctx, "k", []byte("data"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.List(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if f.bearer.Load() {
		t.Fatal("an Authorization header was sent")
	}
	for _, h := range rec.seen {
		for k, vs := range h {
			for _, v := range vs {
				if strings.Contains(v, testSecret) {
					t.Fatalf("the secret travelled in %s: %s", k, v)
				}
			}
		}
		if h.Get("Signature") == "" {
			t.Fatal("unsigned request")
		}
	}
}

func TestBodyDigests(t *testing.T) {
	f := newFake()
	c, rec := newRecordedClient(t, f)
	ctx := context.Background()
	b := c.Bucket("b")
	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")
	os.WriteFile(src, randomData(2*minPartSize+5), 0o644)
	// One request, a seekable reader, an empty object, parts from a file
	// and parts from a stream: every body carries a Content-Digest the fake
	// checked.
	if _, err := b.PutBytes(ctx, "one", []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Upload(ctx, "seek", strings.NewReader("seekable"), 8, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutBytes(ctx, "empty", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.UploadFile(ctx, "file", src, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Upload(ctx, "stream", io.MultiReader(bytes.NewReader(randomData(3*minPartSize))), -1, nil); err != nil {
		t.Fatal(err)
	}
	bodies := 0
	for i, h := range rec.seen {
		method, path, _ := strings.Cut(rec.paths[i], " ")
		if method != http.MethodPut && method != http.MethodPost {
			continue
		}
		bodies++
		if h.Get("Content-Digest") == "" || !strings.Contains(h.Get("Signature-Input"), `"content-digest"`) {
			t.Fatalf("%s without a signed Content-Digest", rec.paths[i])
		}
		if strings.HasSuffix(path, "/objects/empty") && h.Get("Content-Digest") != "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" {
			t.Fatalf("empty object digest %s", h.Get("Content-Digest"))
		}
	}
	// 3 single PUTs + file (start, 3 parts, complete) + stream (start, 3
	// parts, complete).
	if bodies != 13 || int(f.digested.Load()) != bodies {
		t.Fatalf("%d requests with a body, %d digests checked", bodies, f.digested.Load())
	}
}

func TestBadDigestIsNotRetried(t *testing.T) {
	f := newFake()
	c, rec := newRecordedClient(t, f)
	rec.tamper = true
	_, err := c.Bucket("b").PutBytes(context.Background(), "k", []byte("data"), nil)
	if ErrorCode(err) != "bad_digest" {
		t.Fatalf("tampered body: %v", err)
	}
	if n := f.requests.Load(); n != 1 {
		t.Fatalf("bad_digest was retried (%d requests)", n)
	}
	if _, ok := f.objects["b/k"]; ok {
		t.Fatal("tampered body stored")
	}
}

func TestProblemDetails(t *testing.T) {
	f := newFake()
	c := newTestClient(t, f)
	b := c.Bucket("b")
	ctx := context.Background()
	_, err := b.GetBytes(ctx, "missing")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("not an *Error: %v", err)
	}
	if e.StatusCode != 404 || e.Code != "object_not_found" || e.Message != "fake: object_not_found" ||
		e.Type != "tag:thailandhosting.com,2026:object-storage/object_not_found" || e.Instance != "/v1/buckets/b/objects/missing" {
		t.Fatalf("problem: %+v", e)
	}
	// HEAD answers have no body: the code comes from X-Error-Code.
	if _, err := b.Head(ctx, "missing"); ErrorCode(err) != "object_not_found" || !IsNotFound(err) {
		t.Fatalf("head: %v", err)
	}
	wrong, _ := New(Config{Endpoint: c.endpoint.String(), AccessKeyID: "KEY", SecretAccessKey: "wrong"})
	if _, err := wrong.ListBuckets(ctx); ErrorCode(err) != "invalid_signature" {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestRetryAfterIsRespected(t *testing.T) {
	f := newFake()
	c, rec := newRecordedClient(t, f)
	f.flaky.Store(1)
	f.retryAfter = "1"
	start := time.Now()
	if _, err := c.Bucket("b").PutBytes(context.Background(), "k", []byte("data"), nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < time.Second {
		t.Fatalf("retried after %v, Retry-After asked for 1s", d)
	}
	if len(rec.seen) != 2 || rec.seen[0].Get("Signature-Input") == rec.seen[1].Get("Signature-Input") {
		t.Fatal("the retry was not signed afresh")
	}
	if retryAfter("2") != 2*time.Second || retryAfter("") != 0 || retryAfter("999") != 30*time.Second {
		t.Fatal("retryAfter")
	}
}

func TestConditionalWrites(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	ctx := context.Background()
	obj, err := b.PutBytes(ctx, "k", []byte("v1"), &PutOptions{IfNotExists: true})
	if err != nil {
		t.Fatal(err)
	}
	before := f.requests.Load()
	if _, err := b.PutBytes(ctx, "k", []byte("v2"), &PutOptions{IfNoneMatch: "*"}); !IsPreconditionFailed(err) || ErrorCode(err) != "precondition_failed" {
		t.Fatalf("create over an existing key: %v", err)
	}
	if f.requests.Load()-before != 1 {
		t.Fatal("a 412 was retried")
	}
	if _, err := b.PutBytes(ctx, "k", []byte("v2"), &PutOptions{IfMatch: "0123"}); !IsPreconditionFailed(err) {
		t.Fatalf("stale If-Match: %v", err)
	}
	if _, err := b.PutBytes(ctx, "k", []byte("v2"), &PutOptions{IfMatch: obj.ETag}); err != nil {
		t.Fatalf("If-Match current ETag: %v", err)
	}
	if string(f.objects["b/k"]) != "v2" {
		t.Fatal("conditional update not stored")
	}

	// A large upload is checked when the parts are joined, then aborted.
	_, err = b.Upload(ctx, "k", io.MultiReader(bytes.NewReader(randomData(3*minPartSize))), -1, &PutOptions{IfNotExists: true})
	if !IsPreconditionFailed(err) {
		t.Fatalf("multipart create over an existing key: %v", err)
	}
	if len(f.uploads) != 0 || string(f.objects["b/k"]) != "v2" {
		t.Fatal("failed multipart upload changed the object or stayed open")
	}
	if _, err := b.Upload(ctx, "new", io.MultiReader(bytes.NewReader(randomData(3*minPartSize))), -1, &PutOptions{IfNotExists: true}); err != nil {
		t.Fatalf("multipart create of a new key: %v", err)
	}

	cur, _ := b.Head(ctx, "k")
	if err := b.DeleteWithOptions(ctx, "k", &DeleteOptions{IfMatch: obj.ETag}); !IsPreconditionFailed(err) {
		t.Fatalf("delete with a stale ETag: %v", err)
	}
	if err := b.DeleteWithOptions(ctx, "k", &DeleteOptions{IfMatch: cur.ETag}); err != nil {
		t.Fatalf("delete with the current ETag: %v", err)
	}
	if _, ok := f.objects["b/k"]; ok {
		t.Fatal("not deleted")
	}
	if err := b.DeleteWithOptions(ctx, "k", &DeleteOptions{IfMatch: "*"}); !IsPreconditionFailed(err) {
		t.Fatalf("If-Match: * on a missing object: %v", err)
	}
}

func TestConditionalReads(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	ctx := context.Background()
	obj, err := b.PutBytes(ctx, "k", []byte("data"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, "k", &GetOptions{IfNoneMatch: obj.ETag}); !errors.Is(err, ErrNotModified) {
		t.Fatalf("Get If-None-Match: %v", err)
	}
	if _, err := b.HeadWithOptions(ctx, "k", &GetOptions{IfNoneMatch: obj.ETag}); !errors.Is(err, ErrNotModified) {
		t.Fatalf("Head If-None-Match: %v", err)
	}
	if _, err := b.Get(ctx, "k", &GetOptions{IfModifiedSince: fakeModified.Add(time.Hour)}); !errors.Is(err, ErrNotModified) {
		t.Fatalf("Get If-Modified-Since: %v", err)
	}
	if r, err := b.Get(ctx, "k", &GetOptions{IfModifiedSince: fakeModified.Add(-time.Hour)}); err != nil {
		t.Fatalf("Get modified since: %v", err)
	} else {
		r.Close()
	}
	if _, err := b.Get(ctx, "k", &GetOptions{IfMatch: "0123"}); !IsPreconditionFailed(err) {
		t.Fatalf("Get If-Match: %v", err)
	}
	if _, err := b.HeadWithOptions(ctx, "k", &GetOptions{IfMatch: "0123"}); !IsPreconditionFailed(err) {
		t.Fatalf("Head If-Match: %v", err)
	}
	if _, err := b.Get(ctx, "k", &GetOptions{IfUnmodifiedSince: fakeModified.Add(-time.Hour)}); !IsPreconditionFailed(err) {
		t.Fatalf("Get If-Unmodified-Since: %v", err)
	}
	if got, err := b.HeadWithOptions(ctx, "k", &GetOptions{IfMatch: obj.ETag}); err != nil || got.ETag != obj.ETag {
		t.Fatalf("Head If-Match current: %v %v", got, err)
	}
}

func TestReprDigestVerification(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	ctx := context.Background()
	data := []byte("hello digest")
	if _, err := b.PutBytes(ctx, "k", data, nil); err != nil {
		t.Fatal(err)
	}
	head, err := b.Head(ctx, "k")
	if err != nil || head.Digest != contentDigest(data) {
		t.Fatalf("Digest %q %v", head.Digest, err)
	}
	if got, err := b.GetBytes(ctx, "k"); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get: %v", err)
	}

	f.badRepr.Store(true)
	if _, err := b.GetBytes(ctx, "k"); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("damaged download accepted: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "k")
	if _, err := b.DownloadFile(ctx, "k", dst); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("damaged DownloadFile accepted: %v", err)
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a file that failed its digest was kept")
	}
	// A range is not the whole representation: not checked.
	r, err := b.Get(ctx, "k", &GetOptions{Offset: 1, Length: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("range checked against the whole object's digest: %v", err)
	}
	r.Close()

	// A large object fetched as parallel ranges is checked once whole.
	big := randomData(3*minPartSize + 11)
	f.mu.Lock()
	f.objects["b/big"], f.digests["b/big"] = big, contentDigest(big)
	f.mu.Unlock()
	f.badRepr.Store(false)
	dst = filepath.Join(t.TempDir(), "big")
	if _, err := b.DownloadFile(ctx, "big", dst); err != nil {
		t.Fatalf("parallel download: %v", err)
	}
	f.badRepr.Store(true)
	if _, err := b.DownloadFile(ctx, "big", dst+"2"); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("damaged parallel download accepted: %v", err)
	}
}
