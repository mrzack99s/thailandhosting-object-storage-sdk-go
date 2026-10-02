package objectstorage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeService is an in-memory implementation of the /v1 API, enough to
// exercise the SDK offline. It checks request signatures and body digests
// the way the service does, and answers errors as Problem Details.
type fakeService struct {
	mu         sync.Mutex
	objects    map[string][]byte // bucket/key
	types      map[string]string
	digests    map[string]string // bucket/key: Repr-Digest of single uploads
	uploads    map[string]map[int][]byte
	public     map[string][]PublicRule // bucket: what anyone may read
	flaky      atomic.Int32            // answer 503 to this many requests first
	retryAfter string                  // Retry-After sent with those 503s
	corrupt    atomic.Bool             // store one byte wrong
	badRepr    atomic.Bool             // serve objects with a wrong Repr-Digest
	inflight   atomic.Int32
	maxFlight  atomic.Int32
	requests   atomic.Int32
	digested   atomic.Int32 // requests with a body that carried a valid Content-Digest
	bearer     atomic.Bool  // an Authorization header was seen
}

func newFake() *fakeService {
	return &fakeService{objects: map[string][]byte{}, types: map[string]string{}, digests: map[string]string{}, uploads: map[string]map[int][]byte{}, public: map[string][]PublicRule{}}
}

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fail answers an error as the service does: Problem Details (RFC 9457),
// and only X-Error-Code for HEAD.
func fail(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("X-Error-Code", code)
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "tag:thailandhosting.com,2026:object-storage/" + code,
		"title": "fake: " + code, "status": status, "code": code, "instance": r.URL.Path})
}

const testSecret = "SECRET"

// verifySignature checks an HTTP Message Signature as the service does:
// rebuild the signature base from the request as it arrived and compare
// the HMAC. It returns "" when the signature is good.
func verifySignature(r *http.Request, now time.Time) string {
	input := r.Header.Get("Signature-Input")
	inner, ok := strings.CutPrefix(input, "th=(")
	if !ok {
		return "Signature-Input is not th=(...)"
	}
	list, paramStr, ok := strings.Cut(inner, ")")
	if !ok {
		return "unterminated inner list"
	}
	var components []string
	for _, c := range strings.Fields(list) {
		components = append(components, strings.Trim(c, `"`))
	}
	var created int64
	var keyID, alg string
	for _, p := range strings.Split(strings.TrimPrefix(paramStr, ";"), ";") {
		k, v, _ := strings.Cut(p, "=")
		switch k {
		case "created":
			created, _ = strconv.ParseInt(v, 10, 64)
		case "keyid":
			keyID = strings.Trim(v, `"`)
		case "alg":
			alg = strings.Trim(v, `"`)
		}
	}
	// Our profile: exactly these parameters, in this order.
	canonical := fmt.Sprintf(`(%s);created=%d;keyid="%s";alg="hmac-sha256"`, list, created, keyID)
	if input != "th="+canonical {
		return "parameters are not created, keyid, alg: " + input
	}
	if keyID != "KEY" || alg != "hmac-sha256" {
		return "unknown key or alg"
	}
	if d := now.Sub(time.Unix(created, 0)); d > 5*time.Minute || d < -5*time.Minute {
		return "created is too far from our clock"
	}
	covered := map[string]bool{}
	for _, c := range components {
		covered[c] = true
	}
	for _, need := range []string{"@method", "@authority", "@path", "@query"} {
		if !covered[need] {
			return "does not cover " + need
		}
	}
	if r.ContentLength != 0 && !covered["content-digest"] {
		return "a body without a signed Content-Digest"
	}
	var base strings.Builder
	for _, c := range components {
		var v string
		switch c {
		case "@method":
			v = r.Method
		case "@authority":
			v = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(r.Host), ":443"), ":80")
		case "@path":
			v = r.URL.EscapedPath()
		case "@query":
			v = "?" + r.URL.RawQuery
		default:
			if r.Header.Get(c) == "" {
				return "the request has no " + c
			}
			v = r.Header.Get(c)
		}
		base.WriteString(`"` + c + `": ` + v + "\n")
	}
	base.WriteString(`"@signature-params": ` + canonical)
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(base.String()))
	want := "th=:" + base64.StdEncoding.EncodeToString(mac.Sum(nil)) + ":"
	if r.Header.Get("Signature") != want {
		return "signature does not match"
	}
	return ""
}

func (f *fakeService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		m := f.maxFlight.Load()
		if n <= m || f.maxFlight.CompareAndSwap(m, n) {
			break
		}
	}
	if r.Header.Get("Authorization") != "" {
		f.bearer.Store(true)
	}
	if r.Header.Get("Signature-Input") != "" {
		if why := verifySignature(r, time.Now()); why != "" {
			w.Header().Set("Accept-Signature", `th=("@method" "@authority" "@path" "@query" "content-digest");alg="hmac-sha256"`)
			fail(w, r, 401, "invalid_signature")
			return
		}
	} else if !f.publicRead(r) {
		fail(w, r, 401, "unauthorized")
		return
	}
	if cd := r.Header.Get("Content-Digest"); cd != "" {
		body, _ := io.ReadAll(r.Body)
		if sum := sha256.Sum256(body); cd != "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":" {
			fail(w, r, 400, "bad_digest")
			return
		}
		f.digested.Add(1)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	if f.flaky.Load() > 0 && f.flaky.Add(-1) >= 0 {
		io.Copy(io.Discard, r.Body)
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		fail(w, r, 503, "busy")
		return
	}
	time.Sleep(2 * time.Millisecond) // lets parallel requests overlap
	parts := strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/v1/buckets/"), "/", 3)
	bucket := parts[0]
	switch {
	case len(parts) == 3 && strings.HasPrefix(parts[1]+"/"+parts[2], "objects/"):
		key, _ := url.PathUnescape(parts[2])
		f.object(w, r, bucket+"/"+key, key)
	case len(parts) == 2 && parts[1] == "objects":
		f.list(w, r, bucket)
	case len(parts) == 2 && parts[1] == "public":
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodPut {
			var in struct {
				Rules []PublicRule `json:"rules"`
			}
			json.NewDecoder(r.Body).Decode(&in)
			f.public[bucket] = in.Rules
		}
		writeJSON(w, 200, map[string]any{"rules": f.public[bucket]})
	case len(parts) >= 2 && parts[1] == "uploads":
		f.upload(w, r, bucket, parts)
	default:
		fail(w, r, 404, "not_found")
	}
}

// publicRead reports an unsigned GET or HEAD of an object a bucket made
// public.
func (f *fakeService) publicRead(r *http.Request) bool {
	if r.Header.Get("Signature-Input") != "" || r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.EscapedPath(), "/v1/buckets/"), "/", 3)
	if len(parts) != 3 || parts[1] != "objects" {
		return false
	}
	key, _ := url.PathUnescape(parts[2])
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.public[parts[0]] {
		if strings.HasPrefix(key, p.Prefix) {
			return true
		}
	}
	return false
}

// fakeModified is every fake object's Last-Modified.
var fakeModified = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// tagListed reports whether an If-Match / If-None-Match value lists etag
// (quoted) or is "*".
func tagListed(v, etag string) bool {
	for _, t := range strings.Split(v, ",") {
		if t = strings.TrimSpace(t); t == "*" || t == etag {
			return true
		}
	}
	return false
}

// writeCondFails applies If-Match / If-None-Match to a write (RFC 9110).
func writeCondFails(r *http.Request, exists bool, etag string) bool {
	if m := r.Header.Get("If-Match"); m != "" && (!exists || !tagListed(m, etag)) {
		return true
	}
	if m := r.Header.Get("If-None-Match"); m != "" && exists && tagListed(m, etag) {
		return true
	}
	return false
}

func (f *fakeService) object(w http.ResponseWriter, r *http.Request, id, key string) {
	f.mu.Lock()
	data, ok := f.objects[id]
	ct, repr := f.types[id], f.digests[id]
	f.mu.Unlock()
	etag := `"` + md5hex(data) + `"`
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if int64(len(body)) != r.ContentLength {
			fail(w, r, 400, "incomplete_body")
			return
		}
		if f.corrupt.Load() && len(body) > 0 {
			body[0] ^= 1 // damaged on the way: the ETag is of what arrived
		}
		f.mu.Lock()
		old, exists := f.objects[id]
		if writeCondFails(r, exists, `"`+md5hex(old)+`"`) {
			f.mu.Unlock()
			fail(w, r, 412, "precondition_failed")
			return
		}
		f.objects[id], f.types[id], f.digests[id] = body, r.Header.Get("Content-Type"), r.Header.Get("Content-Digest")
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"key": key, "size": len(body), "etag": md5hex(body)})
	case http.MethodGet, http.MethodHead:
		if !ok {
			fail(w, r, 404, "object_not_found")
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", fakeModified.Format(http.TimeFormat))
		if repr != "" {
			if f.badRepr.Load() {
				repr = contentDigest([]byte("something else"))
			}
			w.Header().Set("Repr-Digest", repr)
		}
		if m := r.Header.Get("If-Match"); m != "" && !tagListed(m, etag) {
			fail(w, r, 412, "precondition_failed")
			return
		}
		if t, err := http.ParseTime(r.Header.Get("If-Unmodified-Since")); err == nil && r.Header.Get("If-Match") == "" && fakeModified.After(t) {
			fail(w, r, 412, "precondition_failed")
			return
		}
		if m := r.Header.Get("If-None-Match"); m != "" && tagListed(m, etag) {
			w.WriteHeader(304)
			return
		}
		if t, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && r.Header.Get("If-None-Match") == "" && !fakeModified.After(t) {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("Content-Type", ct)
		start, end := int64(0), int64(len(data))-1
		status := 200
		if rg := r.Header.Get("Range"); rg != "" {
			spec := strings.TrimPrefix(rg, "bytes=")
			a, b, _ := strings.Cut(spec, "-")
			start, _ = strconv.ParseInt(a, 10, 64)
			if b != "" {
				end, _ = strconv.ParseInt(b, 10, 64)
			}
			end = min(end, int64(len(data))-1)
			status = 206
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		}
		w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(status)
		if r.Method == http.MethodGet {
			w.Write(data[start : end+1])
		}
	case http.MethodDelete:
		f.mu.Lock()
		old, exists := f.objects[id]
		if writeCondFails(r, exists, `"`+md5hex(old)+`"`) {
			f.mu.Unlock()
			fail(w, r, 412, "precondition_failed")
			return
		}
		delete(f.objects, id)
		delete(f.digests, id)
		f.mu.Unlock()
		w.WriteHeader(204)
	}
}

func (f *fakeService) list(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit == 0 {
		limit = 1000
	}
	after := ""
	if c := q.Get("cursor"); c != "" {
		b, _ := base64.RawURLEncoding.DecodeString(c)
		after = string(b)
	}
	f.mu.Lock()
	var keys []string
	for id := range f.objects {
		if k, ok := strings.CutPrefix(id, bucket+"/"); ok && strings.HasPrefix(k, q.Get("prefix")) && k > after {
			keys = append(keys, k)
		}
	}
	f.mu.Unlock()
	sort.Strings(keys)
	out := map[string]any{}
	if len(keys) > limit {
		keys = keys[:limit]
		out["nextCursor"] = base64.RawURLEncoding.EncodeToString([]byte(keys[limit-1]))
	}
	objs := []map[string]any{}
	for _, k := range keys {
		objs = append(objs, map[string]any{"key": k, "size": len(f.objects[bucket+"/"+k])})
	}
	out["objects"], out["folders"] = objs, []string{}
	writeJSON(w, 200, out)
}

func (f *fakeService) upload(w http.ResponseWriter, r *http.Request, bucket string, parts []string) {
	if len(parts) == 2 {
		var in struct{ Key string }
		json.NewDecoder(r.Body).Decode(&in)
		id := base64.RawURLEncoding.EncodeToString([]byte(in.Key)) + "." + strconv.Itoa(int(f.requests.Load()))
		f.mu.Lock()
		f.uploads[id] = map[int][]byte{}
		f.mu.Unlock()
		writeJSON(w, 201, map[string]string{"uploadId": id, "key": in.Key})
		return
	}
	id, sub, _ := strings.Cut(parts[2], "/")
	f.mu.Lock()
	up, ok := f.uploads[id]
	f.mu.Unlock()
	if !ok {
		fail(w, r, 404, "upload_not_found")
		return
	}
	k, _ := base64.RawURLEncoding.DecodeString(strings.Split(id, ".")[0])
	key := string(k)
	switch {
	case strings.HasPrefix(sub, "parts/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(sub, "parts/"))
		body, _ := io.ReadAll(r.Body)
		if f.corrupt.Load() && len(body) > 0 {
			body[0] ^= 1
		}
		f.mu.Lock()
		up[n] = body
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"number": n, "etag": md5hex(body), "size": len(body)})
	case sub == "complete":
		var in struct {
			Parts []struct {
				Number int
				ETag   string
			}
		}
		json.NewDecoder(r.Body).Decode(&in)
		var all []byte
		f.mu.Lock()
		old, exists := f.objects[bucket+"/"+key]
		if writeCondFails(r, exists, `"`+md5hex(old)+`"`) {
			f.mu.Unlock()
			fail(w, r, 412, "precondition_failed")
			return
		}
		for i, p := range in.Parts {
			data, ok := up[p.Number]
			if !ok || md5hex(data) != p.ETag || (i < len(in.Parts)-1 && len(data) < minPartSize) {
				f.mu.Unlock()
				fail(w, r, 400, "invalid_part")
				return
			}
			all = append(all, data...)
		}
		f.objects[bucket+"/"+key] = all
		delete(f.digests, bucket+"/"+key) // objects joined from parts have no Repr-Digest
		delete(f.uploads, id)
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"key": key, "size": len(all), "etag": "x-" + strconv.Itoa(len(in.Parts))})
	case sub == "" && r.Method == http.MethodDelete:
		f.mu.Lock()
		delete(f.uploads, id)
		f.mu.Unlock()
		w.WriteHeader(204)
	}
}

func newTestClient(t *testing.T, f *fakeService) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, AccessKeyID: "KEY", SecretAccessKey: "SECRET", PartSize: minPartSize, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func randomData(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestPutGetAndKeyEscaping(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	ctx := context.Background()
	key := "รูป/a b+c?#%.jpg"
	if _, err := b.PutBytes(ctx, key, []byte("hello"), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.objects["b/"+key]; !ok {
		t.Fatalf("stored under %v", f.objects)
	}
	got, err := b.GetBytes(ctx, key)
	if err != nil || string(got) != "hello" {
		t.Fatalf("get %q %v", got, err)
	}
	if _, err := b.GetBytes(ctx, "missing"); !IsNotFound(err) || ErrorCode(err) != "object_not_found" {
		t.Fatalf("missing: %v", err)
	}
	if ok, _ := b.Exists(ctx, key); !ok {
		t.Fatal("exists")
	}
}

func TestRetriesBusyAnswers(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	f.flaky.Store(2)
	if _, err := b.PutBytes(context.Background(), "k", []byte("data"), nil); err != nil {
		t.Fatalf("put after two 503s: %v", err)
	}
	if string(f.objects["b/k"]) != "data" {
		t.Fatal("retried body differs")
	}
}

func TestDetectsCorruptedUpload(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	f.corrupt.Store(true)
	// Bytes damaged on the way give an ETag that is not the MD5 sent.
	if _, err := b.PutBytes(context.Background(), "k", []byte("data"), nil); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("damaged upload accepted: %v", err)
	}
	data := randomData(minPartSize + 10)
	if _, err := b.Upload(context.Background(), "big", bytes.NewReader(data), -1, nil); err == nil {
		t.Fatal("damaged part accepted")
	}
	if len(f.uploads) != 0 {
		t.Fatal("upload with a damaged part was not aborted")
	}
}

func TestUploadStreamInParallelParts(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	data := randomData(5*minPartSize + 1234) // 6 parts
	// An io.Reader of unknown length: read part by part, sent in parallel.
	obj, err := b.Upload(context.Background(), "big.bin", io.MultiReader(bytes.NewReader(data)), -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != int64(len(data)) || !bytes.Equal(f.objects["b/big.bin"], data) {
		t.Fatalf("multipart object differs (%d bytes)", obj.Size)
	}
	if f.maxFlight.Load() < 2 {
		t.Fatalf("parts were not sent in parallel (max %d at once)", f.maxFlight.Load())
	}
	if len(f.uploads) != 0 {
		t.Fatal("upload left open")
	}
}

func TestUploadSmallStreamIsOneRequest(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	if _, err := b.Upload(context.Background(), "small.txt", strings.NewReader("tiny"), -1, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.requests.Load(); got != 1 {
		t.Fatalf("%d requests for a small upload", got)
	}
	if f.types["b/small.txt"] != "text/plain; charset=utf-8" {
		t.Fatalf("content type %q", f.types["b/small.txt"])
	}
}

func TestUploadFileAndParallelDownload(t *testing.T) {
	f := newFake()
	c := newTestClient(t, f)
	b := c.Bucket("b")
	dir := t.TempDir()
	data := randomData(3*minPartSize + 77)
	src := filepath.Join(dir, "src.bin")
	os.WriteFile(src, data, 0o644)
	f.flaky.Store(3) // some parts are retried from the file
	if _, err := b.UploadFile(context.Background(), "file.bin", src, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.objects["b/file.bin"], data) {
		t.Fatal("uploaded file differs")
	}
	dst := filepath.Join(dir, "out", "dst.bin")
	f.maxFlight.Store(0)
	if _, err := b.DownloadFile(context.Background(), "file.bin", dst); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded file differs")
	}
	if f.maxFlight.Load() < 2 {
		t.Fatal("ranges were not fetched in parallel")
	}
	if _, err := os.Stat(dst + ".download"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temporary file left behind")
	}
}

func TestFailedUploadIsAborted(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	ctx, cancel := context.WithCancel(context.Background())
	r := &cancelAfter{r: bytes.NewReader(randomData(4 * minPartSize)), left: 2 * minPartSize, cancel: cancel}
	if _, err := b.Upload(ctx, "x", r, -1, nil); err == nil {
		t.Fatal("cancelled upload succeeded")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.uploads) != 0 {
		t.Fatal("cancelled upload was not aborted")
	}
}

type cancelAfter struct {
	r      io.Reader
	left   int
	cancel func()
}

func (c *cancelAfter) Read(p []byte) (int, error) {
	if c.left <= 0 {
		c.cancel()
		return 0, context.Canceled
	}
	p = p[:min(len(p), c.left)]
	n, err := c.r.Read(p)
	c.left -= n
	return n, err
}

func TestObjectsIteratorPages(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	for i := 0; i < 25; i++ {
		f.objects[fmt.Sprintf("b/p/%02d", i)] = []byte{1}
	}
	n := 0
	for o, err := range b.Objects(context.Background(), "p/") {
		if err != nil {
			t.Fatal(err)
		}
		if o.Key != fmt.Sprintf("p/%02d", n) {
			t.Fatalf("key %d = %s", n, o.Key)
		}
		n++
	}
	if n != 25 {
		t.Fatalf("%d objects", n)
	}
}

func TestPartSizeGrowsForHugeObjects(t *testing.T) {
	c, _ := New(Config{Endpoint: "https://x", AccessKeyID: "a", SecretAccessKey: "b"})
	size := int64(500) << 30 // 500 GiB
	ps := c.partSizeFor(size)
	if (size+ps-1)/ps > maxParts {
		t.Fatalf("part size %d gives too many parts", ps)
	}
}

func TestIterateWithoutRangeFunc(t *testing.T) {
	f := newFake()
	b := newTestClient(t, f).Bucket("b")
	for i := 0; i < 7; i++ {
		f.objects[fmt.Sprintf("b/q/%d", i)] = []byte{1}
	}
	it := b.Iterate(context.Background(), "q/")
	n := 0
	for it.Next() {
		n++
	}
	if it.Err() != nil || n != 7 {
		t.Fatalf("%d objects, %v", n, it.Err())
	}
}

func TestPublicAccess(t *testing.T) {
	f := newFake()
	srv := httptest.NewServer(f)
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, AccessKeyID: "KEY", SecretAccessKey: "SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b := c.Bucket("site")
	for _, key := range []string{"public/a b.txt", "private/x.txt"} {
		if _, err := b.PutBytes(ctx, key, []byte("hello"), nil); err != nil {
			t.Fatal(err)
		}
	}
	rules, err := b.SetPublicAccess(ctx, []PublicRule{{Prefix: "public/"}})
	if err != nil || len(rules) != 1 || rules[0].Prefix != "public/" {
		t.Fatalf("set: %v %v", rules, err)
	}
	if got, err := b.PublicAccess(ctx); err != nil || len(got) != 1 {
		t.Fatalf("get: %v %v", got, err)
	}
	if got, want := b.PublicURL("public/a b.txt"), srv.URL+"/site/public/a%20b.txt"; got != want {
		t.Fatalf("PublicURL %q, want %q", got, want)
	}

	// Without a key the client reads what is public, nothing else.
	anon, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := anon.Bucket("site").GetBytes(ctx, "public/a b.txt"); err != nil || string(data) != "hello" {
		t.Fatalf("anonymous public read: %q %v", data, err)
	}
	if _, err := anon.Bucket("site").GetBytes(ctx, "private/x.txt"); err == nil {
		t.Fatal("anonymous read of a private object")
	}
	if _, err := New(Config{Endpoint: srv.URL, AccessKeyID: "KEY"}); err == nil {
		t.Fatal("a key without its secret was accepted")
	}
}
