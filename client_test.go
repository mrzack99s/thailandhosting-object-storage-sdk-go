package objectstorage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
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
// exercise the SDK offline.
type fakeService struct {
	mu        sync.Mutex
	objects   map[string][]byte // bucket/key
	types     map[string]string
	uploads   map[string]map[int][]byte
	flaky     atomic.Int32 // answer 503 to this many requests first
	corrupt   atomic.Bool  // store one byte wrong
	inflight  atomic.Int32
	maxFlight atomic.Int32
	requests  atomic.Int32
}

func newFake() *fakeService {
	return &fakeService{objects: map[string][]byte{}, types: map[string]string{}, uploads: map[string]map[int][]byte{}}
}

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": code}})
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
	if r.Header.Get("Authorization") != "Bearer KEY:SECRET" {
		fail(w, 401, "unauthorized")
		return
	}
	if f.flaky.Load() > 0 && f.flaky.Add(-1) >= 0 {
		io.Copy(io.Discard, r.Body)
		fail(w, 503, "busy")
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
	case len(parts) >= 2 && parts[1] == "uploads":
		f.upload(w, r, bucket, parts)
	default:
		fail(w, 404, "not_found")
	}
}

func (f *fakeService) object(w http.ResponseWriter, r *http.Request, id, key string) {
	f.mu.Lock()
	data, ok := f.objects[id]
	ct := f.types[id]
	f.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if int64(len(body)) != r.ContentLength {
			fail(w, 400, "incomplete_body")
			return
		}
		if f.corrupt.Load() && len(body) > 0 {
			body[0] ^= 1 // damaged on the way: the ETag is of what arrived
		}
		etag := md5hex(body)
		f.mu.Lock()
		f.objects[id], f.types[id] = body, r.Header.Get("Content-Type")
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"key": key, "size": len(body), "etag": etag})
	case http.MethodGet, http.MethodHead:
		if !ok {
			fail(w, 404, "object_not_found")
			return
		}
		etag := `"` + md5hex(data) + `"`
		if m := r.Header.Get("If-Match"); m != "" && m != etag {
			fail(w, 412, "precondition_failed")
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
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
		delete(f.objects, id)
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
		fail(w, 404, "upload_not_found")
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
		for i, p := range in.Parts {
			data, ok := up[p.Number]
			if !ok || md5hex(data) != p.ETag || (i < len(in.Parts)-1 && len(data) < minPartSize) {
				f.mu.Unlock()
				fail(w, 400, "invalid_part")
				return
			}
			all = append(all, data...)
		}
		f.objects[bucket+"/"+key] = all
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
