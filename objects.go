package objectstorage

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Object describes a stored object.
type Object struct {
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	LastModified time.Time         `json:"lastModified"`
	ContentType  string            `json:"contentType,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// PutOptions are the optional settings of an upload.
type PutOptions struct {
	ContentType        string
	CacheControl       string
	ContentDisposition string
	ContentEncoding    string
	ContentLanguage    string
	// Metadata is stored with the object and returned as X-Meta-<name>
	// (names are case-insensitive; at most 2 KB in all).
	Metadata map[string]string
	// IfNotExists fails the upload with code "precondition_failed" when
	// the key already holds an object (single uploads only).
	IfNotExists bool
}

func (o *PutOptions) header() http.Header {
	h := http.Header{}
	if o == nil {
		return h
	}
	set := func(k, v string) {
		if v != "" {
			h.Set(k, v)
		}
	}
	set("Content-Type", o.ContentType)
	set("Cache-Control", o.CacheControl)
	set("Content-Disposition", o.ContentDisposition)
	set("Content-Encoding", o.ContentEncoding)
	set("Content-Language", o.ContentLanguage)
	for k, v := range o.Metadata {
		h.Set("X-Meta-"+k, v)
	}
	if o.IfNotExists {
		h.Set("If-None-Match", "*")
	}
	return h
}

func (b *Bucket) objectPath(key string) string { return b.path + "/objects/" + escapeKey(key) }

// hashingReader feeds what it reads into an MD5 so the stored ETag can be
// checked without reading the data twice.
type hashingReader struct {
	r io.Reader
	h hash.Hash
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.h.Write(p[:n])
	return n, err
}

// verifyETag compares a single-part ETag (an MD5) with what was sent.
func verifyETag(etag string, sum []byte) error {
	etag = strings.Trim(etag, `"`)
	if len(etag) != 32 || strings.Contains(etag, "-") {
		return nil // not an MD5 (a multipart object): nothing to compare
	}
	if etag != hex.EncodeToString(sum) {
		return fmt.Errorf("objectstorage: the stored data does not match what was sent (ETag %s, MD5 %x)", etag, sum)
	}
	return nil
}

// putSingle uploads size bytes in one request. open returns the body from
// its start; it is called again for each retry.
func (b *Bucket) putSingle(ctx context.Context, key string, open func() (io.Reader, error), size int64, opts *PutOptions) (*Object, error) {
	var hr *hashingReader
	resp, err := b.c.do(ctx, request{method: http.MethodPut, path: b.objectPath(key), header: opts.header(), size: size,
		body: func() (io.Reader, error) {
			r, err := open()
			if err != nil {
				return nil, err
			}
			hr = &hashingReader{r: r, h: md5.New()}
			return hr, nil
		}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out Object
	if err := decodeJSON(resp, &out); err != nil {
		return nil, err
	}
	if err := verifyETag(out.ETag, hr.h.Sum(nil)); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutBytes uploads data as one object.
func (b *Bucket) PutBytes(ctx context.Context, key string, data []byte, opts *PutOptions) (*Object, error) {
	return b.putSingle(ctx, key, func() (io.Reader, error) { return bytes.NewReader(data), nil }, int64(len(data)), opts)
}

// HeadOptions and GetOptions select what to download.
type GetOptions struct {
	// Range downloads part of the object: bytes Offset..Offset+Length-1
	// (Length 0: to the end).
	Offset, Length int64
	// IfNoneMatch makes Get return ErrNotModified when the object's ETag is
	// this one (a cached copy is still current).
	IfNoneMatch string
	// IfMatch fails the download with code "precondition_failed" unless
	// the object's ETag is this one.
	IfMatch string
}

// ErrNotModified is returned by Get when GetOptions.IfNoneMatch matched.
var ErrNotModified = errors.New("objectstorage: not modified")

// ObjectReader is a download in progress; Close it.
type ObjectReader struct {
	io.ReadCloser
	Object
	// ContentRange is set for a range download ("bytes 0-99/1234").
	ContentRange string
}

func objectFromHeader(key string, h http.Header) Object {
	o := Object{Key: key, ETag: strings.Trim(h.Get("ETag"), `"`), ContentType: h.Get("Content-Type")}
	if t, err := http.ParseTime(h.Get("Last-Modified")); err == nil {
		o.LastModified = t
	}
	for k, v := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-meta-") && len(v) > 0 {
			if o.Metadata == nil {
				o.Metadata = map[string]string{}
			}
			o.Metadata[strings.TrimPrefix(lk, "x-meta-")] = v[0]
		}
	}
	if cr := h.Get("Content-Range"); cr != "" {
		if _, total, ok := strings.Cut(cr, "/"); ok {
			o.Size, _ = strconv.ParseInt(total, 10, 64)
		}
	} else {
		o.Size, _ = strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	}
	return o
}

func (o *GetOptions) header() http.Header {
	h := http.Header{}
	if o == nil {
		return h
	}
	if o.Offset > 0 || o.Length > 0 {
		if o.Length > 0 {
			h.Set("Range", fmt.Sprintf("bytes=%d-%d", o.Offset, o.Offset+o.Length-1))
		} else {
			h.Set("Range", fmt.Sprintf("bytes=%d-", o.Offset))
		}
	}
	if o.IfNoneMatch != "" {
		h.Set("If-None-Match", `"`+strings.Trim(o.IfNoneMatch, `"`)+`"`)
	}
	if o.IfMatch != "" {
		h.Set("If-Match", `"`+strings.Trim(o.IfMatch, `"`)+`"`)
	}
	return h
}

// Get streams an object (or a range of it). Object.Size is the whole
// object's size. Close the reader.
func (b *Bucket) Get(ctx context.Context, key string, opts *GetOptions) (*ObjectReader, error) {
	resp, err := b.c.do(ctx, request{method: http.MethodGet, path: b.objectPath(key), header: opts.header(), expect: []int{200, 206, 304}})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		resp.Body.Close()
		return nil, ErrNotModified
	}
	return &ObjectReader{ReadCloser: resp.Body, Object: objectFromHeader(key, resp.Header), ContentRange: resp.Header.Get("Content-Range")}, nil
}

// GetBytes downloads a whole object into memory.
func (b *Bucket) GetBytes(ctx context.Context, key string) ([]byte, error) {
	r, err := b.Get(ctx, key, nil)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// One allocation of the right size, then a single copy.
	var buf bytes.Buffer
	buf.Grow(int(max(r.Size, 0)) + bytes.MinRead)
	_, err = buf.ReadFrom(r)
	return buf.Bytes(), err
}

// Head returns an object's details without its data.
func (b *Bucket) Head(ctx context.Context, key string) (*Object, error) {
	resp, err := b.c.do(ctx, request{method: http.MethodHead, path: b.objectPath(key)})
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	o := objectFromHeader(key, resp.Header)
	return &o, nil
}

// Exists reports whether key holds an object.
func (b *Bucket) Exists(ctx context.Context, key string) (bool, error) {
	_, err := b.Head(ctx, key)
	if IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// Delete deletes an object; deleting a missing one succeeds.
func (b *Bucket) Delete(ctx context.Context, key string) error {
	resp, err := b.c.do(ctx, request{method: http.MethodDelete, path: b.objectPath(key)})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// DeleteMany deletes keys in parallel (Config.Concurrency at once) and
// returns the first error, after trying them all.
func (b *Bucket) DeleteMany(ctx context.Context, keys []string) error {
	return parallel(ctx, b.c.workers, len(keys), func(ctx context.Context, i int) error { return b.Delete(ctx, keys[i]) })
}

// CopyOptions are the optional settings of a copy.
type CopyOptions struct {
	// SourceBucket copies from another bucket of the same Project (default:
	// this bucket).
	SourceBucket string
	// Metadata replaces the copy's metadata (nil keeps the source's).
	Metadata map[string]string
}

// Copy copies srcKey to dstKey inside the service, without downloading.
func (b *Bucket) Copy(ctx context.Context, srcKey, dstKey string, opts *CopyOptions) (*Object, error) {
	in := map[string]any{"from": map[string]string{"bucket": b.name, "key": srcKey}, "key": dstKey}
	if opts != nil {
		if opts.SourceBucket != "" {
			in["from"] = map[string]string{"bucket": opts.SourceBucket, "key": srcKey}
		}
		if opts.Metadata != nil {
			in["metadata"] = opts.Metadata
		}
	}
	var out Object
	if err := b.c.doJSON(ctx, http.MethodPost, b.path+"/copy", nil, in, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOptions select which objects to list.
type ListOptions struct {
	Prefix string
	// Delimiter rolls keys up into folders ("/" lists one folder level).
	Delimiter string
	// Cursor continues a previous page (ListPage.NextCursor).
	Cursor string
	// Limit is the page size (1-1000, default 1000).
	Limit int
}

// ListPage is one page of a listing.
type ListPage struct {
	Objects []Object `json:"objects"`
	// Folders are the common prefixes when a Delimiter was given.
	Folders []string `json:"folders"`
	// NextCursor continues the listing; empty on the last page.
	NextCursor string `json:"nextCursor"`
}

// List returns one page of objects.
func (b *Bucket) List(ctx context.Context, opts *ListOptions) (*ListPage, error) {
	q := url.Values{}
	if opts != nil {
		if opts.Prefix != "" {
			q.Set("prefix", opts.Prefix)
		}
		if opts.Delimiter != "" {
			q.Set("delimiter", opts.Delimiter)
		}
		if opts.Cursor != "" {
			q.Set("cursor", opts.Cursor)
		}
		if opts.Limit > 0 {
			q.Set("limit", strconv.Itoa(opts.Limit))
		}
	}
	var page ListPage
	if err := b.c.doJSON(ctx, http.MethodGet, b.path+"/objects", q, nil, &page, false); err != nil {
		return nil, err
	}
	return &page, nil
}

// LinkOptions configure a shared link.
type LinkOptions struct {
	// Expires is how long the link works (default 1 hour, at most 7 days).
	Expires time.Duration
	// Upload makes a link that uploads (PUT) instead of downloads (GET).
	Upload bool
}

// Link is a URL that works without an access key until ExpiresAt.
type Link struct {
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// CreateLink makes a link to download (or upload) one object without an
// access key, for browsers, other people or another service.
func (b *Bucket) CreateLink(ctx context.Context, key string, opts *LinkOptions) (*Link, error) {
	in := map[string]any{"key": key}
	if opts != nil {
		if opts.Expires > 0 {
			in["expiresIn"] = int64(opts.Expires / time.Second)
		}
		if opts.Upload {
			in["method"] = http.MethodPut
		}
	}
	var out Link
	if err := b.c.doJSON(ctx, http.MethodPost, b.path+"/links", nil, in, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// ObjectIterator walks a listing page by page:
//
//	it := bucket.Iterate(ctx, "photos/")
//	for it.Next() {
//		fmt.Println(it.Object().Key)
//	}
//	if err := it.Err(); err != nil { ... }
type ObjectIterator struct {
	ctx    context.Context
	b      *Bucket
	opts   ListOptions
	page   []Object
	i      int
	cur    Object
	err    error
	last   bool
	loaded bool
}

// Iterate returns an iterator over every object under prefix.
func (b *Bucket) Iterate(ctx context.Context, prefix string) *ObjectIterator {
	return &ObjectIterator{ctx: ctx, b: b, opts: ListOptions{Prefix: prefix}}
}

// Next advances to the next object, fetching the next page when needed.
func (it *ObjectIterator) Next() bool {
	for it.i >= len(it.page) {
		if it.err != nil || (it.loaded && it.last) {
			return false
		}
		page, err := it.b.List(it.ctx, &it.opts)
		if err != nil {
			it.err = err
			return false
		}
		it.page, it.i, it.loaded = page.Objects, 0, true
		it.last = page.NextCursor == ""
		it.opts.Cursor = page.NextCursor
	}
	it.cur = it.page[it.i]
	it.i++
	return true
}

// Object is the current object.
func (it *ObjectIterator) Object() Object { return it.cur }

// Err is the error that stopped the iteration, if any.
func (it *ObjectIterator) Err() error { return it.err }
