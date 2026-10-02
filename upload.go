package objectstorage

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Part is one uploaded part of a multipart upload.
type Part struct {
	Number       int       `json:"number"`
	ETag         string    `json:"etag"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"lastModified,omitempty"`
}

// MultipartUpload is a large upload in progress: send parts (in any
// order, in parallel), then Complete, or Abort. Upload and UploadFile do
// all of this for you.
type MultipartUpload struct {
	b   *Bucket
	ID  string `json:"uploadId"`
	Key string `json:"key"`
}

// CreateMultipartUpload starts a multipart upload of key.
func (b *Bucket) CreateMultipartUpload(ctx context.Context, key string, opts *PutOptions) (*MultipartUpload, error) {
	in := map[string]any{"key": key}
	if opts != nil {
		if opts.ContentType != "" {
			in["contentType"] = opts.ContentType
		}
		if len(opts.Metadata) > 0 {
			in["metadata"] = opts.Metadata
		}
	}
	u := &MultipartUpload{b: b}
	// A retried start may leave an unused upload behind; the service drops
	// those after a week, so retrying is safe.
	if err := b.c.doJSON(ctx, http.MethodPost, b.path+"/uploads", nil, in, u, true); err != nil {
		return nil, err
	}
	return u, nil
}

// ResumeMultipartUpload returns a handle for an upload started earlier
// (its ID from MultipartUpload.ID).
func (b *Bucket) ResumeMultipartUpload(key, uploadID string) *MultipartUpload {
	return &MultipartUpload{b: b, ID: uploadID, Key: key}
}

func (u *MultipartUpload) path() string { return u.b.path + "/uploads/" + u.ID }

// UploadPart sends part number n (1-10000). Every part but the last must
// be at least 5 MiB. Sending a number again replaces that part.
func (u *MultipartUpload) UploadPart(ctx context.Context, n int, data []byte) (Part, error) {
	return u.uploadPart(ctx, n, func() (io.Reader, error) { return bytes.NewReader(data), nil }, int64(len(data)))
}

// UploadPartFrom sends part n from r: size bytes starting at r's current
// offset (r is read again from there if the request is retried).
func (u *MultipartUpload) UploadPartFrom(ctx context.Context, n int, r io.ReaderAt, offset, size int64) (Part, error) {
	return u.uploadPart(ctx, n, func() (io.Reader, error) { return io.NewSectionReader(r, offset, size), nil }, size)
}

func (u *MultipartUpload) uploadPart(ctx context.Context, n int, open func() (io.Reader, error), size int64) (Part, error) {
	var hr *hashingReader
	resp, err := u.b.c.do(ctx, request{method: http.MethodPut, path: u.path() + "/parts/" + strconv.Itoa(n), size: size,
		header: http.Header{"Content-Type": {"application/octet-stream"}},
		body: func() (io.Reader, error) {
			r, err := open()
			if err != nil {
				return nil, err
			}
			hr = &hashingReader{r: r, h: md5.New()}
			return hr, nil
		}})
	if err != nil {
		return Part{}, err
	}
	defer resp.Body.Close()
	var p Part
	if err := decodeJSON(resp, &p); err != nil {
		return Part{}, err
	}
	if err := verifyETag(p.ETag, hr.h.Sum(nil)); err != nil {
		return Part{}, fmt.Errorf("part %d: %w", n, err)
	}
	p.Size = size
	return p, nil
}

// Parts lists the parts received so far.
func (u *MultipartUpload) Parts(ctx context.Context) ([]Part, error) {
	var out struct {
		Parts []Part `json:"parts"`
	}
	err := u.b.c.doJSON(ctx, http.MethodGet, u.path(), nil, nil, &out, false)
	return out.Parts, err
}

// Complete joins the parts into the object. With parts nil, every part
// received is used, in order.
func (u *MultipartUpload) Complete(ctx context.Context, parts []Part) (*Object, error) {
	var in any
	if parts != nil {
		sorted := append([]Part(nil), parts...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Number < sorted[j].Number })
		list := make([]map[string]any, len(sorted))
		for i, p := range sorted {
			list[i] = map[string]any{"number": p.Number, "etag": p.ETag}
		}
		in = map[string]any{"parts": list}
	}
	var out Object
	err := u.b.c.doJSON(ctx, http.MethodPost, u.path()+"/complete", nil, in, &out, true)
	if IsNotFound(err) {
		// A retry after a completion whose answer was lost: the upload is
		// gone because it became the object.
		if obj, herr := u.b.Head(ctx, u.Key); herr == nil {
			return obj, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Abort cancels the upload and deletes its parts.
func (u *MultipartUpload) Abort(ctx context.Context) error {
	err := u.b.c.doJSON(ctx, http.MethodDelete, u.path(), nil, nil, nil, false)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// abortQuietly cleans up after a failed upload, even when ctx is done.
func (u *MultipartUpload) abortQuietly(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	u.Abort(ctx)
}

// partSizeFor picks a part size that keeps an object of size bytes within
// the 10,000-part limit.
func (c *Client) partSizeFor(size int64) int64 {
	ps := c.partSize
	if size > 0 && (size+ps-1)/ps > maxParts {
		ps = (size + maxParts - 1) / maxParts
		ps = (ps + (1 << 20) - 1) &^ ((1 << 20) - 1) // round up to whole MiB
	}
	return ps
}

// Upload stores what r yields as key. size is r's length, or -1 when it is
// not known (a pipe, a network stream). Up to Config.MultipartThreshold the
// object goes in one request; above it, in parts of Config.PartSize sent
// Config.Concurrency at a time, holding at most Concurrency+1 parts in
// memory. An io.ReadSeeker is read again from its start on a retry; other
// readers are buffered part by part so parts can be retried.
func (b *Bucket) Upload(ctx context.Context, key string, r io.Reader, size int64, opts *PutOptions) (*Object, error) {
	opts = withContentType(opts, key)
	if size >= 0 && size <= b.c.threshold {
		if rs, ok := r.(io.ReadSeeker); ok {
			start, err := rs.Seek(0, io.SeekCurrent)
			if err == nil {
				return b.putSingle(ctx, key, func() (io.Reader, error) {
					if _, err := rs.Seek(start, io.SeekStart); err != nil {
						return nil, err
					}
					return io.LimitReader(rs, size), nil
				}, size, opts)
			}
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		return b.PutBytes(ctx, key, data, opts)
	}
	return b.uploadStream(ctx, key, r, size, opts)
}

// uploadStream reads r part by part into pooled buffers and uploads parts
// while the next ones are read.
func (b *Bucket) uploadStream(ctx context.Context, key string, r io.Reader, size int64, opts *PutOptions) (*Object, error) {
	ps := b.c.partSizeFor(size)
	pool := sync.Pool{New: func() any { buf := make([]byte, ps); return &buf }}
	readPart := func() (*[]byte, int, error) {
		buf := pool.Get().(*[]byte)
		n, err := io.ReadFull(r, *buf)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			err = io.EOF
		}
		return buf, n, err
	}
	first, n, rerr := readPart()
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		return nil, rerr
	}
	if errors.Is(rerr, io.EOF) {
		// It all fit in one part: one request is cheaper than three.
		defer pool.Put(first)
		return b.PutBytes(ctx, key, (*first)[:n], opts)
	}
	up, err := b.CreateMultipartUpload(ctx, key, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var (
		mu    sync.Mutex
		parts []Part
		wg    sync.WaitGroup
		slots = make(chan struct{}, b.c.workers)
	)
	send := func(num int, buf *[]byte, n int) {
		defer wg.Done()
		defer func() { <-slots }()
		defer pool.Put(buf)
		p, err := up.UploadPart(ctx, num, (*buf)[:n])
		if err != nil {
			cancel(err)
			return
		}
		mu.Lock()
		parts = append(parts, p)
		mu.Unlock()
	}
	num := 1
	buf, bn := first, n
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go send(num, buf, bn)
		if errors.Is(rerr, io.EOF) {
			break
		}
		num++
		if num > maxParts {
			cancel(fmt.Errorf("objectstorage: more than %d parts of %d bytes; set a larger PartSize or pass the size", maxParts, ps))
			break
		}
		buf, bn, rerr = readPart()
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			cancel(rerr)
			break
		}
		if bn == 0 && errors.Is(rerr, io.EOF) {
			pool.Put(buf)
			break
		}
	}
	wg.Wait()
	if err := context.Cause(ctx); err != nil {
		up.abortQuietly(ctx)
		return nil, err
	}
	obj, err := up.Complete(ctx, parts)
	if err != nil {
		up.abortQuietly(ctx)
		return nil, err
	}
	return obj, nil
}

// UploadFile uploads a local file. Large files are sent as parts read
// straight from the file in parallel (no part is copied into memory), and
// any part is re-read from disk if it has to be sent again.
func (b *Bucket) UploadFile(ctx context.Context, key, path string, opts *PutOptions) (*Object, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if opts == nil || opts.ContentType == "" {
		o := PutOptions{}
		if opts != nil {
			o = *opts
		}
		o.ContentType = mime.TypeByExtension(filepath.Ext(path))
		opts = &o
	}
	if size <= b.c.threshold {
		return b.putSingle(ctx, key, func() (io.Reader, error) { return io.NewSectionReader(f, 0, size), nil }, size, withContentType(opts, key))
	}
	return b.UploadReaderAt(ctx, key, f, size, opts)
}

// UploadReaderAt uploads size bytes of r (a file, a memory-mapped region)
// as parts sent in parallel straight from r.
func (b *Bucket) UploadReaderAt(ctx context.Context, key string, r io.ReaderAt, size int64, opts *PutOptions) (*Object, error) {
	opts = withContentType(opts, key)
	if size <= b.c.threshold {
		return b.putSingle(ctx, key, func() (io.Reader, error) { return io.NewSectionReader(r, 0, size), nil }, size, opts)
	}
	ps := b.c.partSizeFor(size)
	count := int((size + ps - 1) / ps)
	up, err := b.CreateMultipartUpload(ctx, key, opts)
	if err != nil {
		return nil, err
	}
	parts := make([]Part, count)
	err = parallel(ctx, b.c.workers, count, func(ctx context.Context, i int) error {
		off := int64(i) * ps
		p, err := up.UploadPartFrom(ctx, i+1, r, off, min(ps, size-off))
		parts[i] = p
		return err
	})
	if err != nil {
		up.abortQuietly(ctx)
		return nil, err
	}
	obj, err := up.Complete(ctx, parts)
	if err != nil {
		up.abortQuietly(ctx)
		return nil, err
	}
	return obj, nil
}

// withContentType guesses the content type from the key when none is set.
func withContentType(opts *PutOptions, key string) *PutOptions {
	if opts != nil && opts.ContentType != "" {
		return opts
	}
	o := PutOptions{}
	if opts != nil {
		o = *opts
	}
	o.ContentType = mime.TypeByExtension(filepath.Ext(key))
	if o.ContentType == "" {
		o.ContentType = "application/octet-stream"
	}
	return &o
}

// parallel runs fn(0..n-1), workers at a time, stopping at the first
// error (which it returns).
func parallel(ctx context.Context, workers, n int, fn func(context.Context, int) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < min(workers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := fn(ctx, i); err != nil {
					cancel(err)
				}
			}
		}()
	}
feed:
	for i := 0; i < n; i++ {
		select {
		case next <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()
	return context.Cause(ctx)
}

func decodeJSON(resp *http.Response, out any) error {
	return json.NewDecoder(resp.Body).Decode(out)
}
