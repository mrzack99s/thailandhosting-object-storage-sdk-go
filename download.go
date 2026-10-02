package objectstorage

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// DownloadTo writes an object into w. Objects above
// Config.MultipartThreshold are fetched as Config.Concurrency parallel
// ranges, each pinned to the object's ETag so a concurrent overwrite fails
// the download instead of mixing two versions.
func (b *Bucket) DownloadTo(ctx context.Context, key string, w io.WriterAt) (*Object, error) {
	obj, err := b.Head(ctx, key)
	if err != nil {
		return nil, err
	}
	if obj.Size <= b.c.threshold {
		return obj, b.downloadWhole(ctx, key, obj, w)
	}
	ps := b.c.partSize
	count := int((obj.Size + ps - 1) / ps)
	err = parallel(ctx, b.c.workers, count, func(ctx context.Context, i int) error {
		off := int64(i) * ps
		n := min(ps, obj.Size-off)
		return b.downloadRange(ctx, key, obj.ETag, w, off, n)
	})
	return obj, err
}

// downloadWhole streams a small object in one request and checks it
// against its ETag when that is an MD5.
func (b *Bucket) downloadWhole(ctx context.Context, key string, obj *Object, w io.WriterAt) error {
	r, err := b.Get(ctx, key, &GetOptions{IfMatch: obj.ETag})
	if err != nil {
		return err
	}
	defer r.Close()
	h := md5.New()
	n, err := io.Copy(io.MultiWriter(io.NewOffsetWriter(w, 0), h), r)
	if err != nil {
		return err
	}
	if n != obj.Size {
		return fmt.Errorf("objectstorage: %s: got %d of %d bytes", key, n, obj.Size)
	}
	return verifyETag(obj.ETag, h.Sum(nil))
}

// downloadRange fetches n bytes at off, resuming from where a broken
// connection stopped (up to the retry limit).
func (b *Bucket) downloadRange(ctx context.Context, key, etag string, w io.WriterAt, off, n int64) error {
	done := int64(0)
	for attempt := 0; ; attempt++ {
		r, err := b.Get(ctx, key, &GetOptions{Offset: off + done, Length: n - done, IfMatch: etag})
		if err != nil {
			return err
		}
		k, err := io.Copy(io.NewOffsetWriter(w, off+done), io.LimitReader(r, n-done))
		r.Close()
		done += k
		if done == n {
			return nil
		}
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		if attempt >= b.c.retries || ctx.Err() != nil {
			return fmt.Errorf("objectstorage: %s bytes %d-%d: %w", key, off, off+n-1, err)
		}
		if err := sleep(ctx, backoff(attempt)); err != nil {
			return err
		}
	}
}

// DownloadFile saves an object to path. It writes to path+".download" and
// renames it into place, so path never holds a partial object.
func (b *Bucket) DownloadFile(ctx context.Context, key, path string) (*Object, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".download"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	obj, err := b.DownloadTo(ctx, key, f)
	if err == nil {
		err = f.Truncate(obj.Size)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return obj, nil
}
