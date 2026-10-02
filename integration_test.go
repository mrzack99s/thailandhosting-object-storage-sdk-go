package objectstorage

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestIntegration runs against a real endpoint when
// TH_OBJECT_STORAGE_ENDPOINT, TH_ACCESS_KEY_ID and TH_SECRET_ACCESS_KEY are
// set. It creates a bucket, uses it and deletes it.
func TestIntegration(t *testing.T) {
	endpoint := os.Getenv("TH_OBJECT_STORAGE_ENDPOINT")
	if endpoint == "" {
		t.Skip("TH_OBJECT_STORAGE_ENDPOINT is not set")
	}
	c, err := New(Config{Endpoint: endpoint, AccessKeyID: os.Getenv("TH_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("TH_SECRET_ACCESS_KEY")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	name := "sdk-go-it-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 36)
	if _, err := c.CreateBucket(ctx, name); err != nil {
		t.Fatal(err)
	}
	b := c.Bucket(name)
	defer func() {
		for o, err := range b.Objects(context.Background(), "") {
			if err == nil {
				b.Delete(context.Background(), o.Key)
			}
		}
		if err := c.DeleteBucket(context.Background(), name); err != nil {
			t.Errorf("delete bucket: %v", err)
		}
	}()

	// 40 MiB file: parallel parts up, parallel ranges down.
	dir := t.TempDir()
	data := randomData(40 << 20)
	src := filepath.Join(dir, "src.bin")
	os.WriteFile(src, data, 0o644)
	start := time.Now()
	obj, err := b.UploadFile(ctx, "big/file.bin", src, &PutOptions{Metadata: map[string]string{"origin": "go-sdk"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("uploaded %d MiB in %v (ETag %s)", obj.Size>>20, time.Since(start), obj.ETag)
	start = time.Now()
	dst := filepath.Join(dir, "dst.bin")
	if _, err := b.DownloadFile(ctx, "big/file.bin", dst); err != nil {
		t.Fatal(err)
	}
	t.Logf("downloaded in %v", time.Since(start))
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, data) {
		t.Fatal("downloaded file differs")
	}
	head, err := b.Head(ctx, "big/file.bin")
	if err != nil || head.Metadata["origin"] != "go-sdk" {
		t.Fatalf("head %+v %v", head, err)
	}

	// Small objects, ranges, listing, copy, links.
	if _, err := b.PutBytes(ctx, "notes/ไทย.txt", []byte("สวัสดี"), nil); err != nil {
		t.Fatal(err)
	}
	r, err := b.Get(ctx, "big/file.bin", &GetOptions{Offset: 100, Length: 50})
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(part, data[100:150]) {
		t.Fatal("range differs")
	}
	page, err := b.List(ctx, &ListOptions{Delimiter: "/"})
	if err != nil || len(page.Folders) != 2 {
		t.Fatalf("folders %+v %v", page, err)
	}
	if _, err := b.Copy(ctx, "notes/ไทย.txt", "notes/copy.txt", nil); err != nil {
		t.Fatal(err)
	}
	link, err := b.CreateLink(ctx, "notes/ไทย.txt", &LinkOptions{Expires: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(link.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "สวัสดี" {
		t.Fatalf("link served %q", body)
	}
}
