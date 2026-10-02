# ThailandHosting Object Storage — Go SDK

Go client for [ThailandHosting Object Storage](https://www.thailandhosting.com):
buckets, objects, large files and share links over the ThailandHosting API.

```
go get github.com/mrzack99s/thailandhosting-object-storage-sdk-go
```

Go 1.23 or newer. No dependencies outside the standard library.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	objectstorage "github.com/mrzack99s/thailandhosting-object-storage-sdk-go"
)

func main() {
	client, err := objectstorage.New(objectstorage.Config{
		Endpoint:        "https://objects.bkk.thailandhosting.com",
		AccessKeyID:     os.Getenv("TH_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("TH_SECRET_ACCESS_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	bucket := client.Bucket("my-bucket")

	// Any size: large files go up as parallel parts.
	if _, err := bucket.UploadFile(ctx, "backups/db.dump", "/var/backups/db.dump", nil); err != nil {
		log.Fatal(err)
	}
	// Large objects come down as parallel ranges.
	if _, err := bucket.DownloadFile(ctx, "backups/db.dump", "/tmp/db.dump"); err != nil {
		log.Fatal(err)
	}
	// Every object under a prefix, page by page.
	for obj, err := range bucket.Objects(ctx, "backups/") {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(obj.Key, obj.Size)
	}
	// A link that works without a key for one hour.
	link, _ := bucket.CreateLink(ctx, "backups/db.dump", &objectstorage.LinkOptions{Expires: time.Hour})
	fmt.Println(link.URL)
}
```

Create access keys in the Console (Object Storage → Access keys). Reuse one
`Client` for the life of your program: it keeps connections open and is
safe for concurrent use.

## Performance

|               |                                                                                                                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Connections   | pooled keep-alive, HTTP/2 when available, 256 KiB socket buffers                                                                                                                         |
| Uploads       | `UploadFile` / `UploadReaderAt` read parts straight from the file in parallel (no copies in memory); `Upload` streams any `io.Reader`, holding at most `Concurrency + 1` parts in memory |
| Downloads     | `DownloadFile` / `DownloadTo` fetch parallel ranges into the file with `WriteAt`, each pinned to the object's ETag                                                                       |
| Small objects | one request; a stream that turns out small is sent in one request too                                                                                                                    |
| Tuning        | `Config.PartSize` (default 16 MiB), `Config.Concurrency` (default 8), `Config.MultipartThreshold` (default 32 MiB)                                                                       |

Objects larger than 10,000 × `PartSize` automatically get a larger part
size.

## Reliability

- Requests that are safe to repeat are retried with exponential backoff and
  jitter (`Config.MaxRetries`, default 4) on 429, 500, 502, 503, 504 and
  network errors; bodies are re-read from their start (files, seekable
  readers, buffered parts).
- Every single upload and every part is checked against the MD5 the
  service reports, so data damaged on the way is never accepted.
- A failed or cancelled multipart upload is aborted, so its parts are not
  billed.
- `DownloadFile` writes to `path.download` and renames it into place, so
  `path` never holds a partial object; a broken range resumes where it
  stopped.

## API

| Client                                                     |                                   |
| ---------------------------------------------------------- | --------------------------------- |
| `ListBuckets`, `CreateBucket`, `GetBucket`, `DeleteBucket` | buckets                           |
| `Bucket(name)`                                             | a handle for one bucket's objects |

| Bucket                                               |                                                                                        |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `PutBytes`, `Upload`, `UploadFile`, `UploadReaderAt` | upload (`PutOptions`: content type, cache headers, metadata, `IfNotExists`)            |
| `Get`, `GetBytes`, `DownloadTo`, `DownloadFile`      | download (`GetOptions`: range, `IfNoneMatch` → `ErrNotModified`, `IfMatch`)            |
| `Head`, `Exists`, `Delete`, `DeleteMany`, `Copy`     | object operations                                                                      |
| `List`, `Objects`, `Iterate`                          | one page / a `range` iterator (Go 1.23) / a `Next()` iterator                        |
| `CreateLink`                                         | a download or upload link that needs no key                                            |
| `CreateMultipartUpload`, `ResumeMultipartUpload`     | do-it-yourself multipart: `UploadPart`, `UploadPartFrom`, `Parts`, `Complete`, `Abort` |

Errors from the service are `*objectstorage.Error` with `StatusCode`,
`Code` (for example `object_not_found`, `bucket_already_exists`,
`project_suspended`) and `Message`; `IsNotFound(err)` and `ErrorCode(err)`
help to branch on them.

## Testing

```
go test ./...
```

runs against an in-memory fake of the service. To also run against a real
endpoint (it creates and deletes a bucket):

```
TH_OBJECT_STORAGE_ENDPOINT=https://objects.bkk.thailandhosting.com \
TH_ACCESS_KEY_ID=... TH_SECRET_ACCESS_KEY=... go test -run Integration -v ./...
```
