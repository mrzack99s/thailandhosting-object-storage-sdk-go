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

## Authentication

Every request is signed with an HTTP Message Signature (RFC 9421,
HMAC-SHA256 keyed with the secret access key). The secret itself is never
sent: the request carries only the access key ID, the time and the
signature, which covers the method, host, path and query and, for a
request with a body, its `Content-Digest` (SHA-256, RFC 9530). The service
checks the body against that digest as it arrives and stores nothing that
does not match (`bad_digest`).

Signatures are valid for 5 minutes around the service's clock, so keep the
machine's time synchronised (NTP); every retry is signed afresh. A client
without a key sends no signature and reads only what buckets made public.

## Public buckets and folders

```go
// Anyone may read images/ (and nothing else) without a key; needs a key
// allowed to manage buckets. nil makes the bucket private again.
bucket.SetPublicAccess(ctx, []objectstorage.PublicRule{{Prefix: "images/"}})
fmt.Println(bucket.PublicURL("images/logo.png"))
// https://objects.bkk.thailandhosting.com/my-bucket/images/logo.png

// A client without a key reads (and, where allowed, lists) public objects,
// with the same parallel downloads.
anon, _ := objectstorage.New(objectstorage.Config{Endpoint: "https://objects.bkk.thailandhosting.com"})
data, _ := anon.Bucket("my-bucket").GetBytes(ctx, "images/logo.png")
```

What a key may do (buckets, folders, read / list / write / delete,
managing buckets, an expiry date) is set on the key in the Console.

## Conditional requests

```go
// Create only if the key is empty; a second writer gets precondition_failed.
_, err := bucket.PutBytes(ctx, "locks/job-42", []byte(owner), &objectstorage.PutOptions{IfNotExists: true})
if objectstorage.IsPreconditionFailed(err) {
	// someone else holds it
}

// Update only if nobody changed the object since we read it.
obj, _ := bucket.Head(ctx, "config.json")
_, err = bucket.PutBytes(ctx, "config.json", data, &objectstorage.PutOptions{IfMatch: obj.ETag})

// Delete only that version.
err = bucket.DeleteWithOptions(ctx, "config.json", &objectstorage.DeleteOptions{IfMatch: obj.ETag})

// Download only if it changed (a cached copy is still current otherwise).
r, err := bucket.Get(ctx, "config.json", &objectstorage.GetOptions{IfNoneMatch: obj.ETag})
if errors.Is(err, objectstorage.ErrNotModified) {
	// use the cached copy
}
```

The service checks `IfMatch` / `IfNoneMatch` atomically with the write, so
two clients creating the same key with `IfNotExists` cannot both succeed.
Large uploads sent in parts are checked when the parts are joined; a
failed check aborts the upload. `GetOptions` and `HeadWithOptions` also
take `IfModifiedSince` and `IfUnmodifiedSince`. A failed condition is never
retried.

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
  network errors, waiting at least as long as `Retry-After` asks; bodies
  are re-read from their start (files, seekable readers, buffered parts).
- Every upload and every part carries a `Content-Digest` the service
  checks before storing, and is checked against the MD5 the service
  reports, so data damaged on the way is never accepted.
- Objects uploaded in one request keep their SHA-256 (`Object.Digest`, the
  `Repr-Digest` header). Whole-object downloads (`Get` without a range,
  `GetBytes`, `DownloadTo`, `DownloadFile`) are checked against it and fail
  with `ErrDigestMismatch` if the data differs; parallel downloads into a
  file are read back and checked once complete. Objects uploaded in parts
  have no digest and are checked against their ETag per range instead.
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
| `PutBytes`, `Upload`, `UploadFile`, `UploadReaderAt` | upload (`PutOptions`: content type, cache headers, metadata, `IfNotExists`, `IfMatch`, `IfNoneMatch`) |
| `Get`, `GetBytes`, `DownloadTo`, `DownloadFile`      | download (`GetOptions`: range, `IfNoneMatch` / `IfModifiedSince` → `ErrNotModified`, `IfMatch`, `IfUnmodifiedSince`) |
| `Head`, `HeadWithOptions`, `Exists`, `Delete`, `DeleteWithOptions`, `DeleteMany`, `Copy` | object operations (`DeleteOptions`: `IfMatch`, `IfNoneMatch`) |
| `List`, `Objects`, `Iterate`                          | one page / a `range` iterator (Go 1.23) / a `Next()` iterator                        |
| `CreateLink`                                         | a download or upload link that needs no key                                            |
| `PublicAccess`, `SetPublicAccess`, `PublicURL`       | make the bucket or some folders readable by anyone, and their URLs                     |
| `CreateMultipartUpload`, `ResumeMultipartUpload`     | do-it-yourself multipart: `UploadPart`, `UploadPartFrom`, `Parts`, `Complete`, `Abort` |

The service answers errors as Problem Details (RFC 9457,
`application/problem+json`). They come back as `*objectstorage.Error` with
`StatusCode`, `Code` (for example `object_not_found`,
`bucket_already_exists`, `precondition_failed`, `invalid_signature`,
`bad_digest`, `project_suspended`), `Message` (the problem's title), `Type`
and `Instance`; `IsNotFound(err)`, `IsPreconditionFailed(err)` and
`ErrorCode(err)` help to branch on them. `ErrNotModified` and
`ErrDigestMismatch` are plain errors to test with `errors.Is`.

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
