// Package objectstorage is the Go SDK for ThailandHosting Object Storage.
//
//	client, err := objectstorage.New(objectstorage.Config{
//		Endpoint:        "https://objects.bkk.thailandhosting.com",
//		AccessKeyID:     os.Getenv("TH_ACCESS_KEY_ID"),
//		SecretAccessKey: os.Getenv("TH_SECRET_ACCESS_KEY"),
//	})
//	bucket := client.Bucket("my-bucket")
//	_, err = bucket.UploadFile(ctx, "backups/db.dump", "/var/backups/db.dump", nil)
//
// The client is safe for concurrent use and should be reused: it keeps
// connections open. Large uploads are split into parts sent in parallel,
// large downloads are fetched as parallel ranges, and requests that can be
// repeated safely are retried with exponential backoff.
package objectstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Version is the SDK version, sent in the User-Agent.
const Version = "1.0.0"

// Config configures a Client. Endpoint, AccessKeyID and SecretAccessKey are
// required; every other field has a sensible default.
type Config struct {
	// Endpoint is the region's Object Storage endpoint, for example
	// https://objects.bkk.thailandhosting.com.
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string

	// HTTPClient replaces the default client (a pooled, HTTP/2-capable
	// transport). It should not set an overall Timeout: large transfers
	// are bounded by their context instead.
	HTTPClient *http.Client
	// MaxRetries is how many times a failed request that is safe to repeat
	// is retried (default 4; negative disables retries).
	MaxRetries int
	// PartSize is the size of each part of a multipart upload and of each
	// range of a parallel download (default 16 MiB, at least 5 MiB).
	PartSize int64
	// MultipartThreshold is the size above which uploads and downloads are
	// split (default 2 × PartSize).
	MultipartThreshold int64
	// Concurrency is how many parts or ranges move at once (default 8).
	Concurrency int
	// UserAgent is appended to the SDK's own.
	UserAgent string
}

const (
	defaultPartSize    = 16 << 20
	minPartSize        = 5 << 20
	maxParts           = 10000
	defaultConcurrency = 8
	defaultMaxRetries  = 4
)

// Client talks to one region's endpoint.
type Client struct {
	endpoint  *url.URL
	keyID     string
	secret    string
	http      *http.Client
	retries   int
	partSize  int64
	threshold int64
	workers   int
	userAgent string
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" || cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("objectstorage: Endpoint, AccessKeyID and SecretAccessKey are required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("objectstorage: invalid Endpoint %q", cfg.Endpoint)
	}
	u.Path = strings.TrimSuffix(u.Path, "/v1")
	c := &Client{endpoint: u, keyID: cfg.AccessKeyID, secret: cfg.SecretAccessKey, http: cfg.HTTPClient,
		retries: cfg.MaxRetries, partSize: cfg.PartSize, threshold: cfg.MultipartThreshold, workers: cfg.Concurrency}
	if c.http == nil {
		c.http = &http.Client{Transport: defaultTransport()}
	}
	if c.retries == 0 {
		c.retries = defaultMaxRetries
	} else if c.retries < 0 {
		c.retries = 0
	}
	if c.partSize <= 0 {
		c.partSize = defaultPartSize
	}
	c.partSize = max(c.partSize, minPartSize)
	if c.threshold <= 0 {
		c.threshold = 2 * c.partSize
	}
	if c.workers <= 0 {
		c.workers = defaultConcurrency
	}
	c.userAgent = "thailandhosting-object-storage-sdk-go/" + Version
	if cfg.UserAgent != "" {
		c.userAgent += " " + cfg.UserAgent
	}
	return c, nil
}

func defaultTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 256
	t.MaxIdleConnsPerHost = 64
	t.IdleConnTimeout = 90 * time.Second
	t.ResponseHeaderTimeout = 2 * time.Minute
	t.ForceAttemptHTTP2 = true
	// Large buffers move big objects with fewer system calls.
	t.WriteBufferSize = 256 << 10
	t.ReadBufferSize = 256 << 10
	return t
}

// Error is an error answer from the service.
type Error struct {
	StatusCode int
	// Code is the machine-readable reason, for example "object_not_found",
	// "bucket_already_exists" or "busy".
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("objectstorage: %s (HTTP %d): %s", e.Code, e.StatusCode, e.Message)
}

// IsNotFound reports whether err means the bucket, object or upload does not exist.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}

// ErrorCode returns the service's error code of err, or "".
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// escapeKey escapes each segment of an object key, keeping its slashes.
func escapeKey(key string) string {
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// request describes one API call. body, when set, is called once per
// attempt so a retry sends the body again from its start.
type request struct {
	method string
	path   string // after /v1, already escaped
	query  url.Values
	header http.Header
	body   func() (io.Reader, error)
	size   int64 // body length; -1 when unknown
	// retryPOST allows retrying a POST on answers that mean nothing was
	// done (busy, rate limited).
	retryPOST bool
	// expect lists the statuses that are not errors (default: any 2xx).
	expect []int
}

func (c *Client) url(path string, q url.Values) string {
	u := *c.endpoint
	u.RawPath = u.Path + "/v1" + path
	u.Path, _ = url.PathUnescape(u.RawPath)
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func retryableStatus(status int, method string, retryPOST bool) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return method != http.MethodPost || retryPOST
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout:
		return method != http.MethodPost
	}
	return false
}

func backoff(attempt int) time.Duration {
	d := 200 * time.Millisecond << min(attempt, 6)
	d = min(d, 10*time.Second)
	return d/2 + rand.N(d/2+1) // equal jitter
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends the request with retries and returns the response with an open
// body (the caller closes it).
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		var body io.Reader
		if r.body != nil {
			b, err := r.body()
			if err != nil {
				return nil, err
			}
			body = b
		}
		req, err := http.NewRequestWithContext(ctx, r.method, c.url(r.path, r.query), body)
		if err != nil {
			return nil, err
		}
		if r.body != nil {
			req.ContentLength = r.size
			if r.size == 0 {
				req.Body = http.NoBody
			}
		}
		for k, v := range r.header {
			req.Header[k] = v
		}
		req.Header.Set("Authorization", "Bearer "+c.keyID+":"+c.secret)
		req.Header.Set("User-Agent", c.userAgent)
		resp, err := c.http.Do(req)
		canRetry := attempt < c.retries && ctx.Err() == nil
		if err != nil {
			if canRetry && (r.method != http.MethodPost || r.retryPOST || isConnRefused(err)) {
				if err := sleep(ctx, backoff(attempt)); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		if ok(resp.StatusCode, r.expect) {
			return resp, nil
		}
		apiErr := readError(resp)
		if canRetry && retryableStatus(resp.StatusCode, r.method, r.retryPOST) {
			wait := backoff(attempt)
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if s, err := time.ParseDuration(ra + "s"); err == nil && s < 30*time.Second {
					wait = max(wait, s)
				}
			}
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		return nil, apiErr
	}
}

// isConnRefused reports a dial failure: the request never left, so even a
// POST may be sent again.
func isConnRefused(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

func ok(status int, expect []int) bool {
	if len(expect) == 0 {
		return status >= 200 && status < 300
	}
	for _, s := range expect {
		if s == status {
			return true
		}
	}
	return false
}

func readError(resp *http.Response) *Error {
	defer resp.Body.Close()
	e := &Error{StatusCode: resp.StatusCode, Code: resp.Header.Get("X-Error-Code"), Message: http.StatusText(resp.StatusCode)}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var doc struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &doc) == nil && doc.Error.Code != "" {
		e.Code, e.Message = doc.Error.Code, doc.Error.Message
	}
	if e.Code == "" {
		e.Code = strings.ToLower(strings.ReplaceAll(http.StatusText(resp.StatusCode), " ", "_"))
	}
	return e
}

// doJSON sends in (if any) as JSON and decodes the answer into out (if any).
func (c *Client) doJSON(ctx context.Context, method, path string, q url.Values, in, out any, retryPOST bool) error {
	r := request{method: method, path: path, query: q, retryPOST: retryPOST}
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		r.body = func() (io.Reader, error) { return bytes.NewReader(data), nil }
		r.size = int64(len(data))
		r.header = http.Header{"Content-Type": {"application/json"}}
	}
	resp, err := c.do(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
