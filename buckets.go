package objectstorage

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// BucketInfo describes a bucket.
type BucketInfo struct {
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"createdAt"`
	// Public is what anyone may read; GetBucket fills it, ListBuckets
	// does not.
	Public []PublicRule `json:"public,omitempty"`
}

// PublicRule makes the objects under Prefix ("" is the whole bucket)
// readable by anyone without a key, at Bucket.PublicURL. List also lets
// anyone list those keys.
type PublicRule struct {
	Prefix string `json:"prefix"`
	List   bool   `json:"list"`
}

// ListBuckets returns the buckets the access key can use.
func (c *Client) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	var out struct {
		Buckets []BucketInfo `json:"buckets"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/buckets", nil, nil, &out, false)
	return out.Buckets, err
}

// CreateBucket creates a bucket in the endpoint's region. Bucket names are
// unique across the platform: 3-63 characters of a-z, 0-9, dots and hyphens.
func (c *Client) CreateBucket(ctx context.Context, name string) (*BucketInfo, error) {
	var out BucketInfo
	if err := c.doJSON(ctx, http.MethodPut, "/buckets/"+url.PathEscape(name), nil, nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetBucket returns a bucket, or an error IsNotFound reports.
func (c *Client) GetBucket(ctx context.Context, name string) (*BucketInfo, error) {
	var out BucketInfo
	if err := c.doJSON(ctx, http.MethodGet, "/buckets/"+url.PathEscape(name), nil, nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteBucket deletes an empty bucket.
func (c *Client) DeleteBucket(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodDelete, "/buckets/"+url.PathEscape(name), nil, nil, nil, false)
}

// Bucket returns a handle for the objects of one bucket (no request is made).
func (c *Client) Bucket(name string) *Bucket {
	return &Bucket{c: c, name: name, path: "/buckets/" + url.PathEscape(name)}
}

// Bucket is a handle for the objects of one bucket. It is cheap to create
// and safe for concurrent use.
type Bucket struct {
	c    *Client
	name string
	path string
}

// Name is the bucket's name.
func (b *Bucket) Name() string { return b.name }

// PublicAccess returns what anyone may read in the bucket.
func (b *Bucket) PublicAccess(ctx context.Context) ([]PublicRule, error) {
	var out struct {
		Rules []PublicRule `json:"rules"`
	}
	err := b.c.doJSON(ctx, http.MethodGet, b.path+"/public", nil, nil, &out, false)
	return out.Rules, err
}

// SetPublicAccess replaces what anyone may read in the bucket: no rules
// make it private again, PublicRule{} opens all of it, PublicRule{Prefix:
// "images/"} one folder. It needs a key allowed to manage buckets, and
// takes effect within about 15 seconds. It returns the rules as stored.
func (b *Bucket) SetPublicAccess(ctx context.Context, rules []PublicRule) ([]PublicRule, error) {
	if rules == nil {
		rules = []PublicRule{}
	}
	in := map[string]any{"rules": rules}
	var out struct {
		Rules []PublicRule `json:"rules"`
	}
	err := b.c.doJSON(ctx, http.MethodPut, b.path+"/public", nil, in, &out, true)
	return out.Rules, err
}

// PublicURL is the address anyone can open key at once its folder (or the
// bucket) is public. No request is made.
func (b *Bucket) PublicURL(key string) string {
	return b.c.endpoint.String() + "/" + url.PathEscape(b.name) + "/" + escapeKey(key)
}
