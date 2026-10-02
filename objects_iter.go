//go:build go1.23

package objectstorage

import (
	"context"
	"iter"
)

// Objects iterates over every object under prefix, page by page (Go 1.23+;
// Iterate works on any version):
//
//	for obj, err := range bucket.Objects(ctx, "photos/") {
//		if err != nil { return err }
//		fmt.Println(obj.Key, obj.Size)
//	}
func (b *Bucket) Objects(ctx context.Context, prefix string) iter.Seq2[Object, error] {
	return func(yield func(Object, error) bool) {
		it := b.Iterate(ctx, prefix)
		for it.Next() {
			if !yield(it.Object(), nil) {
				return
			}
		}
		if err := it.Err(); err != nil {
			yield(Object{}, err)
		}
	}
}
