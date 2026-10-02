// Command upload uploads a file and prints a one-hour download link.
//
//	TH_OBJECT_STORAGE_ENDPOINT=https://objects.bkk.thailandhosting.com \
//	TH_ACCESS_KEY_ID=... TH_SECRET_ACCESS_KEY=... go run ./examples/upload my-bucket ./photo.jpg
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	objectstorage "github.com/mrzack99s/thailandhosting-object-storage-sdk-go"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: upload <bucket> <file>")
	}
	client, err := objectstorage.New(objectstorage.Config{
		Endpoint:        os.Getenv("TH_OBJECT_STORAGE_ENDPOINT"),
		AccessKeyID:     os.Getenv("TH_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("TH_SECRET_ACCESS_KEY"),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	bucket := client.Bucket(os.Args[1])
	key := filepath.Base(os.Args[2])
	start := time.Now()
	obj, err := bucket.UploadFile(ctx, key, os.Args[2], nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("uploaded %s (%d bytes) in %v\n", obj.Key, obj.Size, time.Since(start).Round(time.Millisecond))
	link, err := bucket.CreateLink(ctx, key, &objectstorage.LinkOptions{Expires: time.Hour})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(link.URL)
}
