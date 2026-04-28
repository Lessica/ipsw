//go:build streamtest
// +build streamtest

package aea_test

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

// Run with:
//
//	go test -tags streamtest -timeout 30m -v -run TestStreamLocalAEA ./pkg/aea/...
//
// The fixture path can be overridden with AEA_TEST_FILE.
func TestStreamLocalAEA(t *testing.T) {
	path := os.Getenv("AEA_TEST_FILE")
	if path == "" {
		path = "/Users/82flex/Codelab/ipsw/22A3351_iPhone17,1_OTA_d9faf503145b73e746c27e075c48af44bfa02f15731649242930e38c98c5fe39.aea"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("AEA fixture not available: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pr, pw := io.Pipe()
	defer pr.Close()

	// Decrypt AEA streaming → pipe.
	decryptErrCh := make(chan error, 1)
	go func() {
		err := aea.DecryptStream(ctx, f, pw, &aea.StreamConfig{})
		decryptErrCh <- err
		_ = pw.CloseWithError(err)
	}()

	out, err := os.CreateTemp("", "kernelcache-stream-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out.Name())

	t.Logf("scanning OTA stream for kernelcache...")
	start := time.Now()
	matcher := func(e *yaa.Entry) bool {
		if e.Type == yaa.RegularFile && e.Path != "" {
			if strings.Contains(e.Path, "kernel") || strings.Contains(e.Path, "Kernel") {
				t.Logf("  file: %s (size=%d)", e.Path, e.Size)
			}
		}
		return ota.IsKernelcacheEntry(e)
	}
	ent, err := ota.StreamFindEntry(ctx, pr, matcher, out)
	if err != nil {
		out.Close()
		// Surface any underlying decrypt error.
		select {
		case derr := <-decryptErrCh:
			t.Logf("DecryptStream error: %v", derr)
		default:
		}
		t.Fatalf("StreamFindEntry: %v", err)
	}
	cancel() // stop AEA decryption goroutine
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("matched entry: type=%c yop=%c path=%q size=%d", byte(ent.Type), byte(ent.Yop), ent.Path, ent.Size)
	t.Logf("payload bytes written: %d (expected %d)", fi.Size(), ent.Size)
	t.Logf("elapsed: %v", time.Since(start))

	if fi.Size() == 0 {
		t.Fatal("kernelcache output is empty")
	}
	if uint64(fi.Size()) != ent.Size {
		t.Fatalf("size mismatch: wrote %d, header says %d", fi.Size(), ent.Size)
	}
	if ent.Type != yaa.RegularFile {
		t.Fatalf("expected RegularFile, got %c", byte(ent.Type))
	}

	// Validate the extracted kernelcache parses as IM4P and decompresses.
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	cc, err := kernelcache.ParseImg4Data(data)
	if err != nil {
		t.Fatalf("ParseImg4Data: %v", err)
	}
	dec, err := kernelcache.DecompressData(cc)
	if err != nil {
		t.Fatalf("DecompressData: %v", err)
	}
	t.Logf("decompressed kernelcache size: %d bytes", len(dec))
	if len(dec) < 1<<20 {
		t.Fatalf("decompressed kernelcache too small: %d bytes", len(dec))
	}
}
