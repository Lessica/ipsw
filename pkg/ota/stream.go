package ota

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

// ErrEntryNotFound is returned by StreamFindEntry when the predicate did not
// match any entry before the input stream was exhausted.
var ErrEntryNotFound = errors.New("ota: entry not found in stream")

// EntryMatcher returns true when the supplied YAA entry header is the desired
// target. The decision must be made from the header alone — the scanner has
// not yet consumed the entry's data payload.
type EntryMatcher func(*yaa.Entry) bool

// StreamFindEntry scans a forward-only YAA archive read from r (the format an
// AEA OTA decrypts to) and writes the data payload of the first entry matched
// by `match` into `w`. Non-matching entry payloads are read sequentially and
// discarded; YOP_EXTRACT / YOP_DST_FIXUP payloads (typically pbzx-compressed
// nested YAA archives) are recursively scanned.
//
// On match the function returns the matched entry header and nil error. If
// the input stream is exhausted without a match, ErrEntryNotFound is
// returned.
func StreamFindEntry(ctx context.Context, r io.Reader, match EntryMatcher, w io.Writer) (*yaa.Entry, error) {
	ent, err := scanYAAStream(ctx, r, match, w)
	return ent, err
}

// IsKernelcacheEntry returns true if the given YAA entry represents a
// release kernelcache file (filename contains "kernelcache.release.").
// OTAs may also ship development/research variants — those are intentionally
// skipped so the streamed extraction stops on the variant users overwhelmingly
// want. Use IsAnyKernelcacheEntry for a permissive match.
func IsKernelcacheEntry(e *yaa.Entry) bool {
	if e == nil || e.Type != yaa.RegularFile {
		return false
	}
	return strings.Contains(e.Path, "kernelcache.release.")
}

// IsAnyKernelcacheEntry returns true for any kernelcache.* file (release,
// development, research, etc.).
func IsAnyKernelcacheEntry(e *yaa.Entry) bool {
	if e == nil || e.Type != yaa.RegularFile {
		return false
	}
	return strings.Contains(e.Path, "kernelcache.")
}

// scanYAAStream parses the YAA stream from r forward-only, recursing into
// YOP_EXTRACT / YOP_DST_FIXUP payloads. Any remaining bytes of an outer
// entry's payload are drained on return so the caller's stream stays aligned.
func scanYAAStream(ctx context.Context, r io.Reader, match EntryMatcher, w io.Writer) (*yaa.Entry, error) {
	var magic uint32
	var headerSize uint16

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, ErrEntryNotFound
			}
			return nil, fmt.Errorf("failed to read entry magic: %w", err)
		}
		if magic != yaa.MagicYAA1 && magic != yaa.MagicAA01 {
			return nil, fmt.Errorf("invalid YAA entry magic %#x", magic)
		}
		if err := binary.Read(r, binary.LittleEndian, &headerSize); err != nil {
			return nil, fmt.Errorf("failed to read entry header size: %w", err)
		}
		if headerSize <= 6 {
			return nil, fmt.Errorf("invalid YAA entry header size: %d", headerSize)
		}

		header := make([]byte, headerSize-6)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, fmt.Errorf("failed to read entry header: %w", err)
		}

		ent, err := yaa.DecodeEntry(bytes.NewReader(header))
		if err != nil {
			return nil, fmt.Errorf("failed to decode YAA entry: %w", err)
		}

		// Determine main payload length following this header.
		var dataLen int64
		switch ent.Type {
		case yaa.RegularFile:
			dataLen = int64(ent.Size) + int64(ent.Yec)
		case yaa.Metadata:
			switch ent.Yop {
			case yaa.YOP_MANIFEST, yaa.YOP_EXTRACT, yaa.YOP_DST_FIXUP:
				dataLen = int64(ent.Size)
			}
		}

		if match != nil && match(ent) {
			payloadLen := int64(ent.Size)
			if payloadLen > 0 {
				if _, werr := io.CopyN(w, r, payloadLen); werr != nil {
					return ent, fmt.Errorf("failed to write matched entry data: %w", werr)
				}
			}
			return ent, nil
		}

		// Recurse into YOP_EXTRACT / YOP_DST_FIXUP — these wrap a pbzx
		// archive of nested YAA entries.
		if ent.Type == yaa.Metadata && (ent.Yop == yaa.YOP_EXTRACT || ent.Yop == yaa.YOP_DST_FIXUP) && dataLen > 0 {
			lr := &io.LimitedReader{R: r, N: dataLen}
			br := bufio.NewReader(lr)
			peek, perr := br.Peek(4)
			if perr != nil && !errors.Is(perr, io.EOF) {
				return nil, fmt.Errorf("failed to peek nested payload magic: %w", perr)
			}

			var nested io.Reader = br
			var inflateDone <-chan error
			var inflatePR *io.PipeReader
			var icancel context.CancelFunc
			if len(peek) >= 4 && string(peek) == "pbzx" {
				var ictx context.Context
				ictx, icancel = context.WithCancel(ctx)
				pr, pw := io.Pipe()
				done := make(chan error, 1)
				go func() {
					err := pbzx.Extract(ictx, br, pw, runtime.NumCPU())
					_ = pw.CloseWithError(err)
					done <- err
				}()
				nested = pr
				inflateDone = done
				inflatePR = pr
			}

			matched, nerr := scanYAAStream(ctx, nested, match, w)

			// Tear down inflate goroutine if used (must do this BEFORE
			// draining lr so pbzx unblocks and stops writing).
			if icancel != nil {
				icancel()
				if inflatePR != nil {
					_ = inflatePR.CloseWithError(io.EOF)
				}
				if inflateDone != nil {
					<-inflateDone
				}
			}

			if matched != nil && nerr == nil {
				return matched, nil
			}
			if nerr != nil && !errors.Is(nerr, ErrEntryNotFound) {
				return nil, fmt.Errorf("nested scan failed: %w", nerr)
			}

			// Drain remaining bytes of outer chunk so the parent stream
			// stays aligned. Read from lr directly so we skip whatever
			// bufio buffered (those bytes were already counted against lr).
			if lr.N > 0 {
				if _, derr := io.Copy(io.Discard, lr); derr != nil {
					return nil, fmt.Errorf("failed to drain nested chunk: %w", derr)
				}
			}
			continue
		}

		if dataLen > 0 {
			if _, derr := io.CopyN(io.Discard, r, dataLen); derr != nil {
				return nil, fmt.Errorf("failed to skip entry payload: %w", derr)
			}
		}
		if ent.Xat > 0 {
			if _, derr := io.CopyN(io.Discard, r, int64(ent.Xat)); derr != nil {
				return nil, fmt.Errorf("failed to skip entry xattrs: %w", derr)
			}
		}
	}
}
