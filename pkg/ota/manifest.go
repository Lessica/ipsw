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

	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

// ManifestChunk describes one outer YOP_EXTRACT chunk as listed by a
// YOP_MANIFEST entry. The manifest sits at the very start of the YAA stream
// produced by an AEA OTA and acts as a table of contents for the 40+ outer
// chunks that follow.
type ManifestChunk struct {
	Index    int    // 0-based position in the manifest
	Label    string // LBL — typically "main"
	Size     int64  // SIZ — decompressed plaintext size of this chunk's payload
	PlainIDX int64  // IDX — running plaintext-side index field
	InputSz  int64  // IDZ — input/compressed-side size field
}

// ReadYOPManifest reads exactly the YOP_MANIFEST entry off the front of an
// AEA-decrypted YAA stream and returns the parsed chunk list together with
// `manifestFrameSize`: the total number of plaintext bytes consumed (== the
// absolute plaintext offset where the first outer YOP_EXTRACT chunk's frame
// magic begins).
//
// In other words, manifest[i]'s outer frame magic sits at absolute plaintext
// offset:  manifestFrameSize + sum_{j<i}(34 + manifest[j].Size)
//
// Equivalently:  manifestFrameSize + manifest[i].PlainIDX.
//
// Callers that want to Range-fetch a single chunk can use this to locate it
// without walking through any chunk bodies.
func ReadYOPManifest(r io.Reader) ([]ManifestChunk, int64, error) {
	var (
		magic      uint32
		headerSize uint16
	)
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return nil, 0, fmt.Errorf("manifest: read magic: %w", err)
	}
	if magic != yaa.MagicYAA1 && magic != yaa.MagicAA01 {
		return nil, 0, fmt.Errorf("manifest: bad magic %#x", magic)
	}
	if err := binary.Read(r, binary.LittleEndian, &headerSize); err != nil {
		return nil, 0, fmt.Errorf("manifest: read headerSize: %w", err)
	}
	if headerSize <= 6 {
		return nil, 0, fmt.Errorf("manifest: bad headerSize %d", headerSize)
	}
	hdr := make([]byte, headerSize-6)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, 0, fmt.Errorf("manifest: read header body: %w", err)
	}
	ent, err := yaa.DecodeEntry(bytes.NewReader(hdr))
	if err != nil {
		return nil, 0, fmt.Errorf("manifest: decode entry: %w", err)
	}
	if ent.Type != yaa.Metadata || ent.Yop != yaa.YOP_MANIFEST {
		return nil, 0, fmt.Errorf("manifest: first entry is %s/%s, expected Metadata/YOP_MANIFEST", ent.Type, ent.Yop)
	}
	if ent.Size <= 0 {
		return nil, int64(headerSize), nil
	}
	body := make([]byte, ent.Size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, 0, fmt.Errorf("manifest: read body: %w", err)
	}
	chunks, err := ParseYOPManifest(body)
	if err != nil {
		return nil, 0, err
	}
	return chunks, int64(headerSize) + int64(ent.Size), nil
}

// ChunkPlainOffset returns the absolute plaintext offset of the outer YAA
// frame magic of manifest[target], given the manifestFrameSize returned by
// ReadYOPManifest.
func ChunkPlainOffset(manifestFrameSize int64, manifest []ManifestChunk, target int) int64 {
	if target < 0 || target >= len(manifest) {
		return -1
	}
	return manifestFrameSize + manifest[target].PlainIDX
}

// ParseYOPManifest decodes a YOP_MANIFEST payload (the bytes that follow the
// manifest entry header in the stream) into a list of ManifestChunk records,
// one per outer YOP_EXTRACT chunk that appears later in the stream.
//
// The manifest payload is itself a sequence of YAA "Metadata + YOP_EXTRACT"
// frames carrying LBL/SIZ/IDX/IDZ fields and no inline payload.
func ParseYOPManifest(data []byte) ([]ManifestChunk, error) {
	rd := bytes.NewReader(data)
	var out []ManifestChunk

	var magic uint32
	var headerSize uint16
	for rd.Len() > 0 {
		if err := binary.Read(rd, binary.LittleEndian, &magic); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("manifest: read magic: %w", err)
		}
		if magic != yaa.MagicYAA1 && magic != yaa.MagicAA01 {
			return nil, fmt.Errorf("manifest: bad magic %#x at offset %d", magic, len(data)-rd.Len()-4)
		}
		if err := binary.Read(rd, binary.LittleEndian, &headerSize); err != nil {
			return nil, fmt.Errorf("manifest: read headerSize: %w", err)
		}
		if headerSize <= 6 {
			return nil, fmt.Errorf("manifest: bad headerSize %d", headerSize)
		}
		hdr := make([]byte, headerSize-6)
		if _, err := io.ReadFull(rd, hdr); err != nil {
			return nil, fmt.Errorf("manifest: read header body: %w", err)
		}
		ent, err := yaa.DecodeEntry(bytes.NewReader(hdr))
		if err != nil {
			return nil, fmt.Errorf("manifest: decode entry %d: %w", len(out), err)
		}
		// Manifest records only carry YOP_EXTRACT metadata frames; ignore
		// anything else defensively.
		if ent.Type != yaa.Metadata || ent.Yop != yaa.YOP_EXTRACT {
			continue
		}
		out = append(out, ManifestChunk{
			Index:    len(out),
			Label:    ent.Label,
			Size:     int64(ent.Size),
			PlainIDX: int64(ent.Index),
			InputSz:  int64(ent.ESize),
		})
	}
	return out, nil
}

// ChunkReader is a forward-only reader over the decompressed plaintext of a
// single outer YOP_EXTRACT chunk. Close must be called to release the
// associated pbzx inflater goroutine.
type ChunkReader struct {
	io.Reader
	cancel  context.CancelFunc
	pr      *io.PipeReader
	done    <-chan error
	limited *io.LimitedReader // outer YAA frame's body span (so caller can drain on close)
	closed  bool
}

// Close tears down the pbzx inflater (if any) and releases parent resources.
// Any unread bytes of the outer chunk remain in the parent reader; calling
// Close before fully consuming this chunk leaves the parent stream
// unaligned, which is fine when the caller is done with the AEA stream
// entirely.
func (c *ChunkReader) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	if c.pr != nil {
		_ = c.pr.CloseWithError(io.EOF)
	}
	if c.done != nil {
		<-c.done
	}
	return nil
}

// SeekToChunk consumes the manifest at the head of an AEA-decrypted YAA stream
// and forwards r past every outer YOP_EXTRACT chunk before `target`, returning
// the parsed manifest and a ChunkReader yielding the (pbzx-decompressed)
// plaintext of the target chunk.
//
// Forward-discard only: this saves no bandwidth on its own but is the
// primitive that — once paired with HTTP-Range driven AEA cluster reads —
// will let callers stream just one chunk of the OTA.
//
// On success the caller should pass chunkReader to StreamFindEntry (or any
// other YAA scanner) and Close it when done.
func SeekToChunk(ctx context.Context, r io.Reader, target int) ([]ManifestChunk, *ChunkReader, error) {
	if target < 0 {
		return nil, nil, fmt.Errorf("ota: target chunk index must be >= 0, got %d", target)
	}

	var manifest []ManifestChunk
	extractSeen := 0

	var magic uint32
	var headerSize uint16
	for {
		select {
		case <-ctx.Done():
			return manifest, nil, ctx.Err()
		default:
		}

		if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return manifest, nil, fmt.Errorf("ota: stream exhausted before reaching chunk %d (saw %d)", target, extractSeen)
			}
			return manifest, nil, fmt.Errorf("seek: read magic: %w", err)
		}
		if magic != yaa.MagicYAA1 && magic != yaa.MagicAA01 {
			return manifest, nil, fmt.Errorf("seek: bad magic %#x", magic)
		}
		if err := binary.Read(r, binary.LittleEndian, &headerSize); err != nil {
			return manifest, nil, fmt.Errorf("seek: read headerSize: %w", err)
		}
		if headerSize <= 6 {
			return manifest, nil, fmt.Errorf("seek: bad headerSize %d", headerSize)
		}
		hdr := make([]byte, headerSize-6)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return manifest, nil, fmt.Errorf("seek: read header body: %w", err)
		}
		ent, err := yaa.DecodeEntry(bytes.NewReader(hdr))
		if err != nil {
			return manifest, nil, fmt.Errorf("seek: decode entry: %w", err)
		}

		// Manifest first.
		if ent.Type == yaa.Metadata && ent.Yop == yaa.YOP_MANIFEST {
			if ent.Size <= 0 {
				continue
			}
			buf := make([]byte, ent.Size)
			if _, err := io.ReadFull(r, buf); err != nil {
				return manifest, nil, fmt.Errorf("seek: read manifest payload: %w", err)
			}
			parsed, err := ParseYOPManifest(buf)
			if err != nil {
				return manifest, nil, err
			}
			manifest = parsed
			if target >= len(manifest) {
				return manifest, nil, fmt.Errorf("ota: target chunk %d out of range (manifest has %d)", target, len(manifest))
			}
			continue
		}

		// Outer YOP_EXTRACT chunk.
		if ent.Type == yaa.Metadata && ent.Yop == yaa.YOP_EXTRACT {
			idx := extractSeen
			extractSeen++
			if idx < target {
				if ent.Size > 0 {
					if _, err := io.CopyN(io.Discard, r, int64(ent.Size)); err != nil {
						return manifest, nil, fmt.Errorf("seek: skip chunk %d body: %w", idx, err)
					}
				}
				if ent.Xat > 0 {
					if _, err := io.CopyN(io.Discard, r, int64(ent.Xat)); err != nil {
						return manifest, nil, fmt.Errorf("seek: skip chunk %d xattrs: %w", idx, err)
					}
				}
				continue
			}
			if idx != target {
				return manifest, nil, fmt.Errorf("ota: extract walk got chunk %d, expected %d", idx, target)
			}
			// Open this chunk for the caller.
			if ent.Size <= 0 {
				return manifest, &ChunkReader{Reader: bytes.NewReader(nil)}, nil
			}
			lr := &io.LimitedReader{R: r, N: int64(ent.Size)}
			br := bufio.NewReader(lr)
			peek, perr := br.Peek(4)
			if perr != nil && !errors.Is(perr, io.EOF) {
				return manifest, nil, fmt.Errorf("seek: peek chunk %d: %w", idx, perr)
			}
			cr := &ChunkReader{Reader: br, limited: lr}
			if len(peek) >= 4 && string(peek) == "pbzx" {
				ictx, icancel := context.WithCancel(ctx)
				pr, pw := io.Pipe()
				done := make(chan error, 1)
				go func() {
					err := pbzx.Extract(ictx, br, pw, runtime.NumCPU())
					_ = pw.CloseWithError(err)
					done <- err
				}()
				cr.Reader = pr
				cr.cancel = icancel
				cr.pr = pr
				cr.done = done
			}
			return manifest, cr, nil
		}

		// Anything else at depth 0: skip its payload.
		var dataLen int64
		switch ent.Type {
		case yaa.RegularFile:
			dataLen = int64(ent.Size) + int64(ent.Yec)
		case yaa.Metadata:
			dataLen = int64(ent.Size)
		}
		if dataLen > 0 {
			if _, err := io.CopyN(io.Discard, r, dataLen); err != nil {
				return manifest, nil, fmt.Errorf("seek: skip outer entry: %w", err)
			}
		}
		if ent.Xat > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(ent.Xat)); err != nil {
				return manifest, nil, fmt.Errorf("seek: skip outer xattrs: %w", err)
			}
		}
	}
}
