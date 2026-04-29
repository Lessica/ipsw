package extract

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
	"github.com/dustin/go-humanize"
)

// streamRemoteAEAKernelcacheRanged extracts the kernelcache from a remote AEA
// OTA using HTTP-Range driven random access. It costs ~2 round-trips for the
// AEA prefix + cluster headers, plus one Range per AEA segment band needed to
// cover the kernelcache YAA frame — typically 25-30 MiB transferred for an
// 18-20 MiB kernelcache (vs ~600 MiB for forward-streaming up to chunk 4).
//
// Assumes the kernelcache is in chunk c.AEAFastKernelChunk (default 4) of the
// OTA's YOP_MANIFEST and that chunk's outer YAA frame body is a flat
// sequence of YAA inner frames (no pbzx wrapper). Returns an error if either
// assumption fails so the caller can fall back to the streaming path.
func streamRemoteAEAKernelcacheRanged(ctx context.Context, c *Config) (map[string][]string, error) {
	outDir := filepath.Clean(c.Output)
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	chunkIdx := c.AEAFastKernelChunk
	if chunkIdx <= 0 {
		chunkIdx = 4
	}

	ro := newHTTPRangeOpener(c.URL, c.Proxy, c.Insecure)
	defer ro.Close()

	streamCfg := &aea.StreamConfig{
		B64SymKey: c.AEAKey,
		PemDB:     c.PemDB,
		Proxy:     c.Proxy,
		Insecure:  c.Insecure,
	}

	log.WithField("chunk", chunkIdx).Info("Probing remote AEA OTA via HTTP Range")
	log.Info("Note: fast mode skips writing a .download partial; rerun without --kernel-fast to seed a resumable transfer")

	ci, _, err := aea.PrepareRanged(ctx, ro, streamCfg)
	if err != nil {
		return nil, fmt.Errorf("aea range: prepare: %w", err)
	}
	log.WithFields(log.Fields{
		"file_size":          humanize.Bytes(uint64(ci.RootHeader.FileSize)),
		"segment_size":       humanize.Bytes(uint64(ci.RootHeader.SegmentSize)),
		"segs_per_cluster":   ci.RootHeader.SegmentsPerCluster,
		"cluster_plain_size": humanize.Bytes(uint64(ci.RootHeader.SegmentSize) * uint64(ci.RootHeader.SegmentsPerCluster)),
		"compression":        ci.RootHeader.Compression,
		"checksum":           ci.RootHeader.Checksum,
		"prefix_len":         ci.PrefixLen,
		"header_sec_size":    ci.HeaderSecSize,
	}).Debug("AEA prefix indexed")
	prefixCalls := ro.calls
	prefixBytes := ro.bytesRead
	log.WithFields(log.Fields{
		"requests": prefixCalls,
		"bytes":    humanize.Bytes(uint64(prefixBytes)),
	}).Debug("Stage 1: prefix loaded")

	// Read manifest from start of plaintext.
	mfRC, err := ci.OpenStream(ctx, ro, 0, 16*1024)
	if err != nil {
		return nil, fmt.Errorf("aea range: open manifest slice: %w", err)
	}
	manifest, manifestFrame, err := ota.ReadYOPManifest(mfRC)
	mfRC.Close()
	if err != nil {
		return nil, fmt.Errorf("aea range: read YOP_MANIFEST: %w", err)
	}
	if chunkIdx >= len(manifest) {
		return nil, fmt.Errorf("aea range: chunk %d out of range (manifest has %d)", chunkIdx, len(manifest))
	}
	chunkPlain := ota.ChunkPlainOffset(manifestFrame, manifest, chunkIdx)
	chunkPlainSize := manifest[chunkIdx].Size + 34 // include outer YAA frame header
	manifestCalls := ro.calls - prefixCalls
	manifestBytes := ro.bytesRead - prefixBytes
	log.WithFields(log.Fields{
		"requests": manifestCalls,
		"bytes":    humanize.Bytes(uint64(manifestBytes)),
		"entries":  len(manifest),
	}).Debug("Stage 2: YOP_MANIFEST parsed")
	log.WithFields(log.Fields{
		"index":       chunkIdx,
		"plain_start": chunkPlain,
		"plain_size":  humanize.Bytes(uint64(chunkPlainSize)),
		"label":       manifest[chunkIdx].Label,
	}).Debug("Target chunk located")

	// Read outer YAA frame header.
	outerHdrBuf, err := readSliceWithIndex(ctx, ci, ro, chunkPlain, 256)
	if err != nil {
		return nil, fmt.Errorf("aea range: read outer header: %w", err)
	}
	if len(outerHdrBuf) < 6 || string(outerHdrBuf[:4]) != "AA01" {
		return nil, fmt.Errorf("aea range: chunk %d: bad outer YAA magic", chunkIdx)
	}
	outerHdrSize := binary.LittleEndian.Uint16(outerHdrBuf[4:6])
	if int(outerHdrSize) > len(outerHdrBuf) {
		outerHdrBuf, err = readSliceWithIndex(ctx, ci, ro, chunkPlain, int64(outerHdrSize))
		if err != nil {
			return nil, fmt.Errorf("aea range: re-read outer header: %w", err)
		}
	}
	outerEnt, err := yaa.DecodeEntry(bytes.NewReader(outerHdrBuf[6:outerHdrSize]))
	if err != nil {
		return nil, fmt.Errorf("aea range: decode outer entry: %w", err)
	}
	innerStart := chunkPlain + int64(outerHdrSize)
	innerEnd := innerStart + int64(outerEnt.Size)
	log.WithFields(log.Fields{
		"yop":         outerEnt.Yop.String(),
		"label":       outerEnt.Label,
		"hdr_size":    outerHdrSize,
		"body_size":   humanize.Bytes(uint64(outerEnt.Size)),
		"inner_start": innerStart,
		"inner_end":   innerEnd,
	}).Debug("Stage 3: outer YAA frame decoded")

	// Detect pbzx wrapper.
	peek, err := readSliceWithIndex(ctx, ci, ro, innerStart, 4)
	if err != nil {
		return nil, fmt.Errorf("aea range: peek inner: %w", err)
	}
	if string(peek) == "pbzx" {
		return nil, fmt.Errorf("aea range: chunk %d body is pbzx-wrapped (not supported)", chunkIdx)
	}

	// Walk inner YAA frames in a rolling window, skipping over bodies
	// without fetching them.
	w := &yaaWindowReader{ci: ci, ro: ro, ctx: ctx, cur: innerStart, end: innerEnd, chunk: 256 * 1024}
	matchKC := func(e *yaa.Entry) bool {
		if e.Type != yaa.RegularFile {
			return false
		}
		if c.AnyKernel {
			return strings.Contains(e.Path, "kernelcache.")
		}
		return strings.Contains(e.Path, "kernelcache.release.")
	}
	var (
		kcStart     int64 = -1
		kcSize      int64
		kcPath      string
		framesSeen  int
		probeStartC = ro.calls
		probeStartB = ro.bytesRead
	)
	for {
		frameStart, _ := w.tell()
		if frameStart >= innerEnd {
			break
		}
		head, err := w.read(6)
		if err != nil {
			return nil, fmt.Errorf("aea range: read inner magic at %d: %w", frameStart, err)
		}
		if string(head[:4]) != "AA01" {
			return nil, fmt.Errorf("aea range: bad inner YAA magic at %d", frameStart)
		}
		hdrSize := binary.LittleEndian.Uint16(head[4:6])
		rest, err := w.read(int(hdrSize) - 6)
		if err != nil {
			return nil, fmt.Errorf("aea range: read inner header at %d: %w", frameStart, err)
		}
		ent, err := yaa.DecodeEntry(bytes.NewReader(rest))
		if err != nil {
			return nil, fmt.Errorf("aea range: decode inner entry at %d: %w", frameStart, err)
		}
		framesSeen++
		log.WithFields(log.Fields{
			"#":      framesSeen,
			"offset": frameStart,
			"path":   ent.Path,
			"size":   humanize.Bytes(uint64(ent.Size)),
			"type":   string(rune(ent.Type)),
		}).Debug("YAA frame")
		if matchKC(ent) {
			kcStart = frameStart
			kcSize = int64(hdrSize) + int64(ent.Size)
			kcPath = ent.Path
			break
		}
		w.skip(int64(ent.Size))
	}
	if kcStart < 0 {
		return nil, fmt.Errorf("aea range: kernelcache not found in chunk %d", chunkIdx)
	}

	probeBytes := ro.bytesRead
	probeCalls := ro.calls
	log.WithFields(log.Fields{
		"frames":   framesSeen,
		"windows":  w.opens,
		"requests": probeCalls - probeStartC,
		"bytes":    humanize.Bytes(uint64(probeBytes - probeStartB)),
	}).Debug("Stage 4: probe completed")
	log.WithFields(log.Fields{
		"path":        kcPath,
		"plain_start": kcStart,
		"size":        humanize.Bytes(uint64(kcSize)),
	}).Debug("kernelcache frame located")

	// Fetch the kernelcache YAA frame.
	rc, err := ci.OpenStream(ctx, ro, kcStart, kcSize)
	if err != nil {
		return nil, fmt.Errorf("aea range: open kernelcache slice: %w", err)
	}
	defer rc.Close()

	// Skip the inner YAA header to get at the body.
	hdrBuf := make([]byte, 6)
	if _, err := io.ReadFull(rc, hdrBuf); err != nil {
		return nil, fmt.Errorf("aea range: read kc magic: %w", err)
	}
	innerHdrSize := binary.LittleEndian.Uint16(hdrBuf[4:6])
	if _, err := io.CopyN(io.Discard, rc, int64(innerHdrSize)-6); err != nil {
		return nil, fmt.Errorf("aea range: skip kc header: %w", err)
	}
	body, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("aea range: read kc body: %w", err)
	}

	transferred := ro.bytesRead
	log.WithFields(log.Fields{
		"transferred": humanize.Bytes(uint64(transferred)),
		"probe":       humanize.Bytes(uint64(probeBytes)),
		"fetch":       humanize.Bytes(uint64(transferred - probeBytes)),
		"requests":    ro.calls,
		"probe_reqs":  probeCalls,
	}).Info("Fast Range AEA kernelcache extraction")

	cc, err := kernelcache.ParseImg4Data(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kernelcache im4p: %v", err)
	}
	dec, err := kernelcache.DecompressData(cc)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress kernelcache: %v", err)
	}

	fname := filepath.Join(outDir, filepath.Base(kcPath))
	if err := os.WriteFile(fname, dec, 0o660); err != nil {
		return nil, fmt.Errorf("failed to write kernelcache %s: %v", fname, err)
	}
	utils.Indent(log.Info, 2)("Wrote " + fname)

	artifacts := map[string][]string{fname: nil}
	if c.KernelDevice != "" {
		artifacts[fname] = []string{c.KernelDevice}
	}
	return artifacts, nil
}

// readSliceWithIndex opens a plaintext slice via OpenStream and reads up to n
// bytes (returning whatever was available — the caller validates length).
func readSliceWithIndex(ctx context.Context, ci *aea.ClusterIndex, ro aea.RangeOpener, off, n int64) ([]byte, error) {
	rc, err := ci.OpenStream(ctx, ro, off, n)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, n)
	got, err := io.ReadFull(rc, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:got], nil
}

// httpRangeOpener implements aea.RangeOpener over an HTTP resource by
// issuing a fresh GET with a Range header for each call. It tracks the
// number of requests and total bytes requested for diagnostics.
type httpRangeOpener struct {
	url       string
	client    *http.Client
	bytesRead int64
	calls     int
}

func newHTTPRangeOpener(remoteURL, proxy string, insecure bool) *httpRangeOpener {
	return &httpRangeOpener{
		url: remoteURL,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:           download.GetProxy(proxy),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		},
	}
}

func (h *httpRangeOpener) OpenRange(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", utils.RandomAgent())
	if length > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("aea range: unexpected status %s for offset=%d length=%d",
			resp.Status, offset, length)
	}
	h.calls++
	if length > 0 {
		h.bytesRead += length
	}
	log.WithFields(log.Fields{
		"#":      h.calls,
		"offset": offset,
		"length": humanize.Bytes(uint64(length)),
	}).Debug("HTTP Range")
	return resp.Body, nil
}

func (h *httpRangeOpener) Close() {
	h.client.CloseIdleConnections()
}

// yaaWindowReader buffers plaintext fetched via aea.ClusterIndex.OpenStream
// so a caller can sequentially read and skip across YAA frame boundaries
// while only paying for cipher segments that overlap the window — when
// skipping a large body the cursor advances without fetching.
type yaaWindowReader struct {
	ci    *aea.ClusterIndex
	ro    aea.RangeOpener
	ctx   context.Context
	cur   int64 // next plaintext offset to fetch (== end of buf in plaintext space)
	end   int64
	chunk int64
	buf   []byte
	pos   int
	opens int
}

func (w *yaaWindowReader) tell() (int64, error) {
	return w.cur - int64(len(w.buf)-w.pos), nil
}

func (w *yaaWindowReader) ensure(n int) error {
	for len(w.buf)-w.pos < n {
		if w.cur >= w.end {
			return io.ErrUnexpectedEOF
		}
		if w.pos > 0 {
			rem := copy(w.buf, w.buf[w.pos:])
			w.buf = w.buf[:rem]
			w.pos = 0
		}
		fetch := w.chunk
		if w.cur+fetch > w.end {
			fetch = w.end - w.cur
		}
		rc, err := w.ci.OpenStream(w.ctx, w.ro, w.cur, fetch)
		if err != nil {
			return err
		}
		w.opens++
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return io.ErrUnexpectedEOF
		}
		w.buf = append(w.buf, data...)
		w.cur += int64(len(data))
	}
	return nil
}

func (w *yaaWindowReader) read(n int) ([]byte, error) {
	if err := w.ensure(n); err != nil {
		return nil, err
	}
	out := w.buf[w.pos : w.pos+n]
	w.pos += n
	return out, nil
}

func (w *yaaWindowReader) skip(n int64) {
	avail := int64(len(w.buf) - w.pos)
	if n <= avail {
		w.pos += int(n)
		return
	}
	n -= avail
	w.buf = w.buf[:0]
	w.pos = 0
	w.cur += n
	if w.cur > w.end {
		w.cur = w.end
	}
}
