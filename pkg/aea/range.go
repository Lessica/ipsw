package aea

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"

	"github.com/blacktop/lzfse-cgo"
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
)

// RangeOpener is implemented by callers that can issue HTTP Range reads (or
// open a local file at a given offset) against an AEA container. Length of -1
// means "open-ended" — read to end of resource.
type RangeOpener interface {
	OpenRange(ctx context.Context, offset, length int64) (io.ReadCloser, error)
}

// ClusterRef describes one AEA cluster at the byte level. It is enough to
// HMAC-validate the cluster header, derive its keys, and locate its body in
// the source.
type ClusterRef struct {
	Index             uint32 // 0-based cluster index (== cindex used in HKDF)
	CipherHeaderStart int64  // byte offset where the cluster's encSegmentHdrData begins
	CipherBodyStart   int64  // byte offset where this cluster's segment bodies begin
	CipherBodyEnd     int64  // byte offset of the next cluster (exclusive)
	PlainStart        int64  // cumulative plaintext start of this cluster
	PlainSize         int64  // plaintext size of this cluster (sum of DecompressedSize)

	// IncomingMAC is the HMAC that authenticates this cluster's header. For
	// cluster 0 this comes from encRootHdr.ClusterHmac; for cluster i>0 it
	// is the nextClusterMac written by cluster i-1's header.
	IncomingMAC HMAC
	// OutgoingMAC is the nextClusterMac field embedded in this cluster's
	// header — it authenticates the *following* cluster's header.
	OutgoingMAC HMAC

	// Decrypted segment headers (ready for use by body decryption).
	Segments []SegmentHeader
	// Per-segment HMACs (parallel to Segments).
	SegmentMACs []HMAC
}

// ClusterIndex is the result of walking cluster headers from the start of an
// AEA container up to (and including) the cluster containing some target
// plaintext offset.
type ClusterIndex struct {
	MainKey       []byte
	RootHeader    RootHeader
	PrefixLen     int64 // bytes consumed before cluster 0 (header + authData + salt + encRoot)
	HeaderSecSize int64 // size of each cluster's header section
	Clusters      []ClusterRef
	// PlainEnd is the cumulative plaintext size covered so far. Walking can
	// stop early; PlainEnd reports how far the index reaches.
	PlainEnd int64
}

// FindCluster returns the index into Clusters whose plaintext span contains
// plainOffset, or -1 if not yet indexed.
func (ci *ClusterIndex) FindCluster(plainOffset int64) int {
	for i, c := range ci.Clusters {
		if plainOffset < c.PlainStart+c.PlainSize {
			return i
		}
	}
	return -1
}

// PrepareRanged loads the AEA prefix (header, authData, salt, encrypted root
// header) using the supplied RangeOpener and returns a partially-populated
// ClusterIndex ready for subsequent header walking.
//
// One Range read is performed; the returned index has PrefixLen and
// HeaderSecSize filled in but no clusters indexed yet.
func PrepareRanged(ctx context.Context, ro RangeOpener, cfg *StreamConfig) (*ClusterIndex, []byte, error) {
	// Open first 64 KiB — easily fits Header + max AuthData + salt + encRoot.
	rc, err := ro.OpenRange(ctx, 0, 64*1024)
	if err != nil {
		return nil, nil, fmt.Errorf("aea range: open prefix: %w", err)
	}
	defer rc.Close()

	metadata, hdr, authData, err := InfoFromReader(rc)
	if err != nil {
		return nil, nil, err
	}
	if hdr.ProfileID() != SymmetricEncryption {
		return nil, nil, fmt.Errorf("aea range: invalid profile %d (want %d)", hdr.ProfileID(), SymmetricEncryption)
	}

	symKey, err := ResolveSymKey(metadata, cfg)
	if err != nil {
		return nil, nil, err
	}
	mainSalt := make([]byte, 32)
	if _, err := io.ReadFull(rc, mainSalt); err != nil {
		return nil, nil, fmt.Errorf("aea range: read main salt: %w", err)
	}
	mainKey, err := deriveKey(
		symKey,
		mainSalt,
		binary.LittleEndian.AppendUint32([]byte(MainKeyInfo), hdr.ProfileAndScryptStrength),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("aea range: derive main key: %w", err)
	}

	var encRootHdr encRootHeader
	if err := binary.Read(rc, binary.LittleEndian, &encRootHdr); err != nil {
		return nil, nil, fmt.Errorf("aea range: read encrypted root header: %w", err)
	}

	// Authenticate + decrypt root header (same logic as stream.go).
	var rootHdrKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(RootHeaderEncryptedKeyInfo)),
		binary.LittleEndian,
		&rootHdrKey,
	); err != nil {
		return nil, nil, fmt.Errorf("aea range: derive root header key: %w", err)
	}
	hmacSalt := make([]byte, len(encRootHdr.ClusterHmac)+len(authData))
	copy(hmacSalt, encRootHdr.ClusterHmac[:])
	copy(hmacSalt[len(encRootHdr.ClusterHmac):], authData)
	rhmac, err := getHMAC(rootHdrKey.MAC[:], encRootHdr.Data[:], hmacSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("aea range: root header HMAC: %w", err)
	}
	if !hmac.Equal(encRootHdr.Hmac[:], rhmac[:]) {
		return nil, nil, fmt.Errorf("aea range: root header HMAC mismatch")
	}
	rootHdrPlain, err := decryptCTR(append(encRootHdr.Data[:], authData...), rootHdrKey.Key[:], rootHdrKey.IV[:])
	if err != nil {
		return nil, nil, fmt.Errorf("aea range: decrypt root header: %w", err)
	}
	var rootHdr RootHeader
	if err := binary.Read(bytes.NewReader(rootHdrPlain), binary.LittleEndian, &rootHdr); err != nil {
		return nil, nil, fmt.Errorf("aea range: parse root header: %w", err)
	}

	prefixLen := int64(binary.Size(hdr)) + int64(hdr.AuthDataLength) + 32 + int64(binary.Size(encRootHdr))
	segHdrSize := int64(checksumSize[rootHdr.Checksum]) + 8
	headerSecSize := segHdrSize*int64(rootHdr.SegmentsPerCluster) + 32 + 32*int64(rootHdr.SegmentsPerCluster)

	ci := &ClusterIndex{
		MainKey:       mainKey,
		RootHeader:    rootHdr,
		PrefixLen:     prefixLen,
		HeaderSecSize: headerSecSize,
	}
	// Cluster 0's incoming MAC is encRootHdr.ClusterHmac.
	ci.Clusters = append(ci.Clusters, ClusterRef{
		Index:             0,
		CipherHeaderStart: prefixLen,
		IncomingMAC:       encRootHdr.ClusterHmac,
	})
	return ci, mainSalt, nil
}

// readClusterHeader fetches and authenticates the header section of cluster
// `c` (whose CipherHeaderStart and IncomingMAC must be filled in). On
// success it populates the cluster's Segments, SegmentMACs, OutgoingMAC,
// CipherBodyStart, CipherBodyEnd, PlainSize, PlainStart fields.
func readClusterHeader(ctx context.Context, ro RangeOpener, mainKey []byte, headerSecSize int64, segHdrSize int64, segPerCluster uint32, c *ClusterRef, plainCursor int64) error {
	rc, err := ro.OpenRange(ctx, c.CipherHeaderStart, headerSecSize)
	if err != nil {
		return fmt.Errorf("aea range: open cluster %d header: %w", c.Index, err)
	}
	defer rc.Close()

	encSegmentHdrData := make([]byte, segHdrSize*int64(segPerCluster))
	if _, err := io.ReadFull(rc, encSegmentHdrData); err != nil {
		return fmt.Errorf("aea range: read cluster %d enc seg headers: %w", c.Index, err)
	}
	var nextClusterMac HMAC
	if err := binary.Read(rc, binary.LittleEndian, &nextClusterMac); err != nil {
		return fmt.Errorf("aea range: read cluster %d next MAC: %w", c.Index, err)
	}
	segMacData := make([]byte, 32*int64(segPerCluster))
	if _, err := io.ReadFull(rc, segMacData); err != nil {
		return fmt.Errorf("aea range: read cluster %d seg MACs: %w", c.Index, err)
	}

	// Derive cluster keys.
	clusterKey, err := deriveKey(mainKey, []byte{},
		binary.LittleEndian.AppendUint32([]byte(ClusterKeyInfo), c.Index))
	if err != nil {
		return fmt.Errorf("aea range: derive cluster %d key: %w", c.Index, err)
	}
	var clusterHeaderKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, clusterKey, []byte{}, []byte(ClusterKeyMaterialInfo)),
		binary.LittleEndian,
		&clusterHeaderKey,
	); err != nil {
		return fmt.Errorf("aea range: derive cluster %d header key: %w", c.Index, err)
	}

	// Authenticate cluster header.
	hmacSalt := make([]byte, len(nextClusterMac)+len(segMacData))
	copy(hmacSalt, nextClusterMac[:])
	copy(hmacSalt[len(nextClusterMac):], segMacData)
	shmac, err := getHMAC(clusterHeaderKey.MAC[:], encSegmentHdrData, hmacSalt)
	if err != nil {
		return fmt.Errorf("aea range: cluster %d HMAC: %w", c.Index, err)
	}
	if !hmac.Equal(c.IncomingMAC[:], shmac[:]) {
		return fmt.Errorf("aea range: cluster %d header HMAC mismatch", c.Index)
	}

	segmentMACs := make([]HMAC, segPerCluster)
	if err := binary.Read(bytes.NewReader(segMacData), binary.LittleEndian, &segmentMACs); err != nil {
		return fmt.Errorf("aea range: parse cluster %d seg MACs: %w", c.Index, err)
	}
	segmentHdrPlain, err := decryptCTR(encSegmentHdrData, clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
	if err != nil {
		return fmt.Errorf("aea range: decrypt cluster %d seg headers: %w", c.Index, err)
	}
	segments := make([]SegmentHeader, segPerCluster)
	if err := binary.Read(bytes.NewReader(segmentHdrPlain), binary.LittleEndian, segments); err != nil {
		return fmt.Errorf("aea range: parse cluster %d seg headers: %w", c.Index, err)
	}

	var plainSz, bodyLen int64
	for _, s := range segments {
		plainSz += int64(s.DecompressedSize)
		bodyLen += int64(s.CompressedSize)
	}

	c.OutgoingMAC = nextClusterMac
	c.Segments = segments
	c.SegmentMACs = segmentMACs
	c.CipherBodyStart = c.CipherHeaderStart + headerSecSize
	c.CipherBodyEnd = c.CipherBodyStart + bodyLen
	c.PlainStart = plainCursor
	c.PlainSize = plainSz
	return nil
}

// IndexUntilPlainOffset extends ci.Clusters by walking cluster headers via
// small Range reads until a cluster whose plaintext span contains the given
// plainOffset is recorded. Returns the index of that cluster.
func (ci *ClusterIndex) IndexUntilPlainOffset(ctx context.Context, ro RangeOpener, plainOffset int64) (int, error) {
	if plainOffset < 0 {
		return -1, fmt.Errorf("aea range: negative plainOffset")
	}
	segHdrSize := int64(checksumSize[ci.RootHeader.Checksum]) + 8
	for {
		idx := len(ci.Clusters) - 1
		cur := &ci.Clusters[idx]
		if cur.Segments == nil {
			if err := readClusterHeader(ctx, ro, ci.MainKey, ci.HeaderSecSize, segHdrSize, ci.RootHeader.SegmentsPerCluster, cur, ci.PlainEnd); err != nil {
				return idx, err
			}
			ci.PlainEnd = cur.PlainStart + cur.PlainSize
		}
		if plainOffset < cur.PlainStart+cur.PlainSize {
			return idx, nil
		}
		// Advance.
		if ci.PlainEnd >= int64(ci.RootHeader.FileSize) {
			return -1, fmt.Errorf("aea range: plainOffset %d past file size %d", plainOffset, ci.RootHeader.FileSize)
		}
		ci.Clusters = append(ci.Clusters, ClusterRef{
			Index:             cur.Index + 1,
			CipherHeaderStart: cur.CipherBodyEnd,
			IncomingMAC:       cur.OutgoingMAC,
		})
	}
}

// OpenRangedReader yields plaintext starting at plainOffset by walking
// cluster headers (Range fetched) up to the target cluster, then issuing one
// HTTP-Range request per cluster covering only the AEA segments whose
// plaintext spans overlap [plainOffset, plainOffset+length). This avoids
// downloading whole-cluster bodies when only a small slice is needed.
//
// length is the number of plaintext bytes the caller intends to consume.
// Pass -1 for open-ended (read to end of file).
func OpenRangedReader(ctx context.Context, ro RangeOpener, plainOffset, length int64, cfg *StreamConfig) (io.ReadCloser, *ClusterIndex, error) {
	ci, _, err := PrepareRanged(ctx, ro, cfg)
	if err != nil {
		return nil, nil, err
	}
	rc, err := ci.OpenStream(ctx, ro, plainOffset, length)
	return rc, ci, err
}

// OpenStream is the same as OpenRangedReader but reuses an existing
// ClusterIndex so prefix + previously-indexed cluster headers are not
// re-fetched. Use this for repeated random-access reads against the same
// AEA container — the cost is then ~ Range(s) for the new segments only.
func (ci *ClusterIndex) OpenStream(ctx context.Context, ro RangeOpener, plainOffset, length int64) (io.ReadCloser, error) {
	target, err := ci.IndexUntilPlainOffset(ctx, ro, plainOffset)
	if err != nil {
		return nil, err
	}

	endPlain := int64(ci.RootHeader.FileSize)
	if length >= 0 {
		endPlain = plainOffset + length
		if endPlain > int64(ci.RootHeader.FileSize) {
			endPlain = int64(ci.RootHeader.FileSize)
		}
	}
	endIdx := target
	if endPlain > 0 {
		endIdx, err = ci.IndexUntilPlainOffset(ctx, ro, endPlain-1)
		if err != nil {
			// Truncated source: clamp to the last fully-indexed cluster
			// and note the reduced end. Caller will get partial plaintext
			// followed by io.ErrUnexpectedEOF / io.EOF when the source
			// runs out mid-body. This is the desired behaviour for
			// partial .download files where only some of chunk N's
			// cipher bytes are present.
			lastGood := -1
			for i := range ci.Clusters {
				if ci.Clusters[i].Segments != nil {
					lastGood = i
				}
			}
			if lastGood < target {
				return nil, fmt.Errorf("aea range: extend index: %w", err)
			}
			endIdx = lastGood
			endPlain = ci.Clusters[lastGood].PlainStart + ci.Clusters[lastGood].PlainSize
			err = nil
		}
	}

	pr, pw := io.Pipe()
	go func() {
		err := decryptIndexedClusters(ctx, ro, pw, ci, target, endIdx, plainOffset, length)
		_ = pw.CloseWithError(err)
	}()
	return readCloser{Reader: pr, close: func() error {
		return pr.CloseWithError(io.EOF)
	}}, nil
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r readCloser) Close() error { return r.close() }

// segRange returns the [firstSeg, lastSeg] range in cluster c whose plaintext
// spans overlap [wantStart, wantEnd), and the byte offset within firstSeg's
// plaintext where reading should begin (segSkip), plus the byte offset
// within lastSeg's plaintext where reading should end (segCap).
func segRange(c *ClusterRef, wantStart, wantEnd int64) (firstSeg, lastSeg int, segSkip, segCap int64) {
	firstSeg = -1
	plainPos := c.PlainStart
	for i, s := range c.Segments {
		segPlainEnd := plainPos + int64(s.DecompressedSize)
		if firstSeg == -1 && segPlainEnd > wantStart && s.DecompressedSize > 0 {
			firstSeg = i
			segSkip = wantStart - plainPos
			if segSkip < 0 {
				segSkip = 0
			}
		}
		if firstSeg != -1 && plainPos < wantEnd {
			lastSeg = i
			segCap = wantEnd - plainPos
			if segCap > int64(s.DecompressedSize) {
				segCap = int64(s.DecompressedSize)
			}
		}
		plainPos = segPlainEnd
	}
	return firstSeg, lastSeg, segSkip, segCap
}

// decryptIndexedClusters issues one Range request per cluster (for the
// minimal segment span needed) and writes the requested plaintext slice to w.
func decryptIndexedClusters(ctx context.Context, ro RangeOpener, w io.Writer, ci *ClusterIndex, startIdx, endIdx int, plainOffset, length int64) error {
	maxWorkers := min(runtime.GOMAXPROCS(0), 4)
	rootHdr := ci.RootHeader

	segPool := newBufferPool()
	decompPool := newBufferPool()

	type segOut struct {
		data           []byte
		fromDecompPool bool
	}

	wantStart := plainOffset
	wantEnd := int64(rootHdr.FileSize)
	if length >= 0 {
		wantEnd = plainOffset + length
		if wantEnd > int64(rootHdr.FileSize) {
			wantEnd = int64(rootHdr.FileSize)
		}
	}

	for ci_i := startIdx; ci_i <= endIdx; ci_i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		cluster := &ci.Clusters[ci_i]
		if cluster.Segments == nil {
			return fmt.Errorf("aea range: cluster %d header not indexed", cluster.Index)
		}

		firstSeg, lastSeg, segSkip, segCap := segRange(cluster, wantStart, wantEnd)
		if firstSeg < 0 {
			continue
		}

		// Compute compressed-byte offset of firstSeg within the cluster body
		// and total compressed bytes spanning firstSeg..lastSeg.
		var preBytes, spanBytes int64
		for i, s := range cluster.Segments {
			if i < firstSeg {
				preBytes += int64(s.CompressedSize)
				continue
			}
			if i > lastSeg {
				break
			}
			spanBytes += int64(s.CompressedSize)
		}
		rangeStart := cluster.CipherBodyStart + preBytes

		bodyRC, err := ro.OpenRange(ctx, rangeStart, spanBytes)
		if err != nil {
			return fmt.Errorf("aea range: open cluster %d seg [%d..%d]: %w",
				cluster.Index, firstSeg, lastSeg, err)
		}

		clusterKey, err := deriveKey(ci.MainKey, []byte{},
			binary.LittleEndian.AppendUint32([]byte(ClusterKeyInfo), cluster.Index))
		if err != nil {
			bodyRC.Close()
			return fmt.Errorf("aea range: derive cluster %d key: %w", cluster.Index, err)
		}

		clusterOut := make([]segOut, lastSeg-firstSeg+1)
		eg, _ := errgroup.WithContext(ctx)
		eg.SetLimit(maxWorkers)

		shortRead := false
		for idx := firstSeg; idx <= lastSeg; idx++ {
			seg := cluster.Segments[idx]
			if seg.DecompressedSize == 0 {
				continue
			}
			data := segPool.get(int(seg.CompressedSize))
			if _, err := io.ReadFull(bodyRC, data); err != nil {
				segPool.put(data)
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					// Source truncated mid-cluster (partial .download).
					// Stop scheduling further segments; emit what we have
					// then propagate io.ErrUnexpectedEOF.
					shortRead = true
					break
				}
				bodyRC.Close()
				return fmt.Errorf("aea range: read cluster %d seg %d body: %w", cluster.Index, idx, err)
			}
			segIdx := idx
			segHdr := seg
			segMAC := cluster.SegmentMACs[idx]
			clKey := clusterKey
			outSlot := idx - firstSeg
			eg.Go(func() error {
				keyInfo := make([]byte, len(SegmentKeyInfo)+4)
				copy(keyInfo, SegmentKeyInfo)
				binary.LittleEndian.PutUint32(keyInfo[len(SegmentKeyInfo):], uint32(segIdx))

				var segmentKey headerKey
				if err := binary.Read(
					hkdf.New(sha256.New, clKey, []byte{}, keyInfo),
					binary.LittleEndian,
					&segmentKey,
				); err != nil {
					segPool.put(data)
					return fmt.Errorf("derive segment key: %w", err)
				}
				shmac, err := getHMAC(segmentKey.MAC[:], data, nil)
				if err != nil {
					segPool.put(data)
					return fmt.Errorf("seg %d HMAC: %w", segIdx, err)
				}
				if !hmac.Equal(segMAC[:], shmac[:]) {
					segPool.put(data)
					return fmt.Errorf("seg %d HMAC mismatch", segIdx)
				}
				if err := decryptCTRInPlace(data, segmentKey.Key[:], segmentKey.IV[:]); err != nil {
					segPool.put(data)
					return fmt.Errorf("seg %d decrypt: %w", segIdx, err)
				}
				if segHdr.DecompressedSize == segHdr.CompressedSize {
					clusterOut[outSlot] = segOut{data: data, fromDecompPool: false}
					return nil
				}
				var decomp []byte
				switch rootHdr.Compression {
				case NONE:
					decomp = data
				case LZBITMAP:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					lzfse.LzBitMapDecompress(data, decomp)
				case LZFSE:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					n := decodeLZFSE(data, decomp)
					if n == 0 {
						decompPool.put(decomp)
						segPool.put(data)
						return fmt.Errorf("LZFSE decompress seg %d", segIdx)
					}
					decomp = decomp[:n]
				case LZMA:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					lzfse.DecodeLZVNBuffer(data, decomp)
				case ZLIB:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					zr, err := zlib.NewReader(bytes.NewReader(data))
					if err != nil {
						decompPool.put(decomp)
						segPool.put(data)
						return fmt.Errorf("zlib reader: %w", err)
					}
					n, err := io.ReadFull(zr, decomp)
					zr.Close()
					if err != nil && err != io.ErrUnexpectedEOF {
						decompPool.put(decomp)
						segPool.put(data)
						return fmt.Errorf("zlib decompress: %w", err)
					}
					decomp = decomp[:n]
				default:
					segPool.put(data)
					return fmt.Errorf("unsupported compression %s", rootHdr.Compression)
				}
				switch rootHdr.Checksum {
				case None:
				case Sha256:
					if computed := sha256.Sum256(decomp); computed != segHdr.Checksum {
						decompPool.put(decomp)
						segPool.put(data)
						return fmt.Errorf("SHA256 mismatch seg %d", segIdx)
					}
				case Murmur:
					computed := murmur3.SeedSum64(0xE2236FDC26A5F6D2, decomp)
					expected := binary.LittleEndian.Uint64(segHdr.Checksum[:8])
					if computed != expected {
						decompPool.put(decomp)
						segPool.put(data)
						return fmt.Errorf("Murmur mismatch seg %d", segIdx)
					}
				}
				segPool.put(data)
				clusterOut[outSlot] = segOut{data: decomp, fromDecompPool: true}
				return nil
			})
		}
		bodyRC.Close()
		if err := eg.Wait(); err != nil {
			for i := range clusterOut {
				if clusterOut[i].data != nil && clusterOut[i].fromDecompPool {
					decompPool.put(clusterOut[i].data)
				}
			}
			return fmt.Errorf("aea range: cluster %d decrypt: %w", cluster.Index, err)
		}

		for i, out := range clusterOut {
			if out.data == nil {
				continue
			}
			data := out.data
			absIdx := firstSeg + i
			if absIdx == firstSeg && segSkip > 0 {
				if int64(len(data)) <= segSkip {
					if out.fromDecompPool {
						decompPool.put(data)
					} else {
						segPool.put(data)
					}
					continue
				}
				data = data[segSkip:]
			}
			if absIdx == lastSeg && segCap > 0 && int64(len(data)) > segCap-segSkipForSeg(absIdx, firstSeg, segSkip) {
				cap := segCap - segSkipForSeg(absIdx, firstSeg, segSkip)
				if cap > 0 && int64(len(data)) > cap {
					data = data[:cap]
				}
			}
			if _, err := w.Write(data); err != nil {
				if out.fromDecompPool {
					decompPool.put(out.data)
				} else {
					segPool.put(out.data)
				}
				return fmt.Errorf("aea range: write seg: %w", err)
			}
			if out.fromDecompPool {
				decompPool.put(out.data)
			} else {
				segPool.put(out.data)
			}
		}
		if shortRead {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func segSkipForSeg(absIdx, firstSeg int, segSkip int64) int64 {
	if absIdx == firstSeg {
		return segSkip
	}
	return 0
}
