package aea

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"

	"github.com/blacktop/lzfse-cgo"
	"github.com/twmb/murmur3"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
)

// StreamConfig configures DecryptStream and ResolveSymKey for streaming
// decryption of AEA containers.
type StreamConfig struct {
	// PrivKeyData is the raw FCS private key (PEM). Optional.
	PrivKeyData []byte
	// B64SymKey is the base64-encoded symmetric key (skips HPKE / fcs lookup).
	B64SymKey string
	// PemDB is a path to a JSON PEM database used to look up FCS keys offline.
	PemDB string
	// Proxy is an optional HTTP/HTTPS proxy used by FCS key fetches.
	Proxy string
	// Insecure skips TLS verification for FCS / pem-DB fetches.
	Insecure bool
}

// ResolveSymKey resolves the AEA symmetric encryption key from the given
// metadata, applying the same priority rules as Decrypt:
//
//  1. metadata["encryption_key"] (hex)
//  2. cfg.B64SymKey (base64)
//  3. HPKE-unwrap via metadata.DecryptFCS using PrivKeyData / PemDB / network
func ResolveSymKey(metadata Metadata, cfg *StreamConfig) ([]byte, error) {
	if cfg == nil {
		cfg = &StreamConfig{}
	}
	if encKey, ok := metadata["encryption_key"]; ok {
		key, err := hex.DecodeString(string(encKey))
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex sym key: %w", err)
		}
		return key, nil
	}
	if cfg.B64SymKey != "" {
		key, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(cfg.B64SymKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 sym key: %w", err)
		}
		return key, nil
	}
	key, err := metadata.DecryptFCS(cfg.PrivKeyData, cfg.PemDB, cfg.Proxy, cfg.Insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to HPKE decrypt fcs-key: %w", err)
	}
	return key, nil
}

// DecryptStream decrypts an AEA container read from r and writes the plaintext
// payload to w. Unlike Decrypt, it operates on forward-only streams: r is read
// once from start to end and w is written sequentially. Cancelling ctx stops
// the decryption between clusters.
//
// The reader r must point at the very beginning of the AEA container (Magic
// "AEA1"). Only the SymmetricEncryption profile is supported.
func DecryptStream(ctx context.Context, r io.Reader, w io.Writer, cfg *StreamConfig) error {
	metadata, hdr, authData, err := InfoFromReader(r)
	if err != nil {
		return err
	}
	if hdr.ProfileID() != SymmetricEncryption {
		return fmt.Errorf("invalid profile: %d; expected %d", hdr.ProfileID(), SymmetricEncryption)
	}

	symKey, err := ResolveSymKey(metadata, cfg)
	if err != nil {
		return err
	}

	mainSalt := make([]byte, 32)
	if _, err := io.ReadFull(r, mainSalt); err != nil {
		return fmt.Errorf("failed to read main salt: %w", err)
	}
	mainKey, err := deriveKey(
		symKey,
		mainSalt,
		binary.LittleEndian.AppendUint32([]byte(MainKeyInfo), hdr.ProfileAndScryptStrength),
	)
	if err != nil {
		return fmt.Errorf("failed to derive main key: %w", err)
	}

	var encRootHdr encRootHeader
	if err := binary.Read(r, binary.LittleEndian, &encRootHdr); err != nil {
		return fmt.Errorf("failed to read encrypted root header: %w", err)
	}

	var rootHdrKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(RootHeaderEncryptedKeyInfo)),
		binary.LittleEndian,
		&rootHdrKey,
	); err != nil {
		return fmt.Errorf("failed to derive root header key: %w", err)
	}
	hmacSalt := make([]byte, len(encRootHdr.ClusterHmac)+len(authData))
	copy(hmacSalt, encRootHdr.ClusterHmac[:])
	copy(hmacSalt[len(encRootHdr.ClusterHmac):], authData)
	rhmac, err := getHMAC(rootHdrKey.MAC[:], encRootHdr.Data[:], hmacSalt)
	if err != nil {
		return fmt.Errorf("failed to get encrypted root header HMAC: %w", err)
	}
	if !hmac.Equal(encRootHdr.Hmac[:], rhmac[:]) {
		return fmt.Errorf("invalid root header HMAC: %x; expected %x", encRootHdr.Hmac, rhmac)
	}
	rootHdrData, err := decryptCTR(append(encRootHdr.Data[:], authData...), rootHdrKey.Key[:], rootHdrKey.IV[:])
	if err != nil {
		return fmt.Errorf("failed to decrypt root header: %w", err)
	}
	var rootHdr RootHeader
	if err := binary.Read(bytes.NewReader(rootHdrData), binary.LittleEndian, &rootHdr); err != nil {
		return err
	}

	return decryptClustersStream(ctx, r, w, mainKey, encRootHdr.ClusterHmac, rootHdr)
}

// decryptClustersStream is a forward-only port of decryptClusters: it reads
// each cluster sequentially from r, decrypts/decompresses its segments in
// parallel into per-segment buffers, then writes the segments in order to w
// before moving on to the next cluster. Output is fully sequential so w may be
// any io.Writer (pipe, network, file).
func decryptClustersStream(ctx context.Context, r io.Reader, w io.Writer, mainKey []byte, clusterMAC HMAC, rootHdr RootHeader) error {
	maxWorkers := min(runtime.GOMAXPROCS(0), 4)

	segPool := newBufferPool()
	decompPool := newBufferPool()

	segmentHeaderSize := checksumSize[rootHdr.Checksum] + 8
	cindex := uint32(0)
	totalSize := uint64(0)

	encSegmentHdrData := make([]byte, segmentHeaderSize*rootHdr.SegmentsPerCluster)
	segmentMacData := make([]byte, 32*rootHdr.SegmentsPerCluster)
	segmentMACs := make([]HMAC, rootHdr.SegmentsPerCluster)
	segmentHdrs := make([]SegmentHeader, rootHdr.SegmentsPerCluster)

	// Per-cluster output buffers (one slot per segment index). These hold the
	// decrypted/decompressed plaintext until the cluster is fully processed,
	// at which point we write them out in segment order. Only seg buffers
	// taken from segPool need to be returned; decomp buffers from decompPool
	// are released after the sequential write.
	type segOut struct {
		data           []byte
		fromDecompPool bool
	}
	clusterOut := make([]segOut, rootHdr.SegmentsPerCluster)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Reset cluster output slots
		for i := range clusterOut {
			clusterOut[i] = segOut{}
		}

		eg, _ := errgroup.WithContext(ctx)
		eg.SetLimit(maxWorkers)

		clusterKey, err := deriveKey(mainKey, []byte{},
			binary.LittleEndian.AppendUint32([]byte(ClusterKeyInfo), uint32(cindex)))
		if err != nil {
			return fmt.Errorf("failed to derive cluster key: %w", err)
		}

		var clusterHeaderKey headerKey
		if err := binary.Read(
			hkdf.New(sha256.New, clusterKey, []byte{}, []byte(ClusterKeyMaterialInfo)),
			binary.LittleEndian,
			&clusterHeaderKey,
		); err != nil {
			return fmt.Errorf("failed to derive cluster header key: %w", err)
		}
		if _, err := io.ReadFull(r, encSegmentHdrData); err != nil {
			return fmt.Errorf("failed to read encrypted segment headers data: %w", err)
		}
		var nextClusterMac HMAC
		if err := binary.Read(r, binary.LittleEndian, &nextClusterMac); err != nil {
			return fmt.Errorf("failed to read next cluster HMAC: %w", err)
		}
		if _, err := io.ReadFull(r, segmentMacData); err != nil {
			return fmt.Errorf("failed to read segment HMAC data: %w", err)
		}

		hmacSalt := make([]byte, len(nextClusterMac)+len(segmentMacData))
		copy(hmacSalt, nextClusterMac[:])
		copy(hmacSalt[len(nextClusterMac):], segmentMacData)

		shmac, err := getHMAC(clusterHeaderKey.MAC[:], encSegmentHdrData, hmacSalt)
		if err != nil {
			return fmt.Errorf("failed to get HMAC for encrypted segment headers data: %w", err)
		}
		if !hmac.Equal(clusterMAC[:], shmac[:]) {
			return fmt.Errorf("invalid cluster #%d HMAC: %x; expected %x", cindex, clusterMAC, shmac)
		}
		if err := binary.Read(bytes.NewReader(segmentMacData), binary.LittleEndian, &segmentMACs); err != nil {
			return fmt.Errorf("failed to read segment HMACs: %w", err)
		}
		segmentHdrData, err := decryptCTR(encSegmentHdrData, clusterHeaderKey.Key[:], clusterHeaderKey.IV[:])
		if err != nil {
			return fmt.Errorf("failed to decrypt segment headers: %w", err)
		}
		if err := binary.Read(bytes.NewReader(segmentHdrData), binary.LittleEndian, segmentHdrs); err != nil {
			return fmt.Errorf("failed to read segment headers: %w", err)
		}

		currentClusterIdx := cindex
		for idx, seg := range segmentHdrs {
			if seg.DecompressedSize == 0 {
				continue
			}
			totalSize += uint64(seg.DecompressedSize)

			segmentData := segPool.get(int(seg.CompressedSize))
			if _, err = io.ReadFull(r, segmentData); err != nil {
				segPool.put(segmentData)
				return fmt.Errorf("failed to read segment data: %w", err)
			}

			segIdx := idx
			segHdr := seg
			segData := segmentData
			segMAC := segmentMACs[idx]
			clKey := clusterKey

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
					segPool.put(segData)
					return fmt.Errorf("failed to derive segment key: %w", err)
				}
				shmac, err := getHMAC(segmentKey.MAC[:], segData, nil)
				if err != nil {
					segPool.put(segData)
					return fmt.Errorf("failed to get HMAC for segment header: %w", err)
				}
				if !hmac.Equal(segMAC[:], shmac[:]) {
					segPool.put(segData)
					return fmt.Errorf("invalid segment #%d HMAC: %x; expected %x", segIdx, segMAC, shmac)
				}
				if err := decryptCTRInPlace(segData, segmentKey.Key[:], segmentKey.IV[:]); err != nil {
					segPool.put(segData)
					return fmt.Errorf("failed to decrypt segment data: %w", err)
				}

				if segHdr.DecompressedSize == segHdr.CompressedSize {
					// Plaintext lives in segData; release it after the
					// sequential cluster write below.
					clusterOut[segIdx] = segOut{data: segData, fromDecompPool: false}
					return nil
				}

				var decomp []byte
				switch rootHdr.Compression {
				case NONE:
					decomp = segData
				case LZBITMAP:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					lzfse.LzBitMapDecompress(segData, decomp)
				case LZFSE:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					n := decodeLZFSE(segData, decomp)
					if n == 0 {
						decompPool.put(decomp)
						segPool.put(segData)
						return fmt.Errorf("failed to decompress LZFSE segment %d", segIdx)
					}
					decomp = decomp[:n]
				case LZMA:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					lzfse.DecodeLZVNBuffer(segData, decomp)
				case ZLIB:
					decomp = decompPool.get(int(segHdr.DecompressedSize))
					zr, err := zlib.NewReader(bytes.NewReader(segData))
					if err != nil {
						decompPool.put(decomp)
						segPool.put(segData)
						return fmt.Errorf("failed to create zlib reader: %w", err)
					}
					n, err := io.ReadFull(zr, decomp)
					zr.Close()
					if err != nil && err != io.ErrUnexpectedEOF {
						decompPool.put(decomp)
						segPool.put(segData)
						return fmt.Errorf("failed to read zlib decompressed data: %w", err)
					}
					decomp = decomp[:n]
				default:
					segPool.put(segData)
					return fmt.Errorf("unsupported compression type: %s", rootHdr.Compression)
				}

				switch rootHdr.Checksum {
				case None:
				case Sha256:
					computed := sha256.Sum256(decomp)
					if computed != segHdr.Checksum {
						decompPool.put(decomp)
						segPool.put(segData)
						return fmt.Errorf("invalid SHA256 checksum for segment %d (cluster %d): expected %x; got %x", segIdx, currentClusterIdx, segHdr.Checksum, computed)
					}
				case Murmur:
					computed := murmur3.SeedSum64(0xE2236FDC26A5F6D2, decomp)
					expected := binary.LittleEndian.Uint64(segHdr.Checksum[:8])
					if computed != expected {
						decompPool.put(decomp)
						segPool.put(segData)
						return fmt.Errorf("invalid MURMUR checksum for segment %d (cluster %d): expected %x; got %x", segIdx, currentClusterIdx, expected, computed)
					}
				default:
					decompPool.put(decomp)
					segPool.put(segData)
					return fmt.Errorf("unsupported checksum type: %d", rootHdr.Checksum)
				}

				// Plaintext is in `decomp`; the compressed/encrypted segData
				// buffer is no longer needed.
				segPool.put(segData)
				clusterOut[segIdx] = segOut{data: decomp, fromDecompPool: true}
				return nil
			})
		}

		if err := eg.Wait(); err != nil {
			// Best-effort release of any slots that completed before the error.
			for i := range clusterOut {
				if clusterOut[i].data != nil && clusterOut[i].fromDecompPool {
					decompPool.put(clusterOut[i].data)
				}
				clusterOut[i] = segOut{}
			}
			return fmt.Errorf("failed to decrypt cluster #%d: %w", cindex, err)
		}

		// Sequentially write segment plaintext in order.
		for i := range clusterOut {
			out := clusterOut[i]
			if out.data == nil {
				continue
			}
			if _, err := w.Write(out.data); err != nil {
				if out.fromDecompPool {
					decompPool.put(out.data)
				} else {
					segPool.put(out.data)
				}
				// Release remaining slots.
				for j := i + 1; j < len(clusterOut); j++ {
					if clusterOut[j].data != nil {
						if clusterOut[j].fromDecompPool {
							decompPool.put(clusterOut[j].data)
						} else {
							segPool.put(clusterOut[j].data)
						}
					}
				}
				return fmt.Errorf("failed to write cluster #%d segment %d: %w", cindex, i, err)
			}
			if out.fromDecompPool {
				decompPool.put(out.data)
			} else {
				segPool.put(out.data)
			}
			clusterOut[i] = segOut{}
		}

		clusterMAC = nextClusterMac
		cindex++

		if totalSize >= rootHdr.FileSize {
			break
		}
	}

	// Padding (mirrors decryptClusters): the original implementation discards
	// the padding plaintext (it is not part of the file payload) but verifies
	// its HMAC matches the trailing clusterMAC. Read what's left of r.
	var paddingKey headerKey
	if err := binary.Read(
		hkdf.New(sha256.New, mainKey, []byte{}, []byte(PaddingKeyInfo)),
		binary.LittleEndian,
		&paddingKey,
	); err != nil {
		return fmt.Errorf("failed to derive padding key: %w", err)
	}
	paddingData, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read padding data: %w", err)
	}
	if len(paddingData) != 0 {
		phmac := hmac.New(sha256.New, paddingKey.MAC[:])
		if _, err := phmac.Write(paddingData); err != nil {
			return fmt.Errorf("failed to write padding data HMAC: %w", err)
		}
		if !hmac.Equal(clusterMAC[:], phmac.Sum(nil)) {
			return fmt.Errorf("invalid padding HMAC: %x; expected %x", phmac.Sum(nil), clusterMAC)
		}
	}

	return nil
}
