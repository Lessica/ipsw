// Package extract contains the extract commands.
package extract

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	fwcmd "github.com/blacktop/ipsw/internal/commands/fw"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/ota"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/dustin/go-humanize"
)

var ErrNoDecryptionKey = errors.New("no decryption key found")

type remoteKernelcacheMember struct {
	file    *zip.File
	devices []string
	output  string
	// iv/key are populated when a wiki key matches the member; payload is populated
	// when the member was peeked and found unencrypted (already decompressed).
	iv      []byte
	key     []byte
	payload []byte
}

// Config is the extract command configuration.
type Config struct {
	// path to the IPSW
	IPSW string `json:"ipsw,omitempty"`
	// url to the remote IPSW
	URL string `json:"url,omitempty"`
	// regex pattern to search for in the IPSW
	Pattern string `json:"pattern,omitempty"`
	// arches of the DSCs to extract
	Arches []string `json:"arches,omitempty"`
	// extract the DriverKit DSCs
	DriverKit bool `json:"driver_kit,omitempty"`
	// extract the DriverKit DSCs
	AllDSCs bool `json:"all_dscs,omitempty"`
	// extract a single device's kernelcache
	KernelDevice string `json:"kernel_device,omitempty"`
	// http proxy to use
	Proxy string `json:"proxy,omitempty"`
	// don't verify the certificate chain
	Insecure bool `json:"insecure,omitempty"`
	// search the DMGs for files
	DMGs bool `json:"dmgs,omitempty"`
	// type of DMG to extract
	// pattern: (app|sys|fs)
	DmgType string `json:"dmg_type,omitempty"`
	// flatten the extracted files paths (remove the folders)
	Flatten bool `json:"flatten,omitempty"`
	// show the progress bar (when using the CLI)
	Progress bool `json:"progress,omitempty"`
	// Is AEA private key encrypted
	Encrypted bool `json:"encrypted,omitempty"`
	// AEA private key PEM DB JSON file
	PemDB string `json:"pem_db,omitempty"`
	// AEA private key in base64 format
	AEAKey string `json:"aea_key,omitempty"`
	// output directory to write extracted files to
	Output string `json:"output,omitempty"`
	// output as JSON
	JSON bool `json:"json,omitempty"`
	// show info
	Info bool `json:"info,omitempty"`
	// Lookup decryption keys from theapplewiki.com
	Lookup bool `json:"lookup,omitempty"`
	// FirmwareKeys are caller-provided decryption keys from theapplewiki.com
	FirmwareKeys download.WikiFWKeys `json:"-"`
	// BuildManifest identity selector (used for rdisk)
	Ident string `json:"ident,omitempty"`
	// Build is the OTA buildID (used to name the on-disk AEA partial so
	// `ipsw download appledb` / `download ota` can resume it).
	Build string `json:"build,omitempty"`
	// Version is the OTA version string (paired with Build for naming).
	Version string `json:"version,omitempty"`
	// RemoveCommas matches the `--remove-commas` download flag for naming.
	RemoveCommas bool `json:"remove_commas,omitempty"`
	// FwType is the firmware type ("ota", "rsr", "ipsw") used in the
	// download appledb naming scheme.
	FwType string `json:"fw_type,omitempty"`
	// AnyKernel matches any kernelcache.* variant (release / development /
	// research). Default is to match only kernelcache.release.*.
	AnyKernel bool `json:"any_kernel,omitempty"`
	// AEADestName, if set, overrides the on-disk filename used for the
	// streamed AEA partial. The path is treated as relative to Output.
	// Use this when the caller wants the partial to follow a non-default
	// naming scheme (e.g. `download ota` NORMAL MODE layout).
	AEADestName string `json:"aea_dest_name,omitempty"`
	// AEAResumeCommand, if set, overrides the copy-pasteable command shown
	// to the user after a partial AEA OTA is saved.
	AEAResumeCommand string `json:"aea_resume_command,omitempty"`
	// AEAFastKernel, when true, uses HTTP-Range driven random access into
	// the AEA container to fetch only the cipher segments overlapping the
	// kernelcache YAA frame. This trades the ability to seed a `.download`
	// resume partial for a roughly 10× reduction in transferred bytes.
	// Currently assumes the kernelcache lives in chunk
	// AEAFastKernelChunk (default 4) of the OTA's YOP_MANIFEST.
	AEAFastKernel bool `json:"aea_fast_kernel,omitempty"`
	// AEAFastKernelChunk is the YOP_MANIFEST chunk index where the
	// kernelcache is expected to live when AEAFastKernel is enabled.
	// Defaults to 4 if zero.
	AEAFastKernelChunk int `json:"aea_fast_kernel_chunk,omitempty"`

	info     *info.Info
	wikiKeys download.WikiFWKeys
}

func isURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// decryptExtractedIM4P decrypts an extracted IM4P file using wiki keys if available
// Returns the new path to the decrypted file (with original extension removed)
func decryptExtractedIM4P(extractedPath string, wikiKeys download.WikiFWKeys) (string, error) {
	if wikiKeys == nil {
		return extractedPath, nil
	}

	// Create decrypted output file without the .im4p/.img3 extension
	// e.g., DeviceTree.n51ap.im4p -> DeviceTree.n51ap
	decryptedPath := strings.TrimSuffix(extractedPath, filepath.Ext(extractedPath))

	decrypted, err := DecryptPayloadWithKeys(extractedPath, decryptedPath, wikiKeys)
	if err != nil {
		return extractedPath, fmt.Errorf("failed to decrypt %s: %v", filepath.Base(extractedPath), err)
	}
	if !decrypted {
		log.Debugf("no key found for %s", filepath.Base(extractedPath))
		return extractedPath, nil
	}
	log.Infof("Decrypting %s", filepath.Base(extractedPath))

	// Remove original encrypted file
	if err := os.Remove(extractedPath); err != nil {
		log.Warnf("failed to remove encrypted file: %v", err)
	}

	return decryptedPath, nil
}

// DecryptPayloadWithKeys decrypts an extracted IM4P/IMG3 payload if a matching wiki key exists.
func DecryptPayloadWithKeys(inputPath, outputPath string, wikiKeys download.WikiFWKeys) (bool, error) {
	iv, key, ok, err := firmwareKeyForFile(wikiKeys, inputPath)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0750); err != nil {
		return false, fmt.Errorf("failed to create output directory: %v", err)
	}
	if err := img4.DecryptPayload(inputPath, outputPath, iv, key); err != nil {
		return false, err
	}
	return true, nil
}

func firmwareKeyForFile(wikiKeys download.WikiFWKeys, filename string) ([]byte, []byte, bool, error) {
	if wikiKeys == nil {
		return nil, nil, false, nil
	}
	for _, fwKey := range wikiKeys {
		for idx, keyFilename := range fwKey.Filename {
			if !firmwareKeyFilenameMatches(filename, keyFilename) {
				continue
			}
			iv, key, ok, err := decodeFirmwareKeyMaterial(fwKey, idx)
			if err != nil || ok {
				return iv, key, ok, err
			}
		}
	}
	return nil, nil, false, nil
}

func firmwareKeyFilenameMatches(path, keyFilename string) bool {
	if len(keyFilename) == 0 {
		return false
	}
	normalizedPath := strings.ToLower(strings.ReplaceAll(path, " ", "_"))
	normalizedKeyFilename := strings.ToLower(strings.ReplaceAll(keyFilename, " ", "_"))
	return strings.HasSuffix(normalizedPath, normalizedKeyFilename)
}

func decodeFirmwareKeyMaterial(fwKey download.WikiFWKey, idx int) ([]byte, []byte, bool, error) {
	if idx < len(fwKey.Iv) && idx < len(fwKey.Key) && isKnownKeyPart(fwKey.Iv[idx]) && isKnownKeyPart(fwKey.Key[idx]) {
		iv, err := hex.DecodeString(fwKey.Iv[idx])
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to decode iv: %v", err)
		}
		key, err := hex.DecodeString(fwKey.Key[idx])
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to decode key: %v", err)
		}
		return iv, key, true, nil
	}
	if idx < len(fwKey.Kbag) && isKnownKeyPart(fwKey.Kbag[idx]) {
		kbag, err := hex.DecodeString(fwKey.Kbag[idx])
		if err != nil {
			return nil, nil, false, fmt.Errorf("failed to decode kbag: %v", err)
		}
		if len(kbag) <= aes.BlockSize {
			return nil, nil, false, fmt.Errorf("kbag is too short: %d bytes", len(kbag))
		}
		return kbag[:aes.BlockSize], kbag[aes.BlockSize:], true, nil
	}
	return nil, nil, false, nil
}

func isKnownKeyPart(value string) bool {
	return len(value) > 0 && !strings.EqualFold(value, "Unknown")
}

func getFolder(c *Config) (*info.Info, string, error) {
	if c.info == nil {
		var err error
		if c.Lookup && c.wikiKeys == nil {
			fPath := filepath.Clean(c.IPSW)
			log.Debugf("Lookup enabled, parsing IPSW path: %s", fPath)
			log.Info("Looking up decryption keys...")
			wkeys, lookupErr := download.LookupKeysFromPath(fPath, "", false)
			if lookupErr != nil {
				log.Warnf("failed to lookup keys from theapplewiki.com: %v", lookupErr)
			} else {
				c.wikiKeys = wkeys // Store keys for later use in extraction
				dtkey, keyErr := wkeys.GetKeyByRegex(`.*DeviceTree.*(img3|im4p)$`)
				if keyErr != nil {
					log.Warnf("failed to get DeviceTree key: %v", keyErr)
				} else {
					log.Debugf("Found DeviceTree key: %s", dtkey)
					c.info, err = info.Parse(fPath, dtkey)
					if err != nil {
						return nil, "", fmt.Errorf("failed to parse plists in IPSW: %v", err)
					}
				}
			}
		}
		if c.info == nil {
			c.info, err = info.Parse(filepath.Clean(c.IPSW))
			if err != nil {
				return nil, "", fmt.Errorf("failed to parse plists in IPSW: %v", err)
			}
		}
	}
	folder, err := c.info.GetFolder(c.KernelDevice)
	if err != nil {
		return c.info, folder, fmt.Errorf("failed to get folder from IPSW metadata: %v", err)
	}
	return c.info, folder, nil
}

func getRemoteFolder(c *Config) (*info.Info, *zip.Reader, string, error) {
	zr, err := download.NewRemoteZipReader(c.URL, &download.RemoteConfig{
		Proxy:    c.Proxy,
		Insecure: c.Insecure,
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to download remote zip: %v", err)
	}
	if c.info == nil {
		if c.Lookup {
			log.Info("Looking up decryption keys...")
			wkeys, lookupErr := download.LookupKeysFromPath(c.URL, c.Proxy, c.Insecure)
			if lookupErr != nil {
				log.Warnf("failed to lookup keys from theapplewiki.com: %v", lookupErr)
			} else {
				c.wikiKeys = wkeys // Store keys for later use in extraction
				dtkey, keyErr := wkeys.GetKeyByRegex(`.*DeviceTree.*(img3|im4p)$`)
				if keyErr != nil {
					log.Warnf("failed to get DeviceTree key: %v", keyErr)
				} else {
					c.info, err = info.ParseZipFiles(zr.File, dtkey)
					if err != nil {
						return nil, nil, "", fmt.Errorf("failed to parse plists in remote zip: %v", err)
					}
				}
			}
		}
		if c.info == nil {
			c.info, err = info.ParseZipFiles(zr.File)
			if err != nil {
				return nil, nil, "", fmt.Errorf("failed to parse plists in remote zip: %v", err)
			}
		}
	}
	folder, err := c.info.GetFolder(c.KernelDevice)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get folder from remote zip metadata: %v", err)
	}
	return c.info, zr, folder, nil
}

func ExtractFromDMG(ipswPath, dmgPath, destPath, pemDB string, pattern *regexp.Regexp) ([]string, error) {
	skipCleanup := false
	tmpExtractDir := ""

	// For AEA-encrypted DMGs, check if the decrypted version already exists
	// (e.g. already extracted + mounted by a prior step like mountSystemOsDMGs).
	// Reuse it to avoid overwriting a mounted DMG's backing file.
	if filepath.Ext(dmgPath) == ".aea" {
		decryptedPath := strings.TrimSuffix(dmgPath, filepath.Ext(dmgPath))
		// Only reuse if this is a real path (not a bare IPSW-internal filename).
		if filepath.IsAbs(decryptedPath) || filepath.Dir(decryptedPath) != "." {
			if _, err := os.Stat(decryptedPath); err == nil {
				dmgPath = decryptedPath
				skipCleanup = true
			}
		}
	}

	if !skipCleanup {
		// If dmgPath is a bare filename (e.g. 043-....dmg.aea), treat it as an IPSW-internal
		// identifier and always extract it into a fresh temp dir. This avoids collisions with
		// same-named files left in the current working directory from prior runs.
		dmgNameOnly := !filepath.IsAbs(dmgPath) && filepath.Dir(dmgPath) == "."
		if dmgNameOnly || func() bool {
			_, err := os.Stat(dmgPath)
			return os.IsNotExist(err)
		}() {
			tmpDIR, err := os.MkdirTemp("", "ipsw_extract_dmg")
			if err != nil {
				return nil, fmt.Errorf("failed to create temp dir: %v", err)
			}
			tmpExtractDir = tmpDIR
			defer os.RemoveAll(tmpExtractDir)

			dmgs, err := utils.Unzip(ipswPath, tmpExtractDir, func(f *zip.File) bool {
				return strings.EqualFold(filepath.Base(f.Name), filepath.Base(dmgPath))
			})
			if err != nil {
				return nil, fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
			}
			if len(dmgs) == 0 {
				return nil, fmt.Errorf("failed to find %s in IPSW", dmgPath)
			}
			dmgPath = dmgs[0] // update dmgPath to the actual extracted file path
		}

		if filepath.Ext(dmgPath) == ".aea" {
			var err error
			dmgPath, err = aea.Decrypt(&aea.DecryptConfig{
				Input:    dmgPath,
				Output:   filepath.Dir(dmgPath),
				PemDB:    pemDB,
				Proxy:    "",    // TODO: make proxy configurable
				Insecure: false, // TODO: make insecure configurable
			})
			if err != nil {
				return nil, fmt.Errorf("failed to parse AEA encrypted DMG: %v", err)
			}
			defer os.Remove(dmgPath)
		}
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to IPSW FS dmg: %v", err)
	}
	if alreadyMounted {
		utils.Indent(log.Debug, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, false)
			}); err != nil {
				log.Errorf("failed to unmount DMG %s at %s: %v", dmgPath, mountPoint, err)
			}
		}()
	}

	var artifacts []string
	// Track visited to avoid loops/duplicates (symlinks)
	visited := make(map[string]bool)

	extractMatchingFile := func(path string) error {
		rel := strings.TrimPrefix(path, mountPoint)
		rel = strings.TrimPrefix(rel, string(os.PathSeparator))
		rel = filepath.Clean(rel)
		if pattern.MatchString(string(os.PathSeparator)+rel) || pattern.MatchString(rel) {
			fname := filepath.Join(destPath, rel)
			if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", filepath.Join(destPath, filepath.Dir(fname)), err)
			}
			utils.Indent(log.Debug, 3)(fmt.Sprintf("Extracting to %s", fname))
			if err := utils.Copy(path, fname); err != nil {
				log.WithError(err).Errorf("failed to copy %s to %s", path, fname)
				return nil // keep going
			}
			artifacts = append(artifacts, fname)
		}
		return nil
	}

	// extract files that match regex pattern (follows symlinked directories)
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				log.Debugf("skipping path due to permission denied: %s", path)
				return nil
			}
			log.WithError(err).Debugf("failed to walk %s", mountPoint)
			return nil // keep going
		}
		if info.Mode()&os.ModeSymlink != 0 {
			// Follow symlinked directories to find files reachable only through symlinks
			// (e.g. /sbin -> /usr/sbin on modern Apple firmwares)
			if linkPath, err := filepath.EvalSymlinks(path); err == nil {
				linfo, err := os.Stat(linkPath)
				if err != nil {
					return nil
				}
				if linfo.IsDir() && !visited[linkPath] {
					visited[linkPath] = true
					return filepath.Walk(linkPath, func(subPath string, subInfo os.FileInfo, subErr error) error {
						if subErr != nil {
							log.WithError(subErr).Debug("failed to walk symlinked path")
							return nil
						}
						if !subInfo.IsDir() && !visited[subPath] {
							visited[subPath] = true
							return extractMatchingFile(subPath)
						}
						return nil
					})
				} else if !linfo.IsDir() {
					// Symlink to a file — check against pattern
					return extractMatchingFile(linkPath)
				}
			}
			return nil
		}
		if info.IsDir() {
			return nil // skip directories
		}
		if !visited[path] {
			visited[path] = true
			return extractMatchingFile(path)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to extract File System files from IPSW: %v", err)
	}

	return artifacts, nil
}

// FirmwareType returns the type of the firmware: IPSW or OTA
func FirmwareType(c *Config) (string, error) {
	var err error
	if len(c.IPSW) > 0 {
		// Use getFolder which handles key lookup if enabled
		_, _, err = getFolder(c)
		if err != nil {
			return "", err
		}
		return c.info.Plists.Type, nil
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return "", fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		c.info, _, _, err = getRemoteFolder(c)
		if err != nil {
			return "", err
		}
		return c.info.Plists.Type, nil
	}
	return "", fmt.Errorf("no IPSW or URL provided")
}

func IsAEA(c *Config) (bool, error) {
	if len(c.IPSW) > 0 {
		return magic.IsAA(filepath.Clean(c.IPSW))
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return false, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		req, err := http.NewRequest("GET", c.URL, nil)
		if err != nil {
			return false, fmt.Errorf("failed to create HTTP request: %v", err)
		}
		req.Header.Set("Range", "bytes=0-4")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("client failed to perform request: %v", err)
		}
		defer resp.Body.Close()
		mdata, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("failed to read remote data: %v", err)
		}
		return magic.IsAEAData(bytes.NewReader(mdata))
	}
	return false, fmt.Errorf("no IPSW or URL provided")
}

// Kernelcache extracts the kernelcache from an IPSW
func Kernelcache(c *Config) (map[string][]string, error) {
	if len(c.IPSW) > 0 {
		_, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		return kernelcache.Extract(c.IPSW, filepath.Join(filepath.Clean(c.Output), folder), c.KernelDevice)
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		// Detect AEA-encrypted OTA payload and stream-decrypt directly.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		isAEA, err := download.IsRemoteAEA(ctx, c.URL, &download.RemoteConfig{
			Proxy:    c.Proxy,
			Insecure: c.Insecure,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to probe remote URL: %v", err)
		}
		if isAEA {
			if c.AEAFastKernel {
				if out, err := streamRemoteAEAKernelcacheRanged(ctx, c); err == nil {
					return out, nil
				} else {
					log.WithError(err).Warn("Fast Range path failed, falling back to streaming AEA decrypt")
				}
			}
			return streamRemoteAEAKernelcache(ctx, cancel, c)
		}
		i, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		keys := c.FirmwareKeys
		if len(keys) == 0 {
			keys = c.wikiKeys
		}
		if len(keys) > 0 {
			return remoteKernelcacheWithKeys(i, zr, filepath.Join(filepath.Clean(c.Output), folder), c.KernelDevice, keys, c.Progress)
		}
		return kernelcache.RemoteParse(zr, filepath.Join(filepath.Clean(c.Output), folder), c.KernelDevice)
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}

func remoteKernelcacheWithKeys(i *info.Info, zr *zip.Reader, destPath, device string, wikiKeys download.WikiFWKeys, progress bool) (map[string][]string, error) {
	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_kcache")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store kernelcache: %v", err)
	}
	defer os.RemoveAll(tmpDIR)

	artifacts := make(map[string][]string)
	selected, err := selectRemoteKernelcacheMembers(i, zr.File, destPath, device, wikiKeys)
	if err != nil {
		return nil, err
	}

	for _, kc := range selected {
		if err := os.MkdirAll(filepath.Dir(kc.output), 0750); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %v", err)
		}

		if kc.payload != nil {
			if err := os.WriteFile(kc.output, kc.payload, 0660); err != nil {
				return nil, fmt.Errorf("failed to write kernelcache %s: %v", kc.file.Name, err)
			}
			artifacts[kc.output] = kc.devices
			continue
		}

		extracted, err := utils.SearchZip([]*zip.File{kc.file}, regexp.MustCompile("^"+regexp.QuoteMeta(kc.file.Name)+"$"), tmpDIR, true, progress)
		if err != nil {
			return nil, fmt.Errorf("failed to extract kernelcache %s: %v", kc.file.Name, err)
		}
		if len(extracted) == 0 {
			return nil, fmt.Errorf("failed to extract kernelcache %s", kc.file.Name)
		}
		if err := img4.DecryptPayload(extracted[0], kc.output, kc.iv, kc.key); err != nil {
			return nil, fmt.Errorf("failed to decrypt kernelcache %s: %v", kc.file.Name, err)
		}
		artifacts[kc.output] = kc.devices
	}

	return artifacts, nil
}

func readZipMember(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open zip member %s: %v", f.Name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read zip member %s: %v", f.Name, err)
	}
	return data, nil
}

func selectRemoteKernelcacheMembers(i *info.Info, files []*zip.File, destPath, device string, wikiKeys download.WikiFWKeys) ([]remoteKernelcacheMember, error) {
	var selected []remoteKernelcacheMember
	var missingKeys []string
	var foundKernelcache bool

	for _, f := range files {
		if !strings.Contains(f.Name, "kernelcache.") {
			continue
		}
		devices := i.GetDevicesForKernelCache(f.Name)
		if len(device) > 0 && !slices.Contains(devices, device) {
			continue
		}
		foundKernelcache = true

		fname := filepath.Join(destPath, filepath.Clean(i.GetKernelCacheFileName(f.Name)))
		if _, err := os.Stat(fname); err == nil {
			log.Warnf("kernelcache already exists: %s", fname)
			continue
		}

		iv, key, ok, err := firmwareKeyForFile(wikiKeys, f.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve key for kernelcache %s: %w", f.Name, err)
		}

		var payload []byte
		if !ok {
			data, err := readZipMember(f)
			if err != nil {
				return nil, err
			}
			cc, err := kernelcache.ParseImg4Data(data)
			if errors.Is(err, kernelcache.ErrEncryptedKernelCache) {
				missingKeys = append(missingKeys, f.Name)
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("failed to parse kernelcache %s: %v", f.Name, err)
			}
			payload, err = kernelcache.DecompressData(cc)
			if err != nil {
				return nil, fmt.Errorf("failed to decompress kernelcache %s: %v", f.Name, err)
			}
		}

		selected = append(selected, remoteKernelcacheMember{
			file:    f,
			devices: devices,
			output:  fname,
			iv:      iv,
			key:     key,
			payload: payload,
		})
	}

	if !foundKernelcache {
		if len(device) > 0 {
			return nil, fmt.Errorf("no kernelcache found for device %s in IPSW", device)
		}
		return nil, fmt.Errorf("no kernelcache found in IPSW")
	}
	if len(missingKeys) > 0 {
		return nil, fmt.Errorf("%w for %s", ErrNoDecryptionKey, strings.Join(missingKeys, ", "))
	}

	return selected, nil
}

// countingReadCloser wraps an io.ReadCloser, tracks how many bytes have been
// read from the underlying reader, and optionally tees the bytes to a writer
// (used to persist the encrypted AEA prefix on disk for later resume). Safe
// for sequential single-reader access (the goroutine driving
// aea.DecryptStream).
type countingReadCloser struct {
	rc io.ReadCloser
	// tee receives every byte we successfully read from rc, except for
	// the first teeSkipBytes that are already on disk (used when
	// concatenating a resumed prefix with a fresh HTTP body).
	tee          io.Writer
	teeSkipBytes int64
	n            int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 && c.tee != nil {
		off := 0
		if c.teeSkipBytes > 0 {
			if int64(n) <= c.teeSkipBytes {
				c.teeSkipBytes -= int64(n)
				off = n
			} else {
				off = int(c.teeSkipBytes)
				c.teeSkipBytes = 0
			}
		}
		if off < n {
			// Best-effort: a tee write failure must not abort the decrypt
			// pipeline; just stop teeing further bytes.
			if _, werr := c.tee.Write(p[off:n]); werr != nil {
				c.tee = nil
			}
		}
	}
	c.n += int64(n)
	return n, err
}

func (c *countingReadCloser) Close() error { return c.rc.Close() }
func (c *countingReadCloser) Count() int64 { return c.n }

// streamRemoteAEAKernelcache pulls an AEA-encrypted OTA from c.URL via a
// single streaming HTTP GET, decrypts it on the fly, scans the inner YAA
// stream for the first kernelcache.* entry, and writes the parsed +
// decompressed kernelcache to c.Output. The HTTP body is cancelled as soon
// as the kernelcache is captured, so only the prefix of the OTA up to that
// entry is actually transferred.
func streamRemoteAEAKernelcache(ctx context.Context, cancelHTTP context.CancelFunc, c *Config) (map[string][]string, error) {
	outDir := filepath.Clean(c.Output)
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build an on-disk filename that matches what `ipsw download appledb`
	// would write for the same OTA, so the encrypted bytes we tee can be
	// resumed by the standard downloader (which appends `.download` to its
	// DestName when looking for resumable transfers).
	aeaName := buildAEADestName(c)
	aeaPath := filepath.Join(outDir, aeaName)
	partialPath := aeaPath + ".download"

	// If a previous run already left a complete AEA on disk, decrypt it
	// locally instead of re-downloading.
	if fi, err := os.Stat(aeaPath); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		log.WithFields(log.Fields{
			"path": aeaPath,
			"size": humanize.Bytes(uint64(fi.Size())),
		}).Info("Reusing local AEA OTA")
		f, err := os.Open(aeaPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open local AEA %s: %v", aeaPath, err)
		}
		defer f.Close()
		return streamAEAKernelcache(ctx, cancelHTTP, c, &countingReadCloser{rc: f}, fi.Size(), outDir, "", aeaPath, fi.Size())
	}

	// If a previous run wrote a `.download` partial, resume from where it
	// stopped: read the cached prefix from disk first, then continue with
	// an HTTP Range request and tee additional bytes back into the same
	// file. This lets `--kernel` reuse the work done by either an earlier
	// `--kernel` invocation or an interrupted `ipsw download` resume.
	var resumeOffset int64
	if fi, err := os.Stat(partialPath); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
		resumeOffset = fi.Size()
	}

	if resumeOffset > 0 {
		return resumeRemoteAEAKernelcache(ctx, cancelHTTP, c, outDir, partialPath, aeaPath, resumeOffset)
	}

	body, size, err := download.OpenRemoteStream(ctx, c.URL, &download.RemoteConfig{
		Proxy:    c.Proxy,
		Insecure: c.Insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open remote AEA stream: %v", err)
	}
	defer body.Close()

	if size > 0 {
		log.WithField("size", humanize.Bytes(uint64(size))).Info("Streaming remote AEA OTA")
	} else {
		log.Info("Streaming remote AEA OTA")
	}

	// Tee the encrypted body into <destName>.download so the
	// already-transferred bytes survive a cancel/error and can be resumed
	// later by the standard `ipsw download` resume-all logic. We don't
	// write directly to the final name so that a complete file (which the
	// local-reuse path above keys on) is never confused with a truncated
	// one.
	var (
		teeFile     *os.File
		teeWriter   io.Writer
		teePathInfo string
	)
	if err := os.MkdirAll(filepath.Dir(partialPath), 0755); err != nil {
		log.WithError(err).WithField("path", partialPath).Warn("Could not create directory for partial AEA file; bytes will not be persisted")
	} else if f, err := os.Create(partialPath); err != nil {
		log.WithError(err).WithField("path", partialPath).Warn("Could not open partial AEA file; bytes will not be persisted")
	} else {
		teeFile = f
		teeWriter = f
		teePathInfo = partialPath
		defer func() { _ = teeFile.Close() }()
	}

	counter := &countingReadCloser{rc: body, tee: teeWriter}
	return streamAEAKernelcache(ctx, cancelHTTP, c, counter, size, outDir, teePathInfo, aeaPath, 0)
}

// resumeRemoteAEAKernelcache continues an interrupted streaming AEA
// download. It reads the on-disk `.download` prefix first, then issues a
// Range request to fetch the remainder, teeing newly-received bytes into
// the same file (in append mode). If the server does not honour Range
// requests, it falls back to a fresh GET that overwrites the partial.
func resumeRemoteAEAKernelcache(
	ctx context.Context,
	cancelHTTP context.CancelFunc,
	c *Config,
	outDir, partialPath, aeaPath string,
	resumeOffset int64,
) (map[string][]string, error) {
	body, _, totalSize, err := download.OpenRemoteStreamAt(ctx, c.URL, resumeOffset, &download.RemoteConfig{
		Proxy:    c.Proxy,
		Insecure: c.Insecure,
	})
	if err != nil {
		log.WithError(err).Warn("Could not resume AEA download; restarting from scratch")
		// Fall through to a fresh download by removing the partial.
		_ = os.Remove(partialPath)
		body, size, err := download.OpenRemoteStream(ctx, c.URL, &download.RemoteConfig{
			Proxy:    c.Proxy,
			Insecure: c.Insecure,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to open remote AEA stream: %v", err)
		}
		defer body.Close()
		if size > 0 {
			log.WithField("size", humanize.Bytes(uint64(size))).Info("Streaming remote AEA OTA")
		} else {
			log.Info("Streaming remote AEA OTA")
		}
		teeFile, err := os.Create(partialPath)
		if err != nil {
			log.WithError(err).WithField("path", partialPath).Warn("Could not open partial AEA file; bytes will not be persisted")
			counter := &countingReadCloser{rc: body}
			return streamAEAKernelcache(ctx, cancelHTTP, c, counter, size, outDir, "", aeaPath, 0)
		}
		defer func() { _ = teeFile.Close() }()
		counter := &countingReadCloser{rc: body, tee: teeFile}
		return streamAEAKernelcache(ctx, cancelHTTP, c, counter, size, outDir, partialPath, aeaPath, 0)
	}
	defer body.Close()

	if totalSize > 0 {
		log.WithFields(log.Fields{
			"size":      humanize.Bytes(uint64(totalSize)),
			"resume":    humanize.Bytes(uint64(resumeOffset)),
			"remaining": humanize.Bytes(uint64(totalSize - resumeOffset)),
		}).Info("Resuming remote AEA OTA")
	} else {
		log.WithField("resume", humanize.Bytes(uint64(resumeOffset))).Info("Resuming remote AEA OTA")
	}

	prefix, err := os.Open(partialPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open partial AEA %s: %v", partialPath, err)
	}
	defer prefix.Close()

	// Append teed bytes to the same partial file.
	teeFile, err := os.OpenFile(partialPath, os.O_WRONLY|os.O_APPEND, 0o660)
	if err != nil {
		log.WithError(err).WithField("path", partialPath).Warn("Could not append to partial AEA file; bytes will not be persisted")
	} else {
		defer func() { _ = teeFile.Close() }()
	}

	combined := io.MultiReader(prefix, body)
	counter := &countingReadCloser{
		rc:           &readCloserShim{r: combined, c: body},
		tee:          teeFile,
		teeSkipBytes: resumeOffset, // the prefix bytes are already on disk
		n:            0,
	}
	return streamAEAKernelcache(ctx, cancelHTTP, c, counter, totalSize, outDir, partialPath, aeaPath, resumeOffset)
}

// readCloserShim adapts an io.Reader (e.g. an io.MultiReader) into an
// io.ReadCloser whose Close defers to the underlying network stream so that
// cancelling the HTTP request still works.
type readCloserShim struct {
	r io.Reader
	c io.Closer
}

func (s *readCloserShim) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *readCloserShim) Close() error               { return s.c.Close() }

// buildAEADestName replicates the OTA naming used by `ipsw download appledb`
// so the streamed `.download` partial is recognised as a resumable transfer
// when the user later re-runs the same command without `--kernel`.
//
// If c.AEADestName is set the caller has supplied an explicit name (relative
// to Output) and it is used verbatim.
func buildAEADestName(c *Config) string {
	if c.AEADestName != "" {
		return c.AEADestName
	}
	base := filepath.Base(c.URL)
	if c.RemoveCommas {
		base = strings.ReplaceAll(base, ",", "_")
	}
	if u, err := url.Parse(c.URL); err == nil {
		if b := filepath.Base(u.Path); b != "" && b != "/" && b != "." {
			base = b
			if c.RemoveCommas {
				base = strings.ReplaceAll(base, ",", "_")
			}
		}
	}
	if c.FwType == "" && c.Build == "" && c.Version == "" && c.KernelDevice == "" {
		return base
	}
	var details string
	if c.Version != "" {
		details += c.Version + "_"
	}
	if c.Build != "" {
		details += c.Build + "_"
	}
	if c.KernelDevice != "" {
		details += c.KernelDevice + "_"
	}
	fwType := c.FwType
	if fwType == "" {
		fwType = "ota"
	}
	details += strings.ToUpper(fwType) + "_"
	return details + base
}

// streamAEAKernelcache drives the shared decrypt + YAA-scan + kernelcache
// pipeline against any AEA reader (remote stream or local file).
//
// partialPath, when non-empty, is the on-disk file that the AEA bytes are
// being teed into; finalPath is its destination name once the full
// container has been transferred. prefixBytes is the number of bytes the
// counter will read from a local prefix (e.g. an existing `.download`
// file) before the network stream starts; it is subtracted from the
// `transferred` log field so it reflects only newly transferred bytes.
func streamAEAKernelcache(
	ctx context.Context,
	cancelHTTP context.CancelFunc,
	c *Config,
	counter *countingReadCloser,
	size int64,
	outDir string,
	partialPath string,
	finalPath string,
	prefixBytes int64,
) (map[string][]string, error) {
	pr, pw := io.Pipe()
	defer pr.Close()

	streamCfg := &aea.StreamConfig{
		B64SymKey: c.AEAKey,
		PemDB:     c.PemDB,
		Proxy:     c.Proxy,
		Insecure:  c.Insecure,
	}

	decryptErrCh := make(chan error, 1)
	go func() {
		err := aea.DecryptStream(ctx, counter, pw, streamCfg)
		decryptErrCh <- err
		_ = pw.CloseWithError(err)
	}()

	var buf bytes.Buffer
	matcher := ota.IsKernelcacheEntry
	if c.AnyKernel {
		matcher = ota.IsAnyKernelcacheEntry
	}
	matched, scanErr := ota.StreamFindEntry(ctx, pr, matcher, &buf)
	// Stop downloading / decrypting as soon as we have the kernelcache.
	cancelHTTP()
	transferred := counter.Count()
	netTransferred := transferred - prefixBytes
	if netTransferred < 0 {
		netTransferred = 0
	}
	// Drain decryption error (don't return on canceled-context, that's expected).
	select {
	case derr := <-decryptErrCh:
		if scanErr != nil && derr != nil && !errors.Is(derr, context.Canceled) && !errors.Is(derr, io.ErrClosedPipe) {
			return nil, fmt.Errorf("AEA decrypt failed: %v", derr)
		}
	default:
	}
	if scanErr != nil {
		if errors.Is(scanErr, ota.ErrEntryNotFound) {
			return nil, fmt.Errorf("kernelcache not found in OTA stream")
		}
		return nil, fmt.Errorf("failed to locate kernelcache in OTA stream: %v", scanErr)
	}

	logFields := log.Fields{"transferred": humanize.Bytes(uint64(netTransferred))}
	if prefixBytes > 0 {
		logFields["resumed_from"] = humanize.Bytes(uint64(prefixBytes))
	}
	if size > 0 {
		logFields["of_total"] = humanize.Bytes(uint64(size))
		logFields["pct"] = fmt.Sprintf("%.2f%%", float64(transferred)*100/float64(size))
	}
	log.WithFields(logFields).Info("Stopped remote download")

	// Report (and finalize) the persisted AEA file. If we happen to have
	// transferred the entire container, drop the .download suffix so the
	// next invocation can short-circuit via the local-reuse path.
	if partialPath != "" {
		complete := size > 0 && transferred >= size
		if complete && finalPath != "" && finalPath != partialPath {
			if err := os.Rename(partialPath, finalPath); err == nil {
				partialPath = finalPath
			}
		}
		if fi, err := os.Stat(partialPath); err == nil {
			fields := log.Fields{
				"path": partialPath,
				"size": humanize.Bytes(uint64(fi.Size())),
			}
			if complete {
				log.WithFields(fields).Info("Saved full AEA OTA")
			} else {
				log.WithFields(fields).Info("Saved partial AEA OTA for resume")
				log.Info("To resume the rest of the OTA download, run:")
				utils.Indent(log.Info, 2)(aeaResumeHint(c, outDir))
			}
		}
	}

	cc, err := kernelcache.ParseImg4Data(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse kernelcache im4p: %v", err)
	}
	dec, err := kernelcache.DecompressData(cc)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress kernelcache: %v", err)
	}

	fname := filepath.Join(outDir, filepath.Base(matched.Path))
	if err := os.WriteFile(fname, dec, 0o660); err != nil {
		return nil, fmt.Errorf("failed to write kernelcache %s: %v", fname, err)
	}

	artifacts := map[string][]string{fname: nil}
	if c.KernelDevice != "" {
		artifacts[fname] = []string{c.KernelDevice}
	}
	return artifacts, nil
}

// aeaResumeHint returns a copy-pasteable command the user can run to finish
// downloading the full OTA on top of the just-saved `.download` partial.
func aeaResumeHint(c *Config, outDir string) string {
	if c.AEAResumeCommand != "" {
		return c.AEAResumeCommand
	}
	if c.Build == "" || c.KernelDevice == "" {
		// Without enough metadata for `ipsw download appledb` to find the
		// same source, fall back to a generic curl resume hint.
		return fmt.Sprintf("curl -L -C - %q -o %q", c.URL, filepath.Join(outDir, buildAEADestName(c)+".download"))
	}
	fwType := c.FwType
	if fwType == "" {
		fwType = "ota"
	}
	parts := []string{
		"ipsw download appledb",
		fmt.Sprintf("--type %s", fwType),
		fmt.Sprintf("--device %q", c.KernelDevice),
		fmt.Sprintf("--build %q", c.Build),
		"--os iOS",
		fmt.Sprintf("--output %q", outDir),
		"--resume-all",
		"-y",
	}
	if c.RemoveCommas {
		parts = append(parts, "--remove-commas")
	}
	return strings.Join(parts, " ")
}

// SPTM extracts the SPTM firmware from an IPSW
func SPTM(c *Config) ([]string, error) {
	var tmpOut []string
	var outfiles []string

	origOutput := c.Output

	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_sptm")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store SPTM im4p: %v", err)
	}
	defer os.RemoveAll(tmpDIR)
	c.Output = tmpDIR

	c.Pattern = `.*sptm.*im4p$`
	out, err := Search(c)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no SPTM firmware found")
	}

	tmpOut = append(tmpOut, out...)

	c.Pattern = `.*txm.*im4p$`
	out, err = Search(c)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no TXM firmware found")
	}

	tmpOut = append(tmpOut, out...)

	c.Output = origOutput

	for _, f := range tmpOut {
		dat, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to open '%s': %v", f, err)
		}

		im4p, err := img4.ParsePayload(dat)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s': %v", f, err)
		}

		folder := filepath.Join(filepath.Clean(c.Output), strings.TrimPrefix(filepath.Dir(f), tmpDIR))
		if err := os.MkdirAll(folder, 0o750); err != nil {
			return nil, fmt.Errorf("failed to create output directory '%s': %v", folder, err)
		}
		fname := filepath.Join(folder, strings.TrimSuffix(filepath.Base(f), ".im4p"))

		data, err := im4p.GetData()
		if err != nil {
			return nil, fmt.Errorf("failed to get data from '%s': %v", f, err)
		}

		if err = os.WriteFile(fname, data, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write '%s': %v", fname, err)
		}

		outfiles = append(outfiles, fname)
	}

	return outfiles, nil
}

func Exclave(c *Config) ([]string, error) {
	var (
		err      error
		tmpOut   []string
		outfiles []string
		excs     [][]byte
	)

	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_exclave")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store Exlave im4p: %v", err)
	}
	defer os.RemoveAll(tmpDIR)

	c.Pattern = `.*exclavecore_bundle.*im4p$`
	out, err := Search(c, tmpDIR)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Exclave bundles found")
	}
	tmpOut = append(tmpOut, out...)

	for _, f := range tmpOut {
		if strings.Contains(f, ".restore.") {
			continue // TODO: skip restore bundles for now
		}
		im4p, err := img4.OpenPayload(f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse '%s': %v", f, err)
		}
		excData, err := im4p.GetData()
		if err != nil {
			return nil, fmt.Errorf("failed to get data from '%s': %v", f, err)
		}
		if !c.Info {
			// save BUND file
			baseName := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
			excFile := filepath.Join(filepath.Clean(c.Output), baseName)
			if err := os.MkdirAll(filepath.Dir(excFile), 0o750); err != nil {
				return nil, fmt.Errorf("failed to create output directory '%s': %v", excFile, err)
			}
			if err := os.WriteFile(excFile, excData, 0o644); err != nil {
				return nil, fmt.Errorf("failed to write '%s': %v", excFile, err)
			}
			outfiles = append(outfiles, excFile)
		}
		// append to exclave cores for kernel/app extraction
		excs = append(excs, excData)
	}

	for _, exc := range excs {
		if c.Info {
			fwcmd.ShowExclaveCores(exc)
			continue
		}
		out, err := fwcmd.ExtractExclaveCores(exc, filepath.Clean(c.Output))
		if err != nil {
			return nil, fmt.Errorf("failed to extract files from exclave bundle: %v", err)
		}
		outfiles = append(outfiles, out...)
	}

	if c.Info {
		return nil, nil
	}

	return outfiles, nil
}

// DSC extracts the DSC file from an IPSW
func DSC(c *Config) ([]string, error) {
	if len(c.IPSW) > 0 {
		_, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		return dyld.Extract(c.IPSW, filepath.Join(filepath.Clean(c.Output), folder), c.PemDB, c.Arches, c.DriverKit, c.AllDSCs)
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		if i.Plists.Type == "OTA" {
			if runtime.GOOS == "darwin" {
				out, err := dyld.ExtractFromRemoteCryptex(zr, filepath.Join(filepath.Clean(c.Output), folder), c.PemDB, c.Arches, c.DriverKit, c.AllDSCs)
				if err != nil {
					if errors.Is(err, dyld.ErrNoCryptex) {
						if len(c.Arches) == 0 {
							log.Warnf("%v; trying to extract dyld_shared_cache from payload files", err)
						} else {
							log.Warnf("%v for the specified arch(es): %s; trying to extract dyld_shared_cache from payload files (older OTAs didn't use cryptexes)", err, strings.Join(c.Arches, ", "))
						}
						c.Pattern = `^` + dyld.CacheRegex
						rfiles, err := ota.RemoteList(zr)
						if err != nil {
							return nil, fmt.Errorf("failed to list files in remote OTA: %v", err)
						}
						var dcaches []string
						for _, f := range rfiles {
							if regexp.MustCompile(c.Pattern).MatchString(f.Name()) {
								dcaches = append(dcaches, f.Name())
							}
						}
						out, err = ota.RemoteExtract(zr, c.Pattern, filepath.Join(filepath.Clean(c.Output), folder), func(s string) bool {
							s = strings.TrimPrefix(s, folder+string(os.PathSeparator))
							if slices.Contains(dcaches, s) {
								dcaches = utils.RemoveStrFromSlice(dcaches, s)
								if len(dcaches) == 0 {
									return true
								}
							}
							return false
						})
						if err != nil {
							return nil, fmt.Errorf("failed to extract OTA: %v", err)
						}
					} else {
						return nil, fmt.Errorf("failed to extract dyld_shared_cache from remote OTA: %v", err)
					}
				}
				return out, nil
			}
			return nil, fmt.Errorf("extracting dyld_shared_cache from remote OTA is only supported on macOS")
		}
		sysDMG, err := i.GetSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("only iOS16.x/macOS13.x+ supported: failed to get SystemOS DMG from remote zip metadata: %v", err)
		}
		if len(sysDMG) == 0 {
			return nil, fmt.Errorf("only iOS16.x/macOS13.x+ supported: no SystemOS DMG found in remote zip metadata")
		}
		tmpDIR, err := os.MkdirTemp("", "ipsw_extract_remote_dyld")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory to store SystemOS DMG: %v", err)
		}
		defer os.RemoveAll(tmpDIR)
		if _, err := utils.SearchZip(zr.File, regexp.MustCompile(fmt.Sprintf("^%s$", sysDMG)), tmpDIR, c.Flatten, true); err != nil {
			return nil, fmt.Errorf("failed to extract SystemOS DMG from remote IPSW: %v", err)
		}
		return dyld.ExtractFromDMG(i, filepath.Join(tmpDIR, sysDMG), filepath.Join(filepath.Clean(c.Output), folder), c.PemDB, c.Arches, c.DriverKit, c.AllDSCs)
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}

// DMG extracts the DMG from an IPSW
func DMG(c *Config) ([]string, error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return nil, fmt.Errorf("no IPSW or URL provided")
	}

	var err error
	var i *info.Info
	var folder string
	var zr *zip.Reader

	if len(c.IPSW) > 0 {
		i, folder, err = getFolder(c)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filepath.Clean(c.IPSW))
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer f.Close()
		finfo, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to stat IPSW: %v", err)
		}
		zr, err = zip.NewReader(f, finfo.Size())
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err = getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
	}

	var dmgPath string
	switch c.DmgType {
	case "app":
		dmgPath, err = i.GetAppOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find appOS DMG in IPSW: %v", err)
		}
	case "sys":
		dmgPath, err = i.GetSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find systemOS DMG in IPSW: %v", err)
		}
	case "fs":
		dmgPath, err = i.GetFileSystemOsDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find filesystem DMG in IPSW: %v", err)
		}
	case "exc":
		dmgPath, err = i.GetExclaveOSDmg()
		if err != nil {
			return nil, fmt.Errorf("failed to find exclaveOS DMG in IPSW: %v", err)
		}
	case "rdisk":
		dmgPath, err = i.GetRestoreRamDiskDmg(c.Ident)
		if err != nil {
			return nil, fmt.Errorf("failed to find RestoreRamDisk DMG in IPSW: %v", err)
		}
	}

	return utils.SearchZip(zr.File, regexp.MustCompile(dmgPath), filepath.Join(filepath.Clean(c.Output), folder), c.Flatten, c.Progress)
}

func extractRemoteDMG(files []*zip.File, dmgPath, destPath, pemDB string, pattern *regexp.Regexp) ([]string, error) {
	if dmgPath == "" {
		return nil, nil
	}

	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_remote_dmg")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store %s: %v", dmgPath, err)
	}
	defer os.RemoveAll(tmpDIR)

	dmgRegex := regexp.MustCompile(fmt.Sprintf("^%s$", regexp.QuoteMeta(dmgPath)))
	extracted, err := utils.SearchZip(files, dmgRegex, tmpDIR, false, true)
	if err != nil {
		return nil, err
	}

	var artifacts []string
	for _, dmg := range extracted {
		out, err := ExtractFromDMG(dmg, dmg, destPath, pemDB, pattern)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, out...)
	}

	return artifacts, nil
}

// Keybags extracts the keybags from an IPSW
func Keybags(c *Config) (fname string, err error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return "", fmt.Errorf("no IPSW or URL provided")
	}

	var i *info.Info
	var folder string
	var kbags *img4.KeyBags

	if len(c.IPSW) > 0 {
		i, folder, err = getFolder(c)
		if err != nil {
			return "", err
		}
		zr, err := zip.OpenReader(filepath.Clean(c.IPSW))
		if err != nil {
			return "", fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer zr.Close()
		kbags, err = img4.GetKeybagsFromIPSW(zr.File, img4.KeybagMetaData{
			Type:    i.Plists.Type,
			Version: i.Plists.BuildManifest.ProductVersion,
			Build:   i.Plists.BuildManifest.ProductBuildVersion,
			Devices: i.Plists.Restore.SupportedProductTypes,
		}, c.Pattern)
		if err != nil {
			return "", fmt.Errorf("failed to parse im4p kbags: %v", err)
		}
	} else if len(c.URL) > 0 {
		var zr *zip.Reader
		if !isURL(c.URL) {
			return "", fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err = getRemoteFolder(c)
		if err != nil {
			return "", err
		}
		kbags, err = img4.GetKeybagsFromIPSW(zr.File, img4.KeybagMetaData{
			Type:    i.Plists.Type,
			Version: i.Plists.BuildManifest.ProductVersion,
			Build:   i.Plists.BuildManifest.ProductBuildVersion,
			Devices: i.Plists.Restore.SupportedProductTypes,
		}, c.Pattern)
		if err != nil {
			return "", fmt.Errorf("failed to parse im4p kbags: %v", err)
		}
	}

	out, err := json.Marshal(kbags)
	if err != nil {
		return "", fmt.Errorf("failed to marshal im4p kbags: %v", err)
	}

	if c.JSON {
		return string(out), nil
	}

	fname = filepath.Join(filepath.Join(filepath.Clean(c.Output), folder), "kbags.json")
	if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
	}
	if err := os.WriteFile(fname, out, 0o666); err != nil {
		return "", fmt.Errorf("failed to write %s: %v", filepath.Join(filepath.Join(filepath.Clean(c.Output), folder), "kbags.json"), err)
	}

	return
}

// FcsKeys extracts the AEA1 DMG fsc-keys from an IPSW
func FcsKeys(c *Config) ([]string, error) {
	if len(c.IPSW) == 0 && len(c.URL) == 0 {
		return nil, fmt.Errorf("no IPSW or URL provided")
	}

	var artifacts []string

	var err error
	var i *info.Info
	var folder string
	var zr *zip.Reader

	if len(c.IPSW) > 0 {
		i, folder, err = getFolder(c)
		if err != nil {
			return nil, err
		}
		f, err := os.Open(filepath.Clean(c.IPSW))
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer f.Close()
		finfo, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("failed to stat IPSW: %v", err)
		}
		zr, err = zip.NewReader(f, finfo.Size())
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err = getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
	}

	dmgPath, err := i.GetSystemOsDmg()
	if err != nil {
		if errors.Is(err, info.ErrorCryptexNotFound) {
			log.Warn("could not find SystemOS DMG; trying filesystem DMG (older IPSWs don't have cryptexes)")
			dmgPath, err = i.GetFileSystemOsDmg()
			if err != nil {
				return nil, fmt.Errorf("failed to get filesystem DMG: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to get SystemOS DMG: %v", err)
		}
	}

	kmap := make(map[string]aea.PrivateKey)

	if filepath.Ext(dmgPath) != ".aea" {
		return nil, fmt.Errorf("fcs-keys are only found in AEA1 DMGs: found '%s'", filepath.Base(dmgPath))
	}

	out, err := utils.SearchPartialZip(zr.File, regexp.MustCompile(dmgPath+`$`), os.TempDir(), 0x1000, false, false)
	if err != nil {
		return nil, fmt.Errorf("failed to extract fcs-keys from DMG: %v", err)
	}
	defer func() {
		for _, f := range out {
			os.Remove(f)
		}
	}()

	for _, f := range out {
		metadata, err := aea.Info(filepath.Clean(f))
		if err != nil {
			return nil, fmt.Errorf("failed to parse AEA1 metadata: %v", err)
		}
		pkmap, err := metadata.GetPrivateKey(nil, c.PemDB, true, c.Proxy, c.Insecure)
		if err != nil {
			return nil, err
		}

		if c.JSON {
			// check if json file exists
			if _, err := os.Stat(filepath.Join(filepath.Clean(c.Output), "fcs-keys.json")); !os.IsNotExist(err) {
				existingPath := filepath.Join(filepath.Clean(c.Output), "fcs-keys.json")
				data, err := os.ReadFile(existingPath)
				if err != nil {
					return nil, fmt.Errorf("failed to read fcs-keys.json: %v", err)
				}
				existingKeys := make(map[string]aea.PrivateKey)
				if err := json.Unmarshal(data, &existingKeys); err != nil {
					log.WithError(err).Warnf("failed to parse existing fcs-keys JSON '%s'; rebuilding file", existingPath)
				} else {
					maps.Copy(kmap, existingKeys)
				}
			}
			maps.Copy(kmap, pkmap)
		} else {
			for _, pk := range pkmap {
				fname := filepath.Join(filepath.Clean(c.Output), folder, filepath.Base(dmgPath)+".pem")

				if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
					return nil, fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
				}

				if err := os.WriteFile(fname, pk, 0o644); err != nil {
					return nil, fmt.Errorf("failed to write fcs-key.pem: %v", err)
				}

				artifacts = append(artifacts, fname)
			}
		}
	}

	if c.JSON {
		out, err := json.Marshal(kmap)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal fcs-keys: %v", err)
		}
		fname := filepath.Join(filepath.Clean(c.Output), "fcs-keys.json")
		if err := os.WriteFile(fname, out, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write fcs-keys.json: %v", err)
		}
		artifacts = append(artifacts, fname)
	}

	return artifacts, nil
}

// Search searches for files matching a pattern in an IPSW
func Search(c *Config, tempDirectory ...string) ([]string, error) {
	var artifacts []string

	if len(c.Pattern) == 0 {
		return nil, fmt.Errorf("no pattern provided")
	}
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp '%s': %v", c.Pattern, err)
	}
	if len(c.IPSW) > 0 {
		i, folder, err := getFolder(c)
		if err != nil {
			return nil, err
		}
		destPath := filepath.Join(filepath.Clean(c.Output), folder)
		if len(tempDirectory) > 0 {
			destPath = tempDirectory[0]
		}
		zr, err := zip.OpenReader(c.IPSW)
		if err != nil {
			return nil, fmt.Errorf("failed to open IPSW: %v", err)
		}
		defer zr.Close()
		out, err := utils.SearchZip(zr.File, re, destPath, c.Flatten, false)
		if err != nil && !c.DMGs {
			return nil, fmt.Errorf("failed to extract files matching pattern from ZIP: %v", err)
		}
		artifacts = append(artifacts, out...)
		if c.DMGs { // SEARCH THE DMGs
			if appOS, err := i.GetAppOsDmg(); err == nil {
				out, err := ExtractFromDMG(c.IPSW, appOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from AppOS %s: %v", appOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if systemOS, err := i.GetSystemOsDmg(); err == nil {
				out, err := ExtractFromDMG(c.IPSW, systemOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from SystemOS %s: %v", systemOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
				out, err := ExtractFromDMG(c.IPSW, fsOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from filesystem %s: %v", fsOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if excOS, err := i.GetExclaveOSDmg(); err == nil {
				out, err := ExtractFromDMG(c.IPSW, excOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from ExclaveOS %s: %v", excOS, err)
				}
				artifacts = append(artifacts, out...)
			}
		}
		// Decrypt extracted IM4P files if wiki keys are available
		if c.wikiKeys != nil {
			for i, artifact := range artifacts {
				if strings.HasSuffix(strings.ToLower(artifact), ".im4p") || strings.HasSuffix(strings.ToLower(artifact), ".img3") {
					newPath, err := decryptExtractedIM4P(artifact, c.wikiKeys)
					if err != nil {
						log.Warnf("failed to decrypt %s: %v", filepath.Base(artifact), err)
					} else {
						artifacts[i] = newPath
					}
				}
			}
		}
		return artifacts, nil
	} else if len(c.URL) > 0 {
		if !isURL(c.URL) {
			return nil, fmt.Errorf("invalid URL provided: %s", c.URL)
		}
		i, zr, folder, err := getRemoteFolder(c)
		if err != nil {
			return nil, err
		}
		destPath := filepath.Join(filepath.Clean(c.Output), folder)
		if c.Output == "" {
			destPath = folder
		}
		out, err := utils.SearchZip(zr.File, re, destPath, c.Flatten, true)
		if err != nil && !c.DMGs {
			return nil, fmt.Errorf("failed to extract files matching pattern '%s' in remote IPSW: %v", c.Pattern, err)
		}
		artifacts = append(artifacts, out...)
		if c.DMGs { // SEARCH THE DMGs
			if appOS, err := i.GetAppOsDmg(); err == nil {
				out, err := extractRemoteDMG(zr.File, appOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from AppOS %s: %v", appOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if systemOS, err := i.GetSystemOsDmg(); err == nil {
				out, err := extractRemoteDMG(zr.File, systemOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from SystemOS %s: %v", systemOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
				out, err := extractRemoteDMG(zr.File, fsOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from filesystem %s: %v", fsOS, err)
				}
				artifacts = append(artifacts, out...)
			}
			if excOS, err := i.GetExclaveOSDmg(); err == nil {
				out, err := extractRemoteDMG(zr.File, excOS, destPath, c.PemDB, re)
				if err != nil {
					return nil, fmt.Errorf("failed to extract files from ExclaveOS %s: %v", excOS, err)
				}
				artifacts = append(artifacts, out...)
			}
		}
		// Decrypt extracted IM4P files if wiki keys are available
		if c.wikiKeys != nil {
			for i, artifact := range artifacts {
				if strings.HasSuffix(strings.ToLower(artifact), ".im4p") || strings.HasSuffix(strings.ToLower(artifact), ".img3") {
					newPath, err := decryptExtractedIM4P(artifact, c.wikiKeys)
					if err != nil {
						log.Warnf("failed to decrypt %s: %v", filepath.Base(artifact), err)
					} else {
						artifacts[i] = newPath
					}
				}
			}
		}
		return artifacts, nil
	}
	return nil, fmt.Errorf("no IPSW or URL provided")
}

// LaunchdConfig extracts launchd config from an IPSW
func LaunchdConfig(path, pemDB string) (string, error) {
	ipswPath := filepath.Clean(path)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return "", fmt.Errorf("failed to parse IPSW: %v", err)
	}
	fsDMG, err := i.GetFileSystemOsDmg()
	if err != nil {
		return "", fmt.Errorf("failed to get filesystem DMG path: %v", err)
	}
	extracted, err := ExtractFromDMG(ipswPath, fsDMG, os.TempDir(), pemDB, regexp.MustCompile(`.*/sbin/launchd$`))
	if err != nil {
		return "", fmt.Errorf("failed to extract launchd from %s: %v", fsDMG, err)
	}

	if len(extracted) == 0 {
		return "", fmt.Errorf("failed to extract launchd from %s: no files extracted", fsDMG)
	} else if len(extracted) > 1 {
		return "", fmt.Errorf("failed to extract launchd from %s: too many files extracted", fsDMG)
	}
	defer os.Remove(filepath.Clean(extracted[0]))

	var m *macho.File
	fat, err := macho.OpenFat(filepath.Clean(extracted[0]))
	if err == nil {
		m = fat.Arches[len(fat.Arches)-1].File // grab last arch (probably arm64e)
	} else {
		if err == macho.ErrNotFat {
			m, err = macho.Open(filepath.Clean(extracted[0]))
			if err != nil {
				return "", fmt.Errorf("failed to open macho file: %v", err)
			}
		} else {
			return "", fmt.Errorf("failed to open universal macho file: %v", err)
		}
	}

	data, err := m.Section("__TEXT", "__config").Data()
	if err != nil {
		return "", fmt.Errorf("failed to get launchd config: %v", err)
	}

	return string(data), nil
}

// SystemVersion extracts the system version info from an IPSW
func SystemVersion(path, pemDB string) (*plist.SystemVersion, error) {
	ipswPath := filepath.Clean(path)

	i, err := info.Parse(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPSW: %v", err)
	}
	fsDMG, err := i.GetFileSystemOsDmg()
	if err != nil {
		return nil, fmt.Errorf("failed to get filesystem DMG path: %v", err)
	}

	extracted, err := ExtractFromDMG(ipswPath, fsDMG, os.TempDir(), pemDB, regexp.MustCompile(`System/Library/CoreServices/SystemVersion.plist$`))
	if err != nil {
		return nil, fmt.Errorf("failed to extract launchd from %s: %v", fsDMG, err)
	}

	if len(extracted) == 0 {
		return nil, fmt.Errorf("failed to extract SystemVersion.plist from %s: no files extracted", fsDMG)
	} else if len(extracted) > 1 {
		return nil, fmt.Errorf("failed to extract SystemVersion.plist from %s: too many files extracted", fsDMG)
	}
	defer os.Remove(filepath.Clean(extracted[0]))

	dat, err := os.ReadFile(extracted[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read SystemVersion.plist: %v", err)
	}

	return plist.ParseSystemVersion(dat)
}
