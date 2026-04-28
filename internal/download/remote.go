package download

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ranger"
	"github.com/pkg/errors"
)

// RemoteConfig is the remote reader config
type RemoteConfig struct {
	Proxy    string
	Insecure bool
}

// NewRemoteZipReader returns a new remote zip file reader
func NewRemoteZipReader(zipURL string, config *RemoteConfig) (*zip.Reader, error) {

	url, err := url.Parse(zipURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse url")
	}

	reader, err := ranger.NewReader(&ranger.HTTPRanger{
		URL:       url,
		UserAgent: utils.RandomAgent(),
		Client: &http.Client{
			Transport: &http.Transport{
				Proxy:           GetProxy(config.Proxy),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ranger reader")
	}

	length, err := reader.Length()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get reader length")
	}

	zr, err := zip.NewReader(reader, length)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create zip reader")
	}

	return zr, nil
}

// IsRemoteAEA performs an HTTP Range request for the first 4 bytes of the
// remote URL and returns true if the response body starts with the AEA1
// magic. It returns false (without error) for any other content prefix.
func IsRemoteAEA(ctx context.Context, remoteURL string, config *RemoteConfig) (bool, error) {
	if config == nil {
		config = &RemoteConfig{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("User-Agent", utils.RandomAgent())
	req.Header.Set("Range", "bytes=0-3")

	cli := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(config.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
		},
	}
	resp, err := cli.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to probe remote URL: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return false, fmt.Errorf("unexpected status code probing remote URL: %s", resp.Status)
	}
	magic := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, magic); err != nil {
		return false, fmt.Errorf("failed to read remote magic: %w", err)
	}
	return string(magic) == "AEA1", nil
}

// OpenRemoteStream issues a streaming HTTP GET against remoteURL and returns
// the response body together with the Content-Length (or -1 if not provided).
// Closing the returned ReadCloser cancels the underlying request.
func OpenRemoteStream(ctx context.Context, remoteURL string, config *RemoteConfig) (io.ReadCloser, int64, error) {
	rc, _, total, err := OpenRemoteStreamAt(ctx, remoteURL, 0, config)
	return rc, total, err
}

// OpenRemoteStreamAt is like OpenRemoteStream, but starts the response body
// at the given byte offset using a Range request (when offset > 0). It
// returns the body, the size of the response body (i.e. the remaining
// bytes), and the total size of the resource if known.
func OpenRemoteStreamAt(ctx context.Context, remoteURL string, offset int64, config *RemoteConfig) (io.ReadCloser, int64, int64, error) {
	if config == nil {
		config = &RemoteConfig{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("User-Agent", utils.RandomAgent())
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	cli := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(config.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
		},
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to open remote stream: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		_ = resp.Body.Close()
		return nil, 0, 0, fmt.Errorf("unexpected status code opening remote stream: %s", resp.Status)
	}
	if offset > 0 && resp.StatusCode != http.StatusPartialContent {
		// Server ignored the Range header; caller must re-do without offset.
		_ = resp.Body.Close()
		return nil, 0, 0, fmt.Errorf("server does not support Range requests (got %s)", resp.Status)
	}

	var bodySize int64 = -1
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			bodySize = n
		}
	}
	totalSize := bodySize
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		// Format: "bytes 0-499/1234" or "bytes 0-499/*"
		if i := strings.LastIndex(cr, "/"); i >= 0 {
			if n, err := strconv.ParseInt(cr[i+1:], 10, 64); err == nil {
				totalSize = n
			}
		}
	} else if offset > 0 && bodySize > 0 {
		totalSize = offset + bodySize
	}
	return resp.Body, bodySize, totalSize, nil
}
