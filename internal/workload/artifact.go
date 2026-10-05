package workload

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/FroZor/loreva-agent/internal/agentcrypto"
	"github.com/FroZor/loreva-agent/internal/connectivity"
	"github.com/FroZor/loreva-agent/internal/protocol"
)

const (
	// MaxArtifactBytes bounds one compressed artifact.
	MaxArtifactBytes       = 32 << 20
	maxExtractedBytes      = 128 << 20
	maxExtractedFiles      = 4096
	artifactEndpointPrefix = "/agent/v1/artifacts/"
)

var (
	errExtractionExists = errors.New("artifact extraction destination already exists")
	// ErrArtifactCacheFull refuses an upload that would exceed the cache limit.
	ErrArtifactCacheFull = errors.New("the artifact cache is full; remove unused workloads or artifacts on the node")
)

// ArtifactSource fetches an artifact that is not in the local cache yet.
// The portal session downloads from the portal; a direct device uploads
// artifacts before planning, so its commands have no source.
type ArtifactSource interface {
	Download(ctx context.Context, reference protocol.ArtifactReference, destination io.Writer) error
}

// PortalConfig is the authenticated portal transport for artifact downloads.
type PortalConfig struct {
	PortalURL            string
	PortalCAPEM          string
	ClientCertificate    *tls.Certificate
	AllowDevelopmentHTTP bool
}

// PortalArtifacts downloads artifacts from the enrolled portal over mTLS.
func PortalArtifacts(config PortalConfig) (ArtifactSource, error) {
	endpoint, err := connectivity.HTTPEndpoint(config.PortalURL, artifactEndpointPrefix, config.AllowDevelopmentHTTP)
	if err != nil {
		return nil, fmt.Errorf("resolve portal artifact endpoint: %w", err)
	}
	httpClient, err := connectivity.NewHTTPClient(connectivity.Config{
		PortalCAPEM: config.PortalCAPEM, ClientCertificate: config.ClientCertificate,
	})
	if err != nil {
		return nil, fmt.Errorf("create portal artifact client: %w", err)
	}

	return portalArtifacts{baseURL: strings.TrimSuffix(endpoint, "/") + "/", httpClient: httpClient}, nil
}

type portalArtifacts struct {
	baseURL    string
	httpClient *http.Client
}

type artifactStore struct {
	root   string
	source ArtifactSource
	// uploadLimit bounds the cache size that uploads may grow it to; zero
	// means no limit.
	uploadLimit int64
}

// acquire returns the cached artifact, downloading it from the source when
// it is missing.
func (store artifactStore) acquire(ctx context.Context, reference protocol.ArtifactReference) (string, error) {
	return store.commit(reference, func(destination io.Writer) error {
		if store.source == nil {
			return errors.New("artifact " + reference.ArtifactID + " was not uploaded before planning")
		}

		return store.source.Download(ctx, reference, destination)
	})
}

// store saves an uploaded artifact after checking its size and digest. It
// always reads the whole upload, also when the artifact is already cached,
// so the uploader gets the same verification either way.
func (store artifactStore) store(reference protocol.ArtifactReference, data io.Reader) error {
	if err := store.checkUploadSpace(reference); err != nil {
		return err
	}

	filled := false
	_, err := store.commit(reference, func(destination io.Writer) error {
		filled = true

		return copyVerified(data, destination, reference)
	})
	if err != nil || filled {
		return err
	}

	return copyVerified(data, io.Discard, reference)
}

// commit returns the cached artifact or writes it with fill into a private
// temporary file and moves it into place.
func (store artifactStore) commit(reference protocol.ArtifactReference, fill func(io.Writer) error) (string, error) {
	digest, err := validateArtifactReference(reference)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(store.root, 0o700); err != nil {
		return "", fmt.Errorf("create artifact cache: %w", err)
	}

	destination := filepath.Join(store.root, digest)
	if err := verifyArtifactFile(destination, reference); err == nil {
		return destination, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	temporary, err := os.CreateTemp(store.root, ".artifact-*")
	if err != nil {
		return "", fmt.Errorf("create artifact temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure artifact temporary file: %w", err)
	}
	if err := fill(temporary); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close artifact: %w", err)
	}

	if err := os.Rename(temporaryPath, destination); err != nil {
		if verifyErr := verifyArtifactFile(destination, reference); verifyErr == nil {
			committed = true
			return destination, nil
		}

		return "", fmt.Errorf("commit artifact: %w", err)
	}

	committed = true

	return destination, nil
}

func (portal portalArtifacts) Download(
	ctx context.Context,
	reference protocol.ArtifactReference,
	destination io.Writer,
) (resultErr error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, portal.baseURL+reference.ArtifactID, nil)
	if err != nil {
		return fmt.Errorf("create artifact request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Accept-Encoding", "identity")

	response, err := portal.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("download portal artifact: %w", err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download portal artifact: unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != reference.SizeBytes {
		return errors.New("portal artifact Content-Length does not match the signed size")
	}

	return copyVerified(response.Body, destination, reference)
}

// copyVerified copies exactly reference.SizeBytes bytes whose SHA-256 is
// reference.SHA256.
func copyVerified(source io.Reader, destination io.Writer, reference protocol.ArtifactReference) error {
	hash := sha256.New()
	limited := &io.LimitedReader{R: source, N: reference.SizeBytes + 1}
	written, err := io.Copy(io.MultiWriter(destination, hash), limited)
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	if written != reference.SizeBytes || limited.N <= 0 {
		return errors.New("artifact body does not match the declared size")
	}

	actual := hex.EncodeToString(hash.Sum(nil))
	expected := strings.TrimPrefix(reference.SHA256, "sha256:")
	if actual != expected {
		return errors.New("artifact SHA-256 does not match the declared digest")
	}

	return nil
}

func validateArtifactReference(reference protocol.ArtifactReference) (string, error) {
	if !agentcrypto.ValidUUID(reference.ArtifactID) {
		return "", errors.New("artifact_id must be a canonical UUID")
	}
	if reference.SizeBytes <= 0 || reference.SizeBytes > MaxArtifactBytes {
		return "", fmt.Errorf("artifact size must be between 1 byte and %d bytes", MaxArtifactBytes)
	}
	if !strings.HasPrefix(reference.SHA256, "sha256:") || len(reference.SHA256) != len("sha256:")+sha256.Size*2 {
		return "", errors.New("artifact sha256 must use sha256:<lowercase-hex>")
	}

	digest := strings.TrimPrefix(reference.SHA256, "sha256:")
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != digest {
		return "", errors.New("artifact sha256 must use canonical lowercase hexadecimal")
	}

	return digest, nil
}

func verifyArtifactFile(path string, reference protocol.ArtifactReference) (resultErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != reference.SizeBytes {
		return errors.New("cached artifact has an invalid file type or size")
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash cached artifact: %w", err)
	}

	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actual != reference.SHA256 {
		return errors.New("cached artifact digest does not match its signed reference")
	}

	return nil
}

func extractTarGzip(source, destination string) (resultErr error) {
	if _, err := os.Lstat(destination); err == nil {
		return errExtractionExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect artifact extraction destination: %w", err)
	}

	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create artifact extraction parent: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, ".compose-project-*")
	if err != nil {
		return fmt.Errorf("create temporary artifact extraction directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if removeErr := os.RemoveAll(temporary); removeErr != nil {
				resultErr = errors.Join(resultErr, removeErr)
			}
		}
	}()

	if err := extractTarGzipInto(source, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		if _, inspectErr := os.Lstat(destination); inspectErr == nil {
			return errExtractionExists
		}

		return fmt.Errorf("commit artifact extraction: %w", err)
	}
	committed = true

	return nil
}

func extractTarGzipInto(source, destination string) (resultErr error) {
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open compose artifact: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	compressed, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open compose gzip stream: %w", err)
	}
	defer func() {
		if closeErr := compressed.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	reader := tar.NewReader(compressed)
	seen := make(map[string]struct{})
	var totalBytes int64

	for count := 0; ; count++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read compose archive: %w", err)
		}
		if count >= maxExtractedFiles {
			return fmt.Errorf("compose archive exceeds %d entries", maxExtractedFiles)
		}

		relative, err := safeArchivePath(header.Name)
		if err != nil {
			return err
		}
		if _, duplicate := seen[relative]; duplicate {
			return fmt.Errorf("compose archive contains duplicate path %q", relative)
		}
		seen[relative] = struct{}{}

		target := filepath.Join(destination, relative)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("create compose archive directory: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || totalBytes+header.Size > maxExtractedBytes {
				return fmt.Errorf("compose archive exceeds %d extracted bytes", maxExtractedBytes)
			}
			totalBytes += header.Size

			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("create compose archive parent: %w", err)
			}
			if err := extractRegularFile(reader, target, header.Size, header.FileInfo().Mode()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("compose archive entry %q has unsupported type %d", relative, header.Typeflag)
		}
	}

	return nil
}

func safeArchivePath(value string) (string, error) {
	value = filepath.FromSlash(value)
	clean := filepath.Clean(value)
	if clean == "." || filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" ||
		clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("compose archive contains unsafe path %q", value)
	}

	return clean, nil
}

func extractRegularFile(reader io.Reader, target string, size int64, sourceMode os.FileMode) (resultErr error) {
	mode := os.FileMode(0o600)
	if sourceMode&0o111 != 0 {
		mode = 0o700
	}

	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create compose archive file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	written, err := io.CopyN(file, reader, size)
	if err != nil || written != size {
		return errors.New("compose archive entry ended before its declared size")
	}

	return nil
}

// checkUploadSpace refuses an upload that would grow the cache beyond its
// limit. Already cached artifacts are always accepted.
func (store artifactStore) checkUploadSpace(reference protocol.ArtifactReference) error {
	if store.uploadLimit == 0 {
		return nil
	}

	digest, err := validateArtifactReference(reference)
	if err != nil {
		return err
	}
	if verifyArtifactFile(filepath.Join(store.root, digest), reference) == nil {
		return nil
	}

	entries, err := os.ReadDir(store.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read artifact cache: %w", err)
	}

	used := reference.SizeBytes
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		used += info.Size()
	}
	if used > store.uploadLimit {
		return ErrArtifactCacheFull
	}

	return nil
}
