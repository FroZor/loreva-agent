package containerfiles

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

const (
	// imageRepository holds the helper images; the tag is a digest prefix
	// of the agent binary they were built from.
	imageRepository = "loreva-agent-files"
	// helperBinary is where the agent binary lives in the helper image.
	helperBinary = "/loreva-agent"
	// executablePath is the running agent binary. It stays readable even
	// after an upgrade replaced the file on disk, so the helper always
	// speaks the protocol of the running agent.
	executablePath = "/proc/self/exe"
)

// ensureImage returns the helper image for the running agent binary,
// importing it into Docker the first time. The image holds nothing but the
// agent's own static binary, so building it needs no registry or network.
func (m *Manager) ensureImage(ctx context.Context) (string, error) {
	m.imageMu.Lock()
	defer m.imageMu.Unlock()

	if m.image != "" {
		return m.image, nil
	}

	digest, size, err := fileDigest(m.executable)
	if err != nil {
		return "", fmt.Errorf("read the agent binary: %w", err)
	}
	reference := imageRepository + ":" + digest[:16]

	_, err = m.engine.ImageInspect(ctx, reference)
	switch {
	case err == nil:
	case errdefs.IsNotFound(err):
		if err := m.importImage(ctx, reference, size); err != nil {
			return "", err
		}
		m.removeOldImages(ctx, reference)
	default:
		return "", fmt.Errorf("inspect the file helper image: %w", err)
	}

	m.image = reference

	return reference, nil
}

func (m *Manager) forgetImage() {
	m.imageMu.Lock()
	m.image = ""
	m.imageMu.Unlock()
}

func (m *Manager) importImage(ctx context.Context, reference string, size int64) error {
	binary, err := os.Open(m.executable)
	if err != nil {
		return fmt.Errorf("open the agent binary: %w", err)
	}
	defer binary.Close()

	reader, writer := io.Pipe()
	go func() {
		writer.CloseWithError(writeImageLayer(writer, binary, size))
	}()
	defer reader.Close()

	result, err := m.engine.ImageImport(ctx, client.ImageImportSource{Source: reader, SourceName: "-"}, reference, client.ImageImportOptions{
		Message: "loreva-agent file helper",
	})
	if err != nil {
		return fmt.Errorf("import the file helper image: %w", err)
	}
	defer result.Close()

	if err := importError(result); err != nil {
		return fmt.Errorf("import the file helper image: %w", err)
	}
	m.logger.Info("file helper image imported", "image", reference)

	return nil
}

// writeImageLayer writes a tar layer holding only the agent binary.
func writeImageLayer(writer io.Writer, binary io.Reader, size int64) error {
	archive := tar.NewWriter(writer)
	header := &tar.Header{
		Name:     strings.TrimPrefix(helperBinary, "/"),
		Mode:     0o755,
		Size:     size,
		Typeflag: tar.TypeReg,
	}
	if err := archive.WriteHeader(header); err != nil {
		return err
	}
	if _, err := io.CopyN(archive, binary, size); err != nil {
		return err
	}

	return archive.Close()
}

// importError reads the JSON progress stream of an import and returns the
// error it reports, if any.
func importError(stream io.Reader) error {
	decoder := json.NewDecoder(stream)
	for {
		var message struct {
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		err := decoder.Decode(&message)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if message.ErrorDetail.Message != "" {
			return errors.New(message.ErrorDetail.Message)
		}
		if message.Error != "" {
			return errors.New(message.Error)
		}
	}
}

// removeOldImages drops helper images of earlier agent versions. It is
// best effort: an image still in use stays.
func (m *Manager) removeOldImages(ctx context.Context, current string) {
	filters := make(client.Filters).Add("reference", imageRepository)
	images, err := m.engine.ImageList(ctx, client.ImageListOptions{Filters: filters})
	if err != nil {
		return
	}

	for _, image := range images.Items {
		for _, tag := range image.RepoTags {
			if tag == current || !strings.HasPrefix(tag, imageRepository+":") {
				continue
			}
			if _, err := m.engine.ImageRemove(ctx, tag, client.ImageRemoveOptions{}); err == nil {
				m.logger.Info("old file helper image removed", "image", tag)
			}
		}
	}
}

func fileDigest(name string) (string, int64, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
