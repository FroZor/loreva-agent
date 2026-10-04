package workload

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/FroZor/loreva-agent/internal/protocol"
	"github.com/FroZor/loreva-agent/internal/strictjson"
)

const maxWorkloadStateBytes = 2 << 20

type operationMarker struct {
	Version       int    `json:"version"`
	RequestID     string `json:"request_id"`
	CommandDigest string `json:"command_digest"`
}

type persistedResult struct {
	Version       int                              `json:"version"`
	CommandDigest string                           `json:"command_digest"`
	Result        protocol.WorkloadOperationResult `json:"result"`
}

type planStore struct {
	root string
}

func (store planStore) savePlan(plan *storedPlan) error {
	digest, err := digestFilename(plan.PlanDigest)
	if err != nil {
		return err
	}

	return saveImmutableJSON(filepath.Join(store.root, "plans", digest+".json"), plan)
}

func (store planStore) loadPlan(planDigest string) (*storedPlan, error) {
	digest, err := digestFilename(planDigest)
	if err != nil {
		return nil, err
	}

	var plan storedPlan
	if err := loadProtectedJSON(filepath.Join(store.root, "plans", digest+".json"), &plan); err != nil {
		return nil, err
	}
	if plan.Version != protocol.WorkloadSchemaVersion || plan.PlanDigest != planDigest {
		return nil, errors.New("stored workload plan is inconsistent")
	}

	return &plan, nil
}

func (store planStore) startOperation(requestID, commandDigest string) error {
	return saveImmutableJSON(filepath.Join(store.root, "operations", requestID+".started.json"), operationMarker{
		Version: protocol.WorkloadSchemaVersion, RequestID: requestID, CommandDigest: commandDigest,
	})
}

func (store planStore) loadStarted(requestID string) (*operationMarker, error) {
	var marker operationMarker
	if err := loadProtectedJSON(filepath.Join(store.root, "operations", requestID+".started.json"), &marker); err != nil {
		return nil, err
	}

	return &marker, nil
}

func (store planStore) saveResult(commandDigest string, result protocol.WorkloadOperationResult) error {
	return saveImmutableJSON(filepath.Join(store.root, "operations", result.RequestID+".result.json"), persistedResult{
		Version: protocol.WorkloadSchemaVersion, CommandDigest: commandDigest, Result: result,
	})
}

func (store planStore) loadResult(requestID string) (*persistedResult, error) {
	var result persistedResult
	if err := loadProtectedJSON(filepath.Join(store.root, "operations", requestID+".result.json"), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func saveImmutableJSON(path string, value any) (resultErr error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create workload state directory: %w", err)
	}

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode workload state: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxWorkloadStateBytes {
		return errors.New("workload state exceeds 2 MiB")
	}

	if _, err := os.Lstat(path); err == nil {
		return compareImmutableJSON(path, data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect workload state: %w", err)
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".workload-state-*")
	if err != nil {
		return fmt.Errorf("create temporary workload state: %w", err)
	}
	closed := false
	defer func() {
		if removeErr := os.Remove(file.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, removeErr)
		}
		if !closed {
			if closeErr := file.Close(); closeErr != nil {
				resultErr = errors.Join(resultErr, closeErr)
			}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary workload state: %w", err)
	}

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write workload state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync workload state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close workload state: %w", err)
	}
	closed = true

	// Linking publishes the complete file atomically and never replaces an
	// existing immutable journal entry. The temporary file is on the same
	// filesystem, so the operation is valid on Unix and NTFS.
	if err := os.Link(file.Name(), path); errors.Is(err, os.ErrExist) {
		return compareImmutableJSON(path, data)
	} else if err != nil {
		return fmt.Errorf("publish immutable workload state: %w", err)
	}

	return nil
}

func compareImmutableJSON(path string, expected []byte) error {
	var existing any
	if err := loadProtectedJSON(path, &existing); err != nil {
		return err
	}

	var expectedValue any
	if err := strictjson.Decode(expected, &expectedValue); err != nil {
		return fmt.Errorf("decode expected immutable workload state: %w", err)
	}
	if !reflect.DeepEqual(existing, expectedValue) {
		return errors.New("immutable workload state already exists with different content")
	}

	return nil
}

func loadProtectedJSON(path string, target any) (resultErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("workload state must be a regular file")
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

	data, err := io.ReadAll(io.LimitReader(file, maxWorkloadStateBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxWorkloadStateBytes {
		return errors.New("workload state exceeds 2 MiB")
	}

	return strictjson.Decode(data, target)
}

func digestFilename(value string) (string, error) {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return "", errors.New("plan_digest must use sha256:<lowercase-hex>")
	}

	digest := strings.TrimPrefix(value, "sha256:")
	for _, character := range digest {
		if character < '0' || (character > '9' && character < 'a') || character > 'f' {
			return "", errors.New("plan_digest must use canonical lowercase hexadecimal")
		}
	}

	return digest, nil
}
