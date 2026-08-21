package specifications

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FroZor/loreva-agent/internal/protocol"
)

func TestCollectReturnsCoreSpecifications(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	snapshot, err := Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ObservationScope != protocol.ObservationScopeHost &&
		snapshot.ObservationScope != protocol.ObservationScopeRuntime {
		t.Fatalf("observation scope = %q", snapshot.ObservationScope)
	}
	if snapshot.Specifications.System.OS.Type != runtime.GOOS {
		t.Fatalf("OS type = %q, want %q", snapshot.Specifications.System.OS.Type, runtime.GOOS)
	}
	if snapshot.Specifications.CPU.LogicalProcessorCount <= 0 {
		t.Fatal("logical processor count was not collected")
	}
	if snapshot.Specifications.Memory.TotalBytes == 0 {
		t.Fatal("memory total was not collected")
	}
}

func TestFitSpecificationsToBudgetTruncatesLogicalProcessors(t *testing.T) {
	processors := make([]protocol.LogicalProcessorSpecifications, 10000)
	for index := range processors {
		processors[index] = protocol.LogicalProcessorSpecifications{
			ID:        strings.Repeat("c", 64),
			PackageID: "package:0",
			CoreID:    "core:0",
			Online:    true,
		}
	}

	specifications := protocol.NodeSpecifications{
		CPU: protocol.CPUSpecifications{LogicalProcessors: processors},
	}
	if err := fitSpecificationsToBudget(&specifications); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(specifications)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxSpecificationsJSON {
		t.Fatalf("specifications snapshot is %d bytes", len(data))
	}
	if len(specifications.CPU.LogicalProcessors) >= len(processors) {
		t.Fatal("large logical-processor set was not truncated")
	}
}

func TestSanitizePreservesUTF8(t *testing.T) {
	if value := sanitize("éé", 3); value != "é" {
		t.Fatalf("sanitized value = %q", value)
	}
}

func TestIssueClassifiesTimeout(t *testing.T) {
	if collectionIssue := issue("storage_devices", context.DeadlineExceeded); collectionIssue.Code != issueTimeout {
		t.Fatalf("issue code = %q", collectionIssue.Code)
	}
}
