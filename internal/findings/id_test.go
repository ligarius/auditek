package findings

import (
	"strings"
	"testing"
)

func TestNewScanIDFormat(t *testing.T) {
	id := NewScanID()
	if !strings.HasPrefix(id, "scan-") {
		t.Fatalf("expected id to start with 'scan-', got %q", id)
	}
	hexPart := strings.TrimPrefix(id, "scan-")
	if len(hexPart) != 8 {
		t.Fatalf("expected 8 hex chars (4 bytes), got %d in %q", len(hexPart), id)
	}
}

func TestNewScanIDUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := NewScanID()
		if seen[id] {
			t.Fatalf("duplicate scan id generated: %q", id)
		}
		seen[id] = true
	}
}
