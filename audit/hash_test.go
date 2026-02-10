package audit_test

import (
	"testing"
	"time"

	"github.com/ajazfarhad/provenance/audit"
)

func TestComputeEventHashIsStableWithMapCanonicalization(t *testing.T) {
	at := time.Date(2026, 2, 3, 12, 0, 0, 0, time.UTC)

	meta1 := map[string]string{}
	meta1["b"] = "2"
	meta1["a"] = "1"

	meta2 := map[string]string{}
	meta2["a"] = "1"
	meta2["b"] = "2"

	e1 := audit.Event{
		ID:            "e-1",
		TrailID:       "t-1",
		Type:          audit.EventExecuted,
		At:            at,
		Actor:         audit.Actor{ID: "u-1", Role: audit.RoleExecutor, Meta: meta1},
		PrevHash:      "prev",
		Commands:      []audit.Command{{Kind: "cli", Raw: "x"}},
		CorrelationID: "corr",
	}

	e2 := e1
	e2.Actor.Meta = meta2

	h1, err := audit.ComputeEventHash(e1)
	if err != nil {
		t.Fatalf("ComputeEventHash error: %v", err)
	}
	h2, err := audit.ComputeEventHash(e2)
	if err != nil {
		t.Fatalf("ComputeEventHash error: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("expected stable hash; got h1=%s h2=%s", h1, h2)
	}
}
