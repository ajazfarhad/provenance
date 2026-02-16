package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/ajazfarhad/provenance/audit"
	"github.com/ajazfarhad/provenance/store/memory"
)

func TestRequestCreatesTrailAndRequestedEvent(t *testing.T) {
	ctx := context.Background()

	// Arrange: deterministic time so test is stable
	fixedNow := time.Date(2026, 2, 3, 12, 0, 0, 0, time.UTC)

	st := memory.New()
	// svc := NewService(st, NoopSanitizer{}, WithClock(func() time.Time { return fixedNow }))
	svc := audit.NewService(st, audit.NoopSanitizer{}, audit.WithClock(func() time.Time { return fixedNow }))

	// Act
	trailID, err := svc.Request(ctx, audit.RequestInput{
		Title:         "Update NTP",
		Description:   "Set NTP servers",
		CorrelationID: "req-123",
		Requester:     audit.Actor{ID: "u-1", Name: "Zack", Role: audit.RoleRequester},
		Targets:       []audit.Target{{Type: "network_device", ID: "sw-12"}},
	})
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}

	// Assert
	trail, events, err := st.GetTrail(ctx, trailID)
	if err != nil {
		t.Fatalf("GetTrail error: %v", err)
	}

	if trail.ID != trailID {
		t.Fatalf("expected trail ID %s, got %s", trailID, trail.ID)
	}
	if trail.Title != "Update NTP" {
		t.Fatalf("expected title %q, got %q", "Update NTP", trail.Title)
	}
	if trail.CorrelationID != "req-123" {
		t.Fatalf("expected correlation id %q, got %q", "req-123", trail.CorrelationID)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Type != audit.EventRequested {
		t.Fatalf("expected first event type %s, got %s", audit.EventRequested, ev.Type)
	}
	if ev.PrevHash != "" {
		t.Fatalf("expected first event PrevHash empty, got %q", ev.PrevHash)
	}
	if ev.Hash == "" {
		t.Fatalf("expected event hash to be set")
	}

	// Hash should match recomputation
	expectedHash, err := audit.ComputeEventHash(ev)
	if err != nil {
		t.Fatalf("ComputeEventHash error: %v", err)
	}
	if ev.Hash != expectedHash {
		t.Fatalf("hash mismatch: expected %s got %s", expectedHash, ev.Hash)
	}
}
