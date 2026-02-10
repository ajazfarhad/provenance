package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/ajazfarhad/provenance/audit"
	"github.com/ajazfarhad/provenance/store/memory"
)

func TestVerifyTrailPassesForValidChain(t *testing.T) {
	ctx := context.Background()

	fixedNow := time.Date(2026, 2, 3, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedNow }

	st := memory.New()
	svc := audit.NewService(st, audit.NoopSanitizer{}, audit.WithClock(clock))

	trailID, err := svc.Request(ctx, audit.RequestInput{
		Title:         "Change VLAN",
		CorrelationID: "corr-1",
		Requester:     audit.Actor{ID: "u-1", Role: audit.RoleRequester},
		Targets:       []audit.Target{{Type: "network_device", ID: "sw-12"}},
	})
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}

	// Move time forward a bit for later events
	fixedNow = fixedNow.Add(1 * time.Second)
	if err := svc.Approve(ctx, trailID, audit.Actor{ID: "u-2", Name: "Approver"}, "corr-1", "ok"); err != nil {
		t.Fatalf("Approve error: %v", err)
	}

	fixedNow = fixedNow.Add(1 * time.Second)
	if err := svc.Execute(ctx, trailID, audit.Actor{ID: "svc-1", Name: "Executor"}, "corr-1",
		[]audit.Command{{Kind: "cli", Raw: "conf t", Diff: "+ vlan 10", Output: "OK"}},
		audit.Result{Status: "SUCCESS", Message: "Applied"},
	); err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	fixedNow = fixedNow.Add(1 * time.Second)
	if err := svc.Verify(ctx, trailID, audit.Actor{ID: "u-3", Name: "Verifier"}, "corr-1",
		[]audit.Evidence{{Kind: "show_cmd", Ref: "show run | i vlan", Detail: map[string]string{"matched": "true"}}},
	); err != nil {
		t.Fatalf("Verify error: %v", err)
	}

	// Assert chain is valid
	if err := svc.VerifyTrail(ctx, trailID); err != nil {
		t.Fatalf("VerifyTrail should pass, got error: %v", err)
	}

	// Extra: assert prev-hash chaining
	_, events, err := st.GetTrail(ctx, trailID)
	if err != nil {
		t.Fatalf("GetTrail error: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i].PrevHash != events[i-1].Hash {
			t.Fatalf("prevhash mismatch at index %d", i)
		}
	}
}

func TestVerifyTrailDetectsTampering(t *testing.T) {
	ctx := context.Background()

	st := memory.New()
	svc := audit.NewService(st, audit.NoopSanitizer{})

	trailID, err := svc.Request(ctx, audit.RequestInput{
		Title:     "Tamper test",
		Requester: audit.Actor{ID: "u-1", Role: audit.RoleRequester},
		Targets:   []audit.Target{{Type: "network_device", ID: "sw-12"}},
	})
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}

	// Create at least 2 events so chain exists
	if err := svc.Execute(ctx, trailID, audit.Actor{ID: "svc-1", Role: audit.RoleExecutor}, "corr",
		[]audit.Command{{Kind: "cli", Raw: "do thing", Output: "OK"}},
		audit.Result{Status: "SUCCESS"},
	); err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Tamper by wrapping the store: when VerifyTrail calls GetTrail, we mutate one event.
	tamper := &tamperingStore{Store: st}

	svc2 := audit.NewService(tamper, audit.NoopSanitizer{})

	err = svc2.VerifyTrail(ctx, trailID)
	if err == nil {
		t.Fatalf("expected verification to fail after tampering")
	}
}

// tamperingStore mutates the returned event list to simulate "someone edited the log"
type tamperingStore struct{ audit.Store }

func (t *tamperingStore) GetTrail(ctx context.Context, trailID string) (audit.Trail, []audit.Event, error) {
	tr, evs, err := t.Store.GetTrail(ctx, trailID)
	if err != nil {
		return audit.Trail{}, nil, err
	}
	if len(evs) > 0 {
		evs[0].CorrelationID = evs[0].CorrelationID + "-tampered"
	}
	return tr, evs, nil
}
