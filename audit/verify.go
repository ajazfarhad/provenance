package audit

import (
	"context"
	"fmt"
)

// VerifyError tells you exactly what failed and where.
type VerifyError struct {
	TrailID string
	EventID string
	Index   int
	Reason  string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("audit verification failed: trail=%s event=%s index=%d reason=%s",
		e.TrailID, e.EventID, e.Index, e.Reason,
	)
}

// VerifyTrail checks the hash chain for a trail.
// It detects:
// - edits to any event fields (hash mismatch)
// - deleted/re-ordered events (PrevHash mismatch)
// - inserted events in the middle (PrevHash mismatch)
func (s *Service) VerifyTrail(ctx context.Context, trailID string) error {
	_, events, err := s.store.GetTrail(ctx, trailID)
	if err != nil {
		return err
	}

	var prevHash string

	for i, ev := range events {
		// 1) Check the chain pointer
		if i == 0 {
			// first event must not point to anything
			if ev.PrevHash != "" {
				return &VerifyError{
					TrailID: trailID,
					EventID: ev.ID,
					Index:   i,
					Reason:  "first event PrevHash must be empty",
				}
			}
		} else {
			if ev.PrevHash != prevHash {
				return &VerifyError{
					TrailID: trailID,
					EventID: ev.ID,
					Index:   i,
					Reason:  fmt.Sprintf("PrevHash mismatch (expected %s, got %s)", short(prevHash), short(ev.PrevHash)),
				}
			}
		}

		// 2) Recompute the hash
		// IMPORTANT: ComputeEventHash does NOT use the Event.Hash field,
		// so we can compute directly from ev.
		expectedHash, err := ComputeEventHash(ev)
		if err != nil {
			return err
		}

		// 3) Compare stored hash to computed hash
		if ev.Hash != expectedHash {
			return &VerifyError{
				TrailID: trailID,
				EventID: ev.ID,
				Index:   i,
				Reason:  fmt.Sprintf("Hash mismatch (expected %s, got %s)", short(expectedHash), short(ev.Hash)),
			}
		}

		prevHash = ev.Hash
	}

	return nil
}

// short is just for readable errors/logs.
func short(s string) string {
	if len(s) <= 10 {
		return s
	}
	return s[:10]
}
