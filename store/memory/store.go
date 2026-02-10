package memory

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/ajazfarhad/provenance/audit"
)

type Store struct {
	mu     sync.RWMutex
	trails map[string]audit.Trail
	events map[string][]audit.Event // trailID => ordered events
}

func New() *Store {
	return &Store{
		trails: make(map[string]audit.Trail),
		events: make(map[string][]audit.Event),
	}
}

func (s *Store) CreateTrail(ctx context.Context, t audit.Trail) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.trails[t.ID]; exists {
		return errors.New("trail already exists")
	}
	s.trails[t.ID] = t
	s.events[t.ID] = []audit.Event{}
	return nil
}

func (s *Store) AppendEvent(ctx context.Context, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.trails[e.TrailID]; !ok {
		return errors.New("trail not found")
	}

	// enforce append-only ordering by time + type? We keep it simple:
	s.events[e.TrailID] = append(s.events[e.TrailID], e)
	return nil
}

func (s *Store) LatestEvent(ctx context.Context, trailID string) (*audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	evs, ok := s.events[trailID]
	if !ok {
		return nil, errors.New("trail not found")
	}
	if len(evs) == 0 {
		return nil, nil
	}
	last := evs[len(evs)-1]
	return &last, nil
}

func (s *Store) GetTrail(ctx context.Context, trailID string) (audit.Trail, []audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.trails[trailID]
	if !ok {
		return audit.Trail{}, nil, errors.New("trail not found")
	}
	evs := append([]audit.Event(nil), s.events[trailID]...)
	return t, evs, nil
}

func (s *Store) QueryEvents(ctx context.Context, q audit.Query) ([]audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []audit.Event

	for trailID, evs := range s.events {
		_ = trailID
		for _, e := range evs {
			if !inRange(e.At, q.From, q.To) {
				continue
			}
			if len(q.EventTypes) > 0 && !containsType(q.EventTypes, e.Type) {
				continue
			}
			if q.TargetType != "" && q.TargetID != "" {
				if !eventHasTarget(e, q.TargetType, q.TargetID) {
					continue
				}
			}
			out = append(out, e)
		}
	}

	// stable ordering: newest first
	sort.Slice(out, func(i, j int) bool {
		return out[i].At.After(out[j].At)
	})

	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func inRange(t, from, to time.Time) bool {
	if !from.IsZero() && t.Before(from) {
		return false
	}
	if !to.IsZero() && !t.Before(to) {
		return false
	}
	return true
}

func containsType(types []audit.EventType, t audit.EventType) bool {
	for _, x := range types {
		if x == t {
			return true
		}
	}
	return false
}

func eventHasTarget(e audit.Event, typ, id string) bool {
	for _, tgt := range e.Targets {
		if tgt.Type == typ && tgt.ID == id {
			return true
		}
	}
	return false
}
