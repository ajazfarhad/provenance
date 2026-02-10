package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// KV is a stable, sortable representation of map entries.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

func mapToSortedKVs(m map[string]string) []KV {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]KV, 0, len(keys))
	for _, k := range keys {
		out = append(out, KV{K: k, V: m[k]})
	}
	return out
}

// Canonical forms (maps become sorted slices)
type canonicalActor struct {
	ID   string    `json:"id"`
	Name string    `json:"name,omitempty"`
	Role ActorRole `json:"role"`
	Meta []KV      `json:"meta,omitempty"`
}

type canonicalTarget struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Labels []KV   `json:"labels,omitempty"`
}

type canonicalEvidence struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Detail []KV   `json:"detail,omitempty"`
}

// hashPayload is exactly what we hash.
// It is fully deterministic: no maps, only primitives and ordered slices.
type hashPayload struct {
	ID            string    `json:"id"`
	TrailID       string    `json:"trail_id"`
	Type          EventType `json:"type"`
	AtUnixNano    int64     `json:"at_unix_nano"`
	Actor         canonicalActor
	CorrelationID string `json:"correlation_id,omitempty"`
	PrevHash      string `json:"prev_hash,omitempty"`

	Targets  []canonicalTarget   `json:"targets,omitempty"`
	Commands []Command           `json:"commands,omitempty"`
	Result   *Result             `json:"result,omitempty"`
	Evidence []canonicalEvidence `json:"evidence,omitempty"`
}

func toCanonicalActor(a Actor) canonicalActor {
	return canonicalActor{
		ID:   a.ID,
		Name: a.Name,
		Role: a.Role,
		Meta: mapToSortedKVs(a.Meta),
	}
}

func toCanonicalTargets(ts []Target) []canonicalTarget {
	if len(ts) == 0 {
		return nil
	}
	out := make([]canonicalTarget, 0, len(ts))
	for _, t := range ts {
		out = append(out, canonicalTarget{
			Type:   t.Type,
			ID:     t.ID,
			Labels: mapToSortedKVs(t.Labels),
		})
	}
	return out
}

func toCanonicalEvidence(es []Evidence) []canonicalEvidence {
	if len(es) == 0 {
		return nil
	}
	out := make([]canonicalEvidence, 0, len(es))
	for _, e := range es {
		out = append(out, canonicalEvidence{
			Kind:   e.Kind,
			Ref:    e.Ref,
			Detail: mapToSortedKVs(e.Detail),
		})
	}
	return out
}

func ComputeEventHash(e Event) (string, error) {
	p := hashPayload{
		ID:            e.ID,
		TrailID:       e.TrailID,
		Type:          e.Type,
		AtUnixNano:    e.At.UnixNano(),
		Actor:         toCanonicalActor(e.Actor),
		CorrelationID: e.CorrelationID,
		PrevHash:      e.PrevHash,
		Targets:       toCanonicalTargets(e.Targets),
		Commands:      e.Commands,
		Result:        e.Result,
		Evidence:      toCanonicalEvidence(e.Evidence),
	}

	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
