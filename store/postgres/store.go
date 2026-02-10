package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ajazfarhad/provenance/audit"
	"github.com/lib/pq"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) CreateTrail(ctx context.Context, t audit.Trail) error {
	if t.ID == "" {
		return errors.New("trail id is required")
	}

	targetsJSON, err := json.Marshal(t.Targets)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_trails (id, created_at, title, description, correlation_id, targets)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, t.ID, t.CreatedAt, t.Title, t.Description, t.CorrelationID, targetsJSON)
	return err
}

func (s *Store) AppendEvent(ctx context.Context, e audit.Event) error {
	if e.ID == "" {
		return errors.New("event id is required")
	}

	actorJSON, err := json.Marshal(e.Actor)
	if err != nil {
		return err
	}
	targetsJSON, err := json.Marshal(e.Targets)
	if err != nil {
		return err
	}
	commandsJSON, err := json.Marshal(e.Commands)
	if err != nil {
		return err
	}
	resultJSON, err := json.Marshal(e.Result)
	if err != nil {
		return err
	}
	evidenceJSON, err := json.Marshal(e.Evidence)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			trail_id, type, at, actor, targets, commands, result, evidence,
			correlation_id, prev_hash, hash, id
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, e.TrailID, e.Type, e.At, actorJSON, targetsJSON, commandsJSON, resultJSON, evidenceJSON,
		e.CorrelationID, e.PrevHash, e.Hash, e.ID)
	return err
}

func (s *Store) LatestEvent(ctx context.Context, trailID string) (*audit.Event, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, trail_id, type, at, actor, targets, commands, result, evidence,
		       correlation_id, prev_hash, hash
		FROM audit_events
		WHERE trail_id = $1
		ORDER BY seq DESC
		LIMIT 1
	`, trailID)

	ev, err := scanEvent(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ev, nil
}

func (s *Store) GetTrail(ctx context.Context, trailID string) (audit.Trail, []audit.Event, error) {
	var t audit.Trail
	var targetsJSON []byte

	row := s.db.QueryRowContext(ctx, `
		SELECT id, created_at, title, description, correlation_id, targets
		FROM audit_trails
		WHERE id = $1
	`, trailID)

	err := row.Scan(&t.ID, &t.CreatedAt, &t.Title, &t.Description, &t.CorrelationID, &targetsJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return audit.Trail{}, nil, errors.New("trail not found")
		}
		return audit.Trail{}, nil, err
	}

	if len(targetsJSON) > 0 {
		if err := json.Unmarshal(targetsJSON, &t.Targets); err != nil {
			return audit.Trail{}, nil, err
		}
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, trail_id, type, at, actor, targets, commands, result, evidence,
		       correlation_id, prev_hash, hash
		FROM audit_events
		WHERE trail_id = $1
		ORDER BY seq ASC
	`, trailID)
	if err != nil {
		return audit.Trail{}, nil, err
	}
	defer rows.Close()

	var events []audit.Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return audit.Trail{}, nil, err
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return audit.Trail{}, nil, err
	}

	return t, events, nil
}

func (s *Store) QueryEvents(ctx context.Context, q audit.Query) ([]audit.Event, error) {
	var args []any
	var b strings.Builder

	b.WriteString(`
		SELECT id, trail_id, type, at, actor, targets, commands, result, evidence,
		       correlation_id, prev_hash, hash
		FROM audit_events
		WHERE 1=1
	`)

	if !q.From.IsZero() {
		args = append(args, q.From)
		fmt.Fprintf(&b, " AND at >= $%d", len(args))
	}
	if !q.To.IsZero() {
		args = append(args, q.To)
		fmt.Fprintf(&b, " AND at < $%d", len(args))
	}
	if len(q.EventTypes) > 0 {
		args = append(args, pq.Array(q.EventTypes))
		fmt.Fprintf(&b, " AND type = ANY($%d)", len(args))
	}
	if q.TargetType != "" && q.TargetID != "" {
		filter := []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}{{Type: q.TargetType, ID: q.TargetID}}
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			return nil, err
		}
		args = append(args, filterJSON)
		fmt.Fprintf(&b, " AND targets @> $%d::jsonb", len(args))
	}

	b.WriteString(" ORDER BY seq DESC")
	if q.Limit > 0 {
		args = append(args, q.Limit)
		fmt.Fprintf(&b, " LIMIT $%d", len(args))
	}

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []audit.Event
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(r rowScanner) (audit.Event, error) {
	var ev audit.Event
	var actorJSON, targetsJSON, commandsJSON, resultJSON, evidenceJSON []byte

	err := r.Scan(
		&ev.ID,
		&ev.TrailID,
		&ev.Type,
		&ev.At,
		&actorJSON,
		&targetsJSON,
		&commandsJSON,
		&resultJSON,
		&evidenceJSON,
		&ev.CorrelationID,
		&ev.PrevHash,
		&ev.Hash,
	)
	if err != nil {
		return audit.Event{}, err
	}

	if len(actorJSON) > 0 {
		if err := json.Unmarshal(actorJSON, &ev.Actor); err != nil {
			return audit.Event{}, err
		}
	}
	if len(targetsJSON) > 0 {
		if err := json.Unmarshal(targetsJSON, &ev.Targets); err != nil {
			return audit.Event{}, err
		}
	}
	if len(commandsJSON) > 0 {
		if err := json.Unmarshal(commandsJSON, &ev.Commands); err != nil {
			return audit.Event{}, err
		}
	}
	if len(resultJSON) > 0 {
		if err := json.Unmarshal(resultJSON, &ev.Result); err != nil {
			return audit.Event{}, err
		}
	}
	if len(evidenceJSON) > 0 {
		if err := json.Unmarshal(evidenceJSON, &ev.Evidence); err != nil {
			return audit.Event{}, err
		}
	}

	return ev, nil
}
