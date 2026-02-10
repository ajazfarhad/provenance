package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ajazfarhad/provenance/audit"
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
		VALUES (?, ?, ?, ?, ?, ?)
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.TrailID, e.Type, e.At, actorJSON, targetsJSON, commandsJSON, resultJSON, evidenceJSON,
		e.CorrelationID, e.PrevHash, e.Hash, e.ID)
	return err
}

func (s *Store) LatestEvent(ctx context.Context, trailID string) (*audit.Event, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, trail_id, type, at, actor, targets, commands, result, evidence,
		       correlation_id, prev_hash, hash
		FROM audit_events
		WHERE trail_id = ?
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
		WHERE id = ?
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
		WHERE trail_id = ?
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
		b.WriteString(" AND at >= ?")
	}
	if !q.To.IsZero() {
		args = append(args, q.To)
		b.WriteString(" AND at < ?")
	}
	if len(q.EventTypes) > 0 {
		b.WriteString(" AND type IN (")
		for i, t := range q.EventTypes {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString("?")
			args = append(args, t)
		}
		b.WriteString(")")
	}

	b.WriteString(" ORDER BY seq DESC")

	applyLimitInSQL := q.Limit > 0 && (q.TargetType == "" || q.TargetID == "")
	if applyLimitInSQL {
		b.WriteString(" LIMIT ?")
		args = append(args, q.Limit)
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
		if q.TargetType != "" && q.TargetID != "" {
			if !eventHasTarget(ev, q.TargetType, q.TargetID) {
				continue
			}
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
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

func eventHasTarget(e audit.Event, typ, id string) bool {
	for _, tgt := range e.Targets {
		if tgt.Type == typ && tgt.ID == id {
			return true
		}
	}
	return false
}
