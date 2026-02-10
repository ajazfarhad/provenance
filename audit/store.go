package audit

import (
	"context"
	"time"
)

// Query lets you ask questions like:
// "what changed on device X last Tuesday?"
type Query struct {
	TargetType string
	TargetID   string
	From       time.Time
	To         time.Time
	EventTypes []EventType
	Limit      int
}

// Store is the plug-in point.
// Memory store now; Postgres store later; Spectre won’t need to change code.
type Store interface {
	CreateTrail(ctx context.Context, t Trail) error
	AppendEvent(ctx context.Context, e Event) error
	GetTrail(ctx context.Context, trailID string) (Trail, []Event, error)
	QueryEvents(ctx context.Context, q Query) ([]Event, error)
	LatestEvent(ctx context.Context, trailID string) (*Event, error)
}
