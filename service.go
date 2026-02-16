package provenance

import (
	"time"

	"github.com/ajazfarhad/provenance/audit"
)

type Client = audit.Service

type Option func(*config)

type config struct {
	now       func() time.Time
	sanitizer Sanitizer
}

func WithClock(now func() time.Time) Option {
	return func(c *config) { c.now = now }
}

func WithSanitizer(s Sanitizer) Option {
	return func(c *config) {
		if s != nil {
			c.sanitizer = s
		}
	}
}

func New(store Store, opts ...Option) *Client {
	cfg := config{
		now:       time.Now().UTC,
		sanitizer: NoopSanitizer{},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	var auditOpts []audit.Option
	if cfg.now != nil {
		auditOpts = append(auditOpts, audit.WithClock(cfg.now))
	}

	return audit.NewService(store, cfg.sanitizer, auditOpts...)
}
