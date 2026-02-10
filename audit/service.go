package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

type Service struct {
	store     Store
	sanitizer Sanitizer
	now       func() time.Time
}

type Option func(*Service)

func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

func NewService(store Store, sanitizer Sanitizer, opts ...Option) *Service {
	if sanitizer == nil {
		sanitizer = NoopSanitizer{}
	}
	s := &Service{
		store:     store,
		sanitizer: sanitizer,
		now:       time.Now().UTC,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type RequestInput struct {
	Title         string
	Description   string
	CorrelationID string
	Requester     Actor
	Targets       []Target
}

func (s *Service) Request(ctx context.Context, in RequestInput) (string, error) {
	if in.Title == "" {
		return "", errors.New("title is required")
	}
	if in.Requester.ID == " " {
		return "", errors.New("requester actor id is required")
	}
	if in.Requester.Role == "" {
		in.Requester.Role = RoleRequester
	}

	trailID := newID()
	now := s.now()

	targets := s.sanitizer.SanitizeTargets(in.Targets)

	t := Trail{
		ID:            trailID,
		CreatedAt:     now,
		Title:         in.Title,
		Description:   in.Description,
		CorrelationID: in.CorrelationID,
		Targets:       targets,
	}

	if err := s.store.CreateTrail(ctx, t); err != nil {
		return "", err
	}

	// Add first event: REQUESTED
	e := Event{
		ID:            newID(),
		TrailID:       trailID,
		Type:          EventRequested,
		At:            now,
		Actor:         in.Requester,
		Targets:       targets,
		Commands:      nil,
		Result:        nil,
		Evidence:      nil,
		CorrelationID: in.CorrelationID,
		PrevHash:      "", // first event
	}

	h, err := ComputeEventHash(e)
	if err != nil {
		return "", err
	}
	e.Hash = h

	if err := s.store.AppendEvent(ctx, e); err != nil {
		return "", err
	}

	return trailID, nil
}

func (s *Service) Approve(ctx context.Context, trailID string, approver Actor, correlationID string, note string) error {
	approver.Role = RoleApprover
	return s.appendSimpleEvent(ctx, trailID, EventApproved, approver, correlationID, note)
}

func (s *Service) Execute(ctx context.Context, trailID string, executor Actor, correlationID string, cmds []Command, res Result) error {
	executor.Role = RoleExecutor

	cmds = s.sanitizer.SanitizeCommands(cmds)

	prev, err := s.store.LatestEvent(ctx, trailID)
	if err != nil {
		return err
	}

	e := Event{
		ID:            newID(),
		TrailID:       trailID,
		Type:          EventExecuted,
		At:            s.now(),
		Actor:         executor,
		Targets:       nil, // optional: can pull from trail if you want
		Commands:      cmds,
		Result:        &res,
		CorrelationID: correlationID,
	}
	if prev != nil {
		e.PrevHash = prev.Hash
	}

	h, err := ComputeEventHash(e)
	if err != nil {
		return err
	}
	e.Hash = h

	return s.store.AppendEvent(ctx, e)
}

func (s *Service) Verify(ctx context.Context, trailID string, verifier Actor, correlationID string, evidence []Evidence) error {
	verifier.Role = RoleVerifier

	prev, err := s.store.LatestEvent(ctx, trailID)
	if err != nil {
		return err
	}

	e := Event{
		ID:            newID(),
		TrailID:       trailID,
		Type:          EventVerified,
		At:            s.now(),
		Actor:         verifier,
		Evidence:      evidence,
		CorrelationID: correlationID,
	}
	if prev != nil {
		e.PrevHash = prev.Hash
	}

	h, err := ComputeEventHash(e)
	if err != nil {
		return err
	}
	e.Hash = h

	return s.store.AppendEvent(ctx, e)
}

func (s *Service) WhatChanged(ctx context.Context, target Target, from, to time.Time, limit int) ([]Event, error) {
	q := Query{
		TargetType: target.Type,
		TargetID:   target.ID,
		From:       from,
		To:         to,
		Limit:      limit,
	}
	return s.store.QueryEvents(ctx, q)
}

func (s *Service) appendSimpleEvent(ctx context.Context, trailID string, typ EventType, actor Actor, correlationID string, note string) error {
	prev, err := s.store.LatestEvent(ctx, trailID)
	if err != nil {
		return err
	}

	// Put "note" in evidence for now (keeps schema generic)
	ev := []Evidence(nil)
	if note != "" {
		ev = []Evidence{{Kind: "note", Ref: note}}
	}

	e := Event{
		ID:            newID(),
		TrailID:       trailID,
		Type:          typ,
		At:            s.now(),
		Actor:         actor,
		Evidence:      ev,
		CorrelationID: correlationID,
	}
	if prev != nil {
		e.PrevHash = prev.Hash
	}

	h, err := ComputeEventHash(e)
	if err != nil {
		return err
	}
	e.Hash = h

	return s.store.AppendEvent(ctx, e)
}

func newID() string {
	// 16 random bytes => 32 hex chars
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
