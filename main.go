package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/ajazfarhad/provenance/audit"
	"github.com/ajazfarhad/provenance/store/postgres"
)

func main() {
	ctx := context.Background()

	dsn := os.Getenv("PROVENANCE_PG_DSN")
	if dsn == "" {
		panic("PROVENANCE_PG_DSN is required")
	}

	db, err := sql.Open("postgres", dsn)
	must(err)

	st := postgres.New(db)
	svc := audit.NewService(st, audit.NoopSanitizer{})

	reqActor := audit.Actor{ID: "u-1", Name: "Ahmed", Role: audit.RoleRequester}
	target := audit.Target{
		Type: "network_device",
		ID:   "sw-12",
		Labels: map[string]string{
			"vendor": "cisco",
			"site":   "dc1",
			"host":   "sw-12",
		},
	}

	trailID, err := svc.Request(ctx, audit.RequestInput{
		Title:         "Update NTP servers",
		Description:   "Set NTP servers on sw-12",
		CorrelationID: "req-abc-123",
		Requester:     reqActor,
		Targets:       []audit.Target{target},
	})

	must(err)

	must(svc.Approve(ctx, trailID, audit.Actor{ID: "u-2", Name: "Max"}, "req-abc-123", "Approved in change window"))

	must(svc.Execute(ctx, trailID, audit.Actor{ID: "svc-spectre", Name: "Spectre"},
		"req-abc-123",
		[]audit.Command{{Kind: "cli", Raw: "ntp server 10.0.0.10", Diff: "+ ntp server 10.0.0.10", Output: "OK"}},
		audit.Result{Status: "SUCCESS", Message: "Applied"},
	))

	must(svc.Verify(ctx, trailID, audit.Actor{ID: "u-3", Name: "Verifier"},
		"req-abc-123",
		[]audit.Evidence{{Kind: "show_cmd", Ref: "show run | i ntp", Detail: map[string]string{"matched": "true"}}},
	))

	if err := svc.VerifyTrail(ctx, trailID); err != nil {
		panic(err)
	}
	fmt.Println("Trail verification OK ✅")

	// Query: "what changed on sw-12 in last 24 hours"
	events, err := svc.WhatChanged(ctx, target, time.Now().Add(-24*time.Hour).UTC(), time.Now().UTC(), 50)
	must(err)

	fmt.Println("Trail:", trailID)
	fmt.Println("Events:")
	for _, e := range events {
		fmt.Printf("- %s %s actor=%s prev=%s hash=%s\n", e.At.Format(time.RFC3339), e.Type, e.Actor.ID, short(e.PrevHash), short(e.Hash))
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}
