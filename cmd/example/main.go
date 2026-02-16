package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ajazfarhad/provenance"
	"github.com/ajazfarhad/provenance/store/memory"
)

func main() {
	ctx := context.Background()

	st := memory.New()
	svc := provenance.New(st, provenance.WithSanitizer(redactingSanitizer{}))

	reqActor := provenance.Actor{ID: "u-1", Name: "Ahmed", Role: provenance.RoleRequester}
	target := provenance.Target{
		Type: "network_device",
		ID:   "sw-12",
		Labels: map[string]string{
			"vendor": "cisco",
			"site":   "dc1",
			"host":   "sw-12",
		},
	}

	trailID, err := svc.Request(ctx, provenance.RequestInput{
		Title:         "Update NTP servers",
		Description:   "Set NTP servers on sw-12",
		CorrelationID: "req-abc-123",
		Requester:     reqActor,
		Targets:       []provenance.Target{target},
	})

	must(err)
	fmt.Println("Requested change...")
	fmt.Println("Trail ID:", trailID)
	fmt.Printf("Targets: %s:%s labels=%v\n", target.Type, target.ID, target.Labels)

	fmt.Printf("Approving change for Trail ID: %s\n", trailID)
	must(svc.Approve(ctx, trailID, provenance.Actor{ID: "u-2", Name: "Max"}, "req-abc-123", "Approved in change window"))
	fmt.Println("Approved ✅")

	must(svc.Execute(ctx, trailID, provenance.Actor{ID: "svc-spectre", Name: "Spectre"},
		"req-abc-123",
		[]provenance.Command{{Kind: "cli", Raw: "ntp server 10.0.0.10", Diff: "+ ntp server 10.0.0.10", Output: "OK"}},
		provenance.Result{Status: "SUCCESS", Message: "Applied"},
	))
	printSanitizedOutput(ctx, st, trailID)

	must(svc.Verify(ctx, trailID, provenance.Actor{ID: "u-3", Name: "Verifier"},
		"req-abc-123",
		[]provenance.Evidence{{Kind: "show_cmd", Ref: "show run | i ntp", Detail: map[string]string{"matched": "true"}}},
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

func printSanitizedOutput(ctx context.Context, st *memory.Store, trailID string) {
	_, events, err := st.GetTrail(ctx, trailID)
	must(err)

	for _, ev := range events {
		if len(ev.Commands) == 0 {
			continue
		}
		fmt.Println("Sanitized command:", ev.Commands[0].Raw)
		return
	}
	fmt.Println("Sanitized command: <none>")
}

type redactingSanitizer struct{}

func (redactingSanitizer) SanitizeTargets(targets []provenance.Target) []provenance.Target {
	return targets
}

func (redactingSanitizer) SanitizeCommands(cmds []provenance.Command) []provenance.Command {
	for i := range cmds {
		cmds[i].Raw = "[redacted]"
	}
	return cmds
}
