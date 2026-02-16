<div align="center">
  <img src="docs/assets/banner.png"
       alt="Provenance banner"
       width="800" />
</div>

<br/>

<h1 align="center">Provenance</h1>

<p align="center">
Audit trails for infrastructure changes with tamper-evident hashing.
</p>

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/ajazfarhad/provenance">
  <img src="https://img.shields.io/github/license/ajazfarhad/provenance">
  <img src="https://img.shields.io/github/actions/workflow/status/ajazfarhad/provenance/ci.yml">
</p>

#### API (facade)

Import the top-level package and use the built-in store adapters.

```go
import (
  "github.com/ajazfarhad/provenance"
  "github.com/ajazfarhad/provenance/store/memory"
)

st := memory.New()
svc := provenance.New(st)

trailID, _ := svc.Request(ctx, provenance.RequestInput{
  Title: "Update NTP servers",
  Requester: provenance.Actor{ID: "u-1"},
})

_ = svc.Approve(ctx, trailID, provenance.Actor{ID: "u-2"}, "corr-1", "Approved")
```

Verify and query

```go
_ = svc.VerifyTrail(ctx, trailID)

events, _ := svc.WhatChanged(ctx, provenance.Target{Type: "network_device", ID: "sw-12"},
  time.Now().Add(-24*time.Hour).UTC(),
  time.Now().UTC(),
  50,
)
```

#### Sanitizers

```go
type RedactingSanitizer struct{}

func (RedactingSanitizer) SanitizeTargets(ts []provenance.Target) []provenance.Target {
  return ts
}
func (RedactingSanitizer) SanitizeCommands(cmds []provenance.Command) []provenance.Command {
  for i := range cmds {
    cmds[i].Raw = "[redacted]"
  }
  return cmds
}

svc := provenance.New(st, provenance.WithSanitizer(RedactingSanitizer{}))
```

#### Stores

- `store/memory.New()` for tests or in-memory usage
- `store/sqlite.New(*sql.DB)` for SQLite
- `store/postgres.New(*sql.DB)` for Postgres

#### Example output (from `cmd/example`)

```
Requested change...
Trail ID: 9f3a8f7a6b7e9b8c2a1d3f4a5b6c7d8e
Targets: network_device:sw-12 labels=map[host:sw-12 site:dc1 vendor:cisco]
Approving change for Trail ID: 9f3a8f7a6b7e9b8c2a1d3f4a5b6c7d8e
Approved ✅
Sanitized command: [redacted]
Trail verification OK ✅
Trail: 9f3a8f7a6b7e9b8c2a1d3f4a5b6c7d8e
Events:
- 2026-02-16T09:28:03Z REQUESTED actor=u-1 prev= hash=675ac49e
```
