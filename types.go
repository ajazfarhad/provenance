package provenance

import "github.com/ajazfarhad/provenance/audit"

type EventType = audit.EventType

const (
	EventRequested EventType = audit.EventRequested
	EventApproved  EventType = audit.EventApproved
	EventExecuted  EventType = audit.EventExecuted
	EventVerified  EventType = audit.EventVerified
	EventFailed    EventType = audit.EventFailed
)

type ActorRole = audit.ActorRole

const (
	RoleRequester ActorRole = audit.RoleRequester
	RoleApprover  ActorRole = audit.RoleApprover
	RoleExecutor  ActorRole = audit.RoleExecutor
	RoleVerifier  ActorRole = audit.RoleVerifier
)

type Actor = audit.Actor
type Target = audit.Target
type Command = audit.Command
type Result = audit.Result
type Evidence = audit.Evidence
type Event = audit.Event
type Trail = audit.Trail
type Query = audit.Query
type RequestInput = audit.RequestInput

type VerifyError = audit.VerifyError

func ComputeEventHash(e Event) (string, error) {
	return audit.ComputeEventHash(e)
}
