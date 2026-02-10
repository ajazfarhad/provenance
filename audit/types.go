package audit

import "time"

type EventType string

const (
	EventRequested EventType = "REQUESTED"
	EventApproved  EventType = "APPROVED"
	EventExecuted  EventType = "EXECUTED"
	EventVerified  EventType = "VERIFIED"
	EventFailed    EventType = "FAILED"
)

type ActorRole string

const (
	RoleRequester ActorRole = "REQUESTER"
	RoleApprover  ActorRole = "APPROVER"
	RoleExecutor  ActorRole = "EXECUTOR"
	RoleVerifier  ActorRole = "VERIFIER"
)

type Actor struct {
	ID   string            // user id / service id
	Name string            // display name (optional)
	Role ActorRole         // requester/approver/executor/verifier
	Meta map[string]string // ip, team, auth method, etc.
}

type Target struct {
	Type   string            // e.g. "network_device", "server", "k8s_cluster"
	ID     string            // your stable identifier
	Labels map[string]string // hostname, site, vendor, etc.
}

type Command struct {
	Kind       string // e.g. "cli", "netconf", "rest"
	Raw        string // exact command or payload (store securely!)
	Diff       string // config diff if applicable
	Output     string // sanitized output
	OutputMeta map[string]string
}

type Result struct {
	Status   string // "SUCCESS" / "FAILED" / "PARTIAL"
	Message  string
	ExitCode *int
}

type Evidence struct {
	Kind   string            // "show_cmd", "snapshot_hash", "ticket_link"
	Ref    string            // evidence reference / link / command used
	Detail map[string]string // structured evidence, hashes, etc.
}

type Event struct {
	ID            string
	TrailID       string
	Type          EventType
	At            time.Time
	Actor         Actor
	Targets       []Target
	Commands      []Command
	Result        *Result
	Evidence      []Evidence
	CorrelationID string

	// immutability / tamper-evidence
	PrevHash string
	Hash     string
}

// Trail groups multiple events for one logical change (one "write request").
type Trail struct {
	ID            string
	CreatedAt     time.Time
	Title         string
	Description   string
	CorrelationID string
	Targets       []Target
}
