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
	ID   string            `json:"id"`             // user id / service id
	Name string            `json:"name,omitempty"` // display name (optional)
	Role ActorRole         `json:"role"`           // requester/approver/executor/verifier
	Meta map[string]string `json:"meta,omitempty"` // ip, team, auth method, etc.
}

type Target struct {
	Type   string            `json:"type"`             // e.g. "network_device", "server", "k8s_cluster"
	ID     string            `json:"id"`               // your stable identifier
	Labels map[string]string `json:"labels,omitempty"` // hostname, site, vendor, etc.
}

type Command struct {
	Kind       string            `json:"kind"`                    // e.g. "cli", "netconf", "rest"
	Raw        string            `json:"raw"`                     // exact command or payload (store securely!)
	Diff       string            `json:"diff,omitempty"`          // config diff if applicable
	Output     string            `json:"output,omitempty"`        // sanitized output
	OutputMeta map[string]string `json:"output_meta,omitempty"`   // output metadata
}

type Result struct {
	Status   string `json:"status"`              // "SUCCESS" / "FAILED" / "PARTIAL"
	Message  string `json:"message,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

type Evidence struct {
	Kind   string            `json:"kind"`             // "show_cmd", "snapshot_hash", "ticket_link"
	Ref    string            `json:"ref"`              // evidence reference / link / command used
	Detail map[string]string `json:"detail,omitempty"` // structured evidence, hashes, etc.
}

type Event struct {
	ID            string     `json:"id"`
	TrailID       string     `json:"trail_id"`
	Type          EventType  `json:"type"`
	At            time.Time  `json:"at"`
	Actor         Actor      `json:"actor"`
	Targets       []Target   `json:"targets,omitempty"`
	Commands      []Command  `json:"commands,omitempty"`
	Result        *Result    `json:"result,omitempty"`
	Evidence      []Evidence `json:"evidence,omitempty"`
	CorrelationID string     `json:"correlation_id,omitempty"`

	// immutability / tamper-evidence
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// Trail groups multiple events for one logical change (one "write request").
type Trail struct {
	ID            string    `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Title         string    `json:"title"`
	Description   string    `json:"description,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Targets       []Target  `json:"targets,omitempty"`
}
