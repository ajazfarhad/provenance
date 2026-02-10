package audit

// Sanitizer allows the host app to redact secrets.
// Default is no-op.
type Sanitizer interface {
	SanitizeTargets(targets []Target) []Target
	SanitizeCommands(cmds []Command) []Command
}

type NoopSanitizer struct{}

func (NoopSanitizer) SanitizeTargets(targets []Target) []Target { return targets }
func (NoopSanitizer) SanitizeCommands(cmds []Command) []Command { return cmds }
