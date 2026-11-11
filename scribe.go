package scribe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// Dialect selects an explicit script contract. There is no automatic fallback.
type Dialect string

const (
	// Sirius selects the native Sirius contract.
	Sirius Dialect = "sirius"
	// NSE selects the experimental NSE-shaped contract.
	NSE Dialect = "nse"
)

// Target describes a known endpoint. Port zero represents a host-only task.
// IP, when set, is the connection address; Host remains the logical hostname.
type Target struct {
	CPE         []string `json:"cpe,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	CertSubject string   `json:"cert_subject,omitempty"`
	ALPN        string   `json:"alpn,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	Host        string   `json:"host"`
	IP          string   `json:"ip,omitempty"`
	Port        uint16   `json:"port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Product     string   `json:"product,omitempty"`
	Version     string   `json:"version,omitempty"`
	Service     string   `json:"service,omitempty"`
	State       string   `json:"state,omitempty"`
	TLS         bool     `json:"tls,omitempty"`
}

// Validate rejects ambiguous or malformed endpoint metadata.
func (t Target) Validate() error {
	if !(t.Confidence >= 0 && t.Confidence <= 1) {
		return fmt.Errorf("confidence must be between zero and one")
	}
	if strings.TrimSpace(t.Host) == "" || strings.ContainsAny(t.Host, "/?#@\\[]% ") || strings.ContainsFunc(t.Host, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return fmt.Errorf("target host must be a hostname or IP address without a scheme or port")
	}
	if strings.Contains(t.Host, ":") && net.ParseIP(t.Host) == nil {
		return fmt.Errorf("target host must not include a port")
	}
	if t.IP != "" && net.ParseIP(t.IP) == nil {
		return fmt.Errorf("invalid target IP %q", t.IP)
	}
	if t.Protocol != "" && t.Protocol != "tcp" && t.Protocol != "udp" {
		return fmt.Errorf("unsupported target protocol %q", t.Protocol)
	}
	switch t.State {
	case "", "open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered":
	default:
		return fmt.Errorf("unsupported target port state %q", t.State)
	}
	return nil
}

// Script is source supplied by the caller, not an implicit on-disk catalog.
type Script struct {
	ID      string         `json:"id"`
	Dialect Dialect        `json:"dialect"`
	Source  []byte         `json:"-"`
	Args    map[string]any `json:"args,omitempty"`
}

// Limits bounds invocation work; zero values select runtime defaults.
type Limits struct {
	// CPU bounds Lua VM instruction accounting; zero selects the runtime default.
	CPU uint64 `json:"cpu,omitempty"`
	// Memory bounds Lua allocation accounting in bytes, not process RSS.
	Memory uint64 `json:"memory,omitempty"`
	// Timeout bounds invocation duration; positive task limits only tighten runtime ceilings.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// CapabilityDeniedError identifies an attempted operation outside a job grant.
type CapabilityDeniedError struct{ Capability string }

// Error describes the denied capability without changing its typed identity.
func (e *CapabilityDeniedError) Error() string {
	return fmt.Sprintf("capability %q denied", e.Capability)
}

// Task is one script invocation against one known endpoint.
type Task struct {
	planSkip        string
	plannerExcluded bool
	// Nil preserves legacy SDK authority; a non-nil empty list denies all calls.
	Capabilities []string `json:"capabilities,omitempty"`
	Limits       Limits   `json:"limits,omitempty"`
	Script       Script   `json:"script"`
	Target       Target   `json:"target"`
}

// Finding is an affirmative script observation with supporting evidence.
// A runtime error or lack of output must never be converted into a finding.
type Finding struct {
	ID         string         `json:"id"`
	Title      string         `json:"title"`
	Severity   string         `json:"severity"`
	Evidence   string         `json:"evidence,omitempty"`
	References []string       `json:"references,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Verdict is an explicit vulnerability assessment; missing verdicts remain unknown.
type Verdict string

const (
	// Unknown indicates no explicit vulnerability conclusion.
	Unknown Verdict = "unknown"
	// Vulnerable is an explicit positive vulnerability verdict.
	Vulnerable Verdict = "vulnerable"
	// NotVulnerable is an explicit negative verdict subject to identification gates.
	NotVulnerable Verdict = "not_vulnerable"
)

// Output preserves script data, findings, logs and skip evidence independently of execution status.
type Output struct {
	Logs          string    `json:"logs,omitempty"`
	LogsTruncated bool      `json:"logs_truncated,omitempty"`
	Verdict       Verdict   `json:"-"`
	Data          any       `json:"data,omitempty"`
	Findings      []Finding `json:"findings,omitempty"`
	// Skipped indicates execution was excluded or a rule did not match.
	Skipped    bool   `json:"-"`
	SkipReason string `json:"skip_reason,omitempty"`
}

// Runtime implements a dialect. Execute must support concurrent invocations,
// own its interpreter state, and enforce its own execution and I/O limits.
type Runtime interface {
	Dialect() Dialect
	Execute(context.Context, Task) (Output, error)
}

// Function is a compiled-in Go capability exposed by the Sirius runtime.
// Implementations must honor ctx and bound their allocations and output.
// Registering a function grants trusted Go code the embedding process's authority.
type Function func(ctx context.Context, target Target, args []any) (any, error)

// Status describes execution completion independently of the vulnerability verdict.
type Status string

const (
	// Cancelled indicates cancelled execution.
	Cancelled Status = "cancelled"
	// Completed indicates execution completed; it does not imply a verdict.
	Completed Status = "completed"
	// Skipped indicates execution was excluded or a rule did not match.
	Skipped Status = "skipped"
	// Failed indicates execution failed.
	Failed Status = "error"
)

// Result reports execution status independently of vulnerability status.
type Result struct {
	PlannerMiss   bool    `json:"planner_miss,omitempty"`
	SchemaVersion int     `json:"schema_version"`
	ScriptID      string  `json:"script_id"`
	ScriptSHA256  string  `json:"script_sha256"`
	Dialect       Dialect `json:"dialect"`
	Target        Target  `json:"target"`
	Status        Status  `json:"status"`
	Verdict       Verdict `json:"verdict"`
	Output        Output  `json:"output"`
	Error         string  `json:"error,omitempty"`
	ElapsedMS     int64   `json:"elapsed_ms"`
}
