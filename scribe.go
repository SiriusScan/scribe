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
	// CPE contains identity hints; nil means none, never a verdict.
	CPE []string `json:"cpe,omitempty"`
	// Confidence is identity confidence in [0,1]; zero is unspecified confidence.
	Confidence float64 `json:"confidence,omitempty"`
	// CertSubject is an observed certificate subject; empty is unknown, not trust validation.
	CertSubject string `json:"cert_subject,omitempty"`
	// ALPN is the observed negotiated protocol; empty is unknown.
	ALPN string `json:"alpn,omitempty"`
	// TLSVersion is the observed TLS version string; empty is unknown.
	TLSVersion string `json:"tls_version,omitempty"`
	// Banner is observed endpoint text; empty means unavailable.
	Banner string `json:"banner,omitempty"`
	// Host is the required logical hostname or IP without scheme or port; zero Target is invalid.
	Host string `json:"host"`
	// IP overrides the connection address when nonempty; empty uses Host.
	IP string `json:"ip,omitempty"`
	// Port is the endpoint port number; zero denotes host-only work.
	Port uint16 `json:"port,omitempty"`
	// Protocol is tcp or udp; empty is unspecified and capability calls may reject it.
	Protocol string `json:"protocol,omitempty"`
	// Product is supplied product identity; empty is unknown.
	Product string `json:"product,omitempty"`
	// Version is supplied product version text; empty is unknown.
	Version string `json:"version,omitempty"`
	// Service is supplied service identity; empty is unknown.
	Service string `json:"service,omitempty"`
	// State is supplied port state; empty is unspecified, not confirmed open.
	State string `json:"state,omitempty"`
	// TLS requests TLS for endpoint capabilities; false uses plaintext.
	TLS bool `json:"tls,omitempty"`
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
	// ID identifies caller-owned source; empty is rejected by the engine.
	ID string `json:"id"`
	// Dialect selects sirius or nse explicitly; empty is invalid.
	Dialect Dialect `json:"dialect"`
	// Source contains Lua source bytes, bounded by MaxSourceBytes; empty is invalid.
	Source []byte `json:"-"`
	// Args contains invocation arguments; nil supplies no arguments.
	Args map[string]any `json:"args,omitempty"`
}

// Limits bounds invocation work; zero values select runtime defaults.
// In runtime/lua54 these are 10,000,000 CPU accounting units, 32 MiB
// allocated memory and five seconds. Task limits only tighten those ceilings.
// Negative Timeout is rejected; zero inherits the configured ceiling.
type Limits struct {
	// CPU bounds Lua VM instruction accounting; zero selects the runtime default.
	CPU uint64 `json:"cpu,omitempty"`
	// Memory bounds Lua allocation accounting in bytes, not process RSS.
	Memory uint64 `json:"memory,omitempty"`
	// Timeout is a nanosecond time.Duration (including JSON encoding) and bounds invocation duration; positive task limits only tighten runtime ceilings.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// CapabilityDeniedError identifies an attempted operation outside a job grant.
type CapabilityDeniedError struct {
	// Capability is the exact denied registered function name; empty denotes no name.
	Capability string
}

// Error describes the denied capability without changing its typed identity.
func (e *CapabilityDeniedError) Error() string {
	return fmt.Sprintf("capability %q denied", e.Capability)
}

// Task is one script invocation against one known endpoint.
type Task struct {
	preparedHints   *selectionHints
	planSkip        string
	plannerExcluded bool
	// Nil preserves legacy SDK authority; a non-nil empty list denies all calls.
	Capabilities []string `json:"capabilities,omitempty"`
	// Limits tightens runtime ceilings; zero inherits configured limits.
	Limits Limits `json:"limits,omitempty"`
	// Script is the invocation source and arguments; zero is invalid.
	Script Script `json:"script"`
	// Target is caller-supplied endpoint identity; zero is invalid.
	Target Target `json:"target"`
}

// Finding is an affirmative script observation with supporting evidence.
// A runtime error or lack of output must never be converted into a finding.
type Finding struct {
	// ID is the script-provided finding identifier; empty supplies none.
	ID string `json:"id"`
	// Title is script-provided descriptive text; empty supplies none.
	Title string `json:"title"`
	// Severity is script-provided severity text; empty is unspecified.
	Severity string `json:"severity"`
	// Evidence is supporting text; empty supplies none.
	Evidence string `json:"evidence,omitempty"`
	// References contains supporting reference strings; nil supplies none.
	References []string `json:"references,omitempty"`
	// Metadata contains script-provided structured evidence; nil supplies none.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Verdict is an explicit vulnerability assessment; missing verdicts remain unknown.
// The zero value is empty, distinct from Unknown, and establishes no assessment.
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
	// Logs contains bounded script log text; empty means no captured text.
	Logs string `json:"logs,omitempty"`
	// LogsTruncated reports discarded log bytes; false means no reported truncation.
	LogsTruncated bool `json:"logs_truncated,omitempty"`
	// Verdict is an explicit assessment; empty establishes no verdict and is omitted from output JSON.
	Verdict Verdict `json:"-"`
	// Data is bounded converted script output; nil means absent.
	Data any `json:"data,omitempty"`
	// Findings contains affirmative observations; nil contains no findings.
	Findings []Finding `json:"findings,omitempty"`
	// Skipped indicates execution was excluded or a rule did not match; false is not a verdict.
	Skipped bool `json:"-"`
	// SkipReason explains a skip; empty supplies no explanation.
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
// The empty zero value is uninitialized, never completed.
type Status string

const (
	// Cancelled indicates cancelled execution.
	Cancelled Status = "cancelled"
	// Completed indicates execution completed; it does not imply a verdict.
	Completed Status = "completed"
	// Skipped indicates execution was excluded or a rule did not match; false is not a verdict.
	Skipped Status = "skipped"
	// Failed indicates execution failed.
	Failed Status = "error"
)

// Result reports execution status independently of vulnerability status.
type Result struct {
	// PlannerMiss reports a completed explicit verdict from an exhaustively run, planner-excluded task. False means no such evidence; it is not a verdict.
	PlannerMiss bool `json:"planner_miss,omitempty"`
	// SchemaVersion identifies the execution record schema. Engine records use 1; zero is an uninitialized record, not a supported schema.
	SchemaVersion int `json:"schema_version"`
	// ScriptID copies the caller-supplied script identifier. Empty means no identifier was supplied.
	ScriptID string `json:"script_id"`
	// ScriptSHA256 is the lowercase hexadecimal SHA-256 digest of the executed source bytes. Empty means no digest was recorded.
	ScriptSHA256 string `json:"script_sha256"`
	// Dialect records the explicitly selected script contract. Empty is unspecified and never selects a fallback.
	Dialect Dialect `json:"dialect"`
	// Target preserves endpoint facts associated with this execution. Its zero value has no valid host.
	Target Target `json:"target"`
	// Status records execution completion independently of Verdict. Empty is uninitialized and cannot establish successful execution.
	Status Status `json:"status"`
	// Verdict records the conservative assessment. Empty or unknown is inconclusive; only completed explicit verdicts establish a conclusion.
	Verdict Verdict `json:"verdict"`
	// Output preserves script data, findings, logs and skip evidence. Its zero value contains no evidence.
	Output Output `json:"output"`
	// Error describes an execution failure. Empty means no error text was recorded and does not establish a clean verdict.
	Error string `json:"error,omitempty"`
	// ElapsedMS is elapsed execution time in whole milliseconds. Zero includes unmeasured terminal queue records and executions shorter than one millisecond.
	ElapsedMS int64 `json:"elapsed_ms"`
}
