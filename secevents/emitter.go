package secevents

import (
	"errors"
	"strings"
	"time"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// Sink delivers a stamped security event to its destination (the SIEM via the
// log pipeline, or the broker). Implementations must treat ev as read-only and be
// safe for concurrent use.
type Sink interface {
	Emit(ctx *azugo.Context, ev *broker.Envelope) error
}

// Emitter emits NIS2-audit security events through a Sink. Construct one per
// service; it is safe for concurrent use.
type Emitter struct {
	sink Sink
}

// NewEmitter returns an Emitter that delivers events through sink (e.g.
// NewLogSink or NewBrokerSink).
func NewEmitter(sink Sink) *Emitter {
	return &Emitter{sink: sink}
}

// Emit is the escape hatch for events not covered by a typed helper. It tags the
// envelope as a security event when no category is set, strips free-text/PII and
// token attribute keys, stamps the event (id, high-precision occurrence time,
// correlation) and validates before handing it to the sink.
func (e *Emitter) Emit(ctx *azugo.Context, ev *broker.Envelope) error {
	if e == nil || e.sink == nil {
		return errors.New("secevents: emitter has no sink")
	}

	if ev == nil {
		return errors.New("secevents: nil envelope")
	}

	if len(ev.Categories) == 0 {
		ev.Categories = []broker.Category{broker.CategorySecurity}
	}

	ev.Attributes = sanitize(ev.Attributes)

	broker.Stamp(ctx, ev)

	if err := ev.Validate(); err != nil {
		return err
	}

	return e.sink.Emit(ctx, ev)
}

// security builds a security envelope skeleton with the severity recorded as an
// attribute (the Sink maps it to a log level / SIEM field).
func security(eventType string, sev Severity, op broker.Operation, outcome broker.Outcome) *broker.Envelope {
	return &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Operation:  op,
		Outcome:    outcome,
		Attributes: map[string]any{AttrSeverity: string(severityOr(sev))},
	}
}

// Auth is a login / step-up / re-auth event.
type Auth struct {
	Actor   broker.Actor
	Method  string
	StepUp  bool
	Outcome broker.Outcome
}

// Authentication records a login / step-up / re-auth. A non-success outcome is
// raised to warning severity.
func (e *Emitter) Authentication(ctx *azugo.Context, a Auth) error {
	sev := SeverityInfo
	if outcomeOr(a.Outcome) != broker.OutcomeSuccess {
		sev = SeverityWarning
	}

	ev := security(EventAuthentication, sev, "", outcomeOr(a.Outcome))
	ev.Actor = actor(a.Actor)
	ev.Attributes[AttrMethod] = a.Method

	if a.StepUp {
		ev.Attributes[AttrKind] = "step_up"
	}

	return e.Emit(ctx, ev)
}

// Denial is an authorization denial / IDOR attempt.
type Denial struct {
	Actor         broker.Actor
	Resource      broker.Resource
	RequiredScope string
	Reason        string
	IDOR          bool // direct-object-reference probe — raised to high severity
}

// AuthZDenied records a scope/authZ denial or IDOR attempt (outcome denied).
func (e *Emitter) AuthZDenied(ctx *azugo.Context, d Denial) error {
	sev := SeverityWarning
	if d.IDOR {
		sev = SeverityHigh
	}

	ev := security(EventAuthZDenied, sev, "", broker.OutcomeDenied)
	ev.Actor = actor(d.Actor)
	ev.Resource = resourceOrNil(d.Resource)
	ev.Attributes[AttrRequiredScope] = d.RequiredScope
	ev.Attributes[AttrReason] = d.Reason

	if d.IDOR {
		ev.Attributes[AttrIDOR] = true
	}

	return e.Emit(ctx, ev)
}

// TokenFailure is a service-to-service token / DPoP failure.
type TokenFailure struct {
	Actor  broker.Actor
	Kind   string // TokenKind* — issuance | validation | replay | proof
	Reason string
}

// ServiceTokenFailure records a DPoP service-token issuance/validation, replay or
// proof failure. Replay and proof failures are attack signals (high severity).
func (e *Emitter) ServiceTokenFailure(ctx *azugo.Context, f TokenFailure) error {
	sev := SeverityWarning
	if f.Kind == TokenKindReplay || f.Kind == TokenKindProof {
		sev = SeverityHigh
	}

	ev := security(EventServiceToken, sev, "", broker.OutcomeFailure)
	ev.Actor = actor(f.Actor)
	ev.Attributes[AttrKind] = f.Kind
	ev.Attributes[AttrReason] = f.Reason

	return e.Emit(ctx, ev)
}

// Edge is an edge/WAF block or rate-limit trigger.
type Edge struct {
	IP     string
	Rule   string
	Reason string
}

// EdgeBlock records an edge/WAF block, rate-limit trigger or anomalous traffic
// (outcome denied).
func (e *Emitter) EdgeBlock(ctx *azugo.Context, edge Edge) error {
	ev := security(EventEdgeBlock, SeverityWarning, "", broker.OutcomeDenied)
	ev.IP = edge.IP
	ev.Attributes[AttrRule] = edge.Rule
	ev.Attributes[AttrReason] = edge.Reason

	return e.Emit(ctx, ev)
}

// Egress is an egress-policy / NetworkPolicy violation.
type Egress struct {
	Actor  broker.Actor
	Target string
	Policy string
	Reason string
}

// EgressViolation records traffic leaving the allow-list — always an alarm (high
// severity, outcome denied).
func (e *Emitter) EgressViolation(ctx *azugo.Context, eg Egress) error {
	ev := security(EventEgressViolation, SeverityHigh, "", broker.OutcomeDenied)
	ev.Actor = actor(eg.Actor)
	ev.Attributes[AttrTarget] = eg.Target
	ev.Attributes[AttrPolicy] = eg.Policy
	ev.Attributes[AttrReason] = eg.Reason

	return e.Emit(ctx, ev)
}

// SigningEgress is an outbound call to the signing tier (the QTSP-facing
// signing services).
type SigningEgress struct {
	Actor     broker.Actor
	Target    string
	APIKeyRef string // a reference to the key used, never the key itself
	Outcome   broker.Outcome
}

// SigningEgressCall records a call to the signing tier. A non-success outcome is
// raised to warning severity.
func (e *Emitter) SigningEgressCall(ctx *azugo.Context, s SigningEgress) error {
	sev := SeverityInfo
	if outcomeOr(s.Outcome) != broker.OutcomeSuccess {
		sev = SeverityWarning
	}

	ev := security(EventSigningEgress, sev, "", outcomeOr(s.Outcome))
	ev.Actor = actor(s.Actor)
	ev.Attributes[AttrTarget] = s.Target
	ev.Attributes[AttrAPIKeyRef] = s.APIKeyRef

	return e.Emit(ctx, ev)
}

// Secret is a secret/key access, use, rotation or failed fetch.
type Secret struct {
	Actor   broker.Actor
	KeyRef  string
	Action  string // e.g. "access" | "use" | "rotate" | "fetch"
	Outcome broker.Outcome
}

// SecretAccess records Vault access, KMS key use, rotation or a failed secret
// fetch. A failure is raised to high severity.
func (e *Emitter) SecretAccess(ctx *azugo.Context, s Secret) error {
	sev := SeverityInfo
	if outcomeOr(s.Outcome) != broker.OutcomeSuccess {
		sev = SeverityHigh
	}

	ev := security(EventSecretAccess, sev, "", outcomeOr(s.Outcome))
	ev.Actor = actor(s.Actor)
	ev.Attributes[AttrKeyRef] = s.KeyRef
	ev.Attributes[AttrAction] = s.Action

	return e.Emit(ctx, ev)
}

// DataAnomaly is a denied direct-table attempt or procedure-execution anomaly.
type DataAnomaly struct {
	Role   string
	Detail string
}

// DataTierAnomaly records a data-tier anomaly — a signal of credential misuse
// (high severity, outcome denied).
func (e *Emitter) DataTierAnomaly(ctx *azugo.Context, d DataAnomaly) error {
	ev := security(EventDataTierAnomaly, SeverityHigh, "", broker.OutcomeDenied)
	ev.Attributes[AttrRole] = d.Role
	ev.Attributes[AttrDetail] = d.Detail

	return e.Emit(ctx, ev)
}

// Config is a deploy / IaC / privilege / admin change.
type Config struct {
	Actor  broker.Actor
	Change string
}

// ConfigChange records an image deploy, IaC change, privilege change or admin
// action.
func (e *Emitter) ConfigChange(ctx *azugo.Context, c Config) error {
	ev := security(EventConfigChange, SeverityWarning, broker.OpUpdate, broker.OutcomeSuccess)
	ev.Actor = actor(c.Actor)
	ev.Attributes[AttrChange] = c.Change

	return e.Emit(ctx, ev)
}

// Privileged is an operator / break-glass access.
type Privileged struct {
	Actor        broker.Actor
	DataSubjects []string
	Resource     broker.Resource
	Reason       string
}

// PrivilegedAccess records operator / break-glass access — elevated and always
// high severity. The same action is a GDPR access; emit the GDPR-audit record too.
func (e *Emitter) PrivilegedAccess(ctx *azugo.Context, p Privileged) error {
	ev := security(EventPrivilegedAccess, SeverityHigh, broker.OpRead, broker.OutcomeSuccess)
	ev.Actor = actor(p.Actor)
	ev.DataSubjects = p.DataSubjects
	ev.Resource = resourceOrNil(p.Resource)
	ev.Attributes[AttrReason] = p.Reason

	return e.Emit(ctx, ev)
}

// Detection is a "first-awareness" incident detection.
type Detection struct {
	Actor       broker.Actor
	Severity    Severity // defaults to high
	Summary     string
	IncidentRef string
	// DetectedAt is the precise instant awareness began; zero means "now". This
	// is the NIS2 24-hour clock anchor and is returned to the caller.
	DetectedAt time.Time
}

// FirstAwareness records the "first awareness" of a possible significant incident
// and returns the high-precision occurrence time so the caller can anchor the
// NIS2 24-hour clock and the incident register. Severity defaults to high.
func (e *Emitter) FirstAwareness(ctx *azugo.Context, d Detection) (time.Time, error) {
	sev := d.Severity
	if sev == "" {
		sev = SeverityHigh
	}

	ev := security(EventFirstAwareness, sev, "", broker.OutcomeFailure)
	ev.Actor = actor(d.Actor)
	ev.Attributes[AttrSummary] = d.Summary
	ev.Attributes[AttrIncidentRef] = d.IncidentRef

	if !d.DetectedAt.IsZero() {
		ev.OccurredAt = d.DetectedAt.UTC()
	}

	err := e.Emit(ctx, ev)

	return ev.OccurredAt, err
}

// actor returns a pointer to a copy of a when it carries any identity, else nil.
func actor(a broker.Actor) *broker.Actor {
	if a.ID == "" && a.Type == "" && a.Assurance == "" {
		return nil
	}

	return &a
}

// resourceOrNil returns a pointer to r when it carries anything, else nil.
func resourceOrNil(r broker.Resource) *broker.Resource {
	if r.Type == "" && r.ID == "" {
		return nil
	}

	return &r
}

func outcomeOr(o broker.Outcome) broker.Outcome {
	if o == "" {
		return broker.OutcomeSuccess
	}

	return o
}

func severityOr(s Severity) Severity {
	if s == "" {
		return SeverityInfo
	}

	return s
}

// severityOf reads the severity attribute back off an envelope (used by sinks),
// defaulting to info.
func severityOf(ev *broker.Envelope) Severity {
	if ev == nil {
		return SeverityInfo
	}

	if s, ok := ev.Attributes[AttrSeverity].(string); ok && s != "" {
		return Severity(s)
	}

	return SeverityInfo
}

// MaxAttrValueLen is the maximum length (in runes) of a string attribute value;
// longer values are truncated by sanitize. Reason/Detail/Summary/Change are
// bounded operational metadata (a ticket-style reference), never narratives —
// unbounded free text would bloat the SIEM and is an injection channel.
const MaxAttrValueLen = 256

// forbiddenAttrKeys are attribute-key fragments that would put PII or document
// content into the security stream. Security events are metadata only.
var forbiddenAttrKeys = []string{
	"document_bytes", "content_bytes", "file_bytes", "free_text",
	"note", "comment", "body", "payload", "email", "phone",
}

// sanitize drops free-text/content/PII attribute keys defensively and truncates
// string values to MaxAttrValueLen runes. It never mutates the input map — a
// sanitized copy is returned when anything must change, so caller-owned maps
// stay intact. The publisher additionally strips bearer-token-shaped keys
// (broker.Stamp).
func sanitize(attrs map[string]any) map[string]any {
	if len(attrs) == 0 {
		return attrs
	}

	var out map[string]any // allocated only when something changes

	cow := func() {
		if out == nil {
			out = make(map[string]any, len(attrs))
			for ck, cv := range attrs {
				out[ck] = cv
			}
		}
	}

	for k, v := range attrs {
		lk := strings.ToLower(k)
		for _, f := range forbiddenAttrKeys {
			if strings.Contains(lk, f) {
				cow()
				delete(out, k)

				break
			}
		}

		if s, ok := v.(string); ok {
			if r := []rune(s); len(r) > MaxAttrValueLen {
				cow()
				if _, kept := out[k]; kept {
					out[k] = string(r[:MaxAttrValueLen])
				}
			}
		}
	}

	if out == nil {
		return attrs
	}

	return out
}
