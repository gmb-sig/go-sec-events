package secevents

// Event types for Regime C security events (Audit Design §5, §7).
const (
	// EventAuthentication — user login / step-up / re-auth.
	EventAuthentication = "auth.login"
	// EventAuthZDenied — scope/authZ denial or IDOR attempt.
	EventAuthZDenied = "authz.denied"
	// EventServiceToken — service-to-service DPoP token issuance/validation,
	// replay or proof failure.
	EventServiceToken = "auth.service_token"
	// EventEdgeBlock — edge/WAF block, rate-limit trigger, anomalous traffic.
	EventEdgeBlock = "edge.block"
	// EventEgressViolation — egress-policy / NetworkPolicy violation (anything
	// leaving the allow-list is an alarm).
	EventEgressViolation = "egress.violation"
	// EventSigningEgress — a call to simpleSign / LVRTC, incl. ApiKey use.
	EventSigningEgress = "egress.signing"
	// EventSecretAccess — Vault access, KMS key use, rotation, failed fetch.
	EventSecretAccess = "secret.access"
	// EventDataTierAnomaly — denied direct-table attempt or procedure-execution
	// anomaly (a signal of credential misuse).
	EventDataTierAnomaly = "data.anomaly"
	// EventConfigChange — image deploy, IaC change, privilege change, admin action.
	EventConfigChange = "config.change"
	// EventPrivilegedAccess — operator / break-glass access (also a GDPR access).
	EventPrivilegedAccess = "access.privileged"
	// EventFirstAwareness — detection of a possible significant incident; the
	// NIS2 24-hour clock anchor.
	EventFirstAwareness = "incident.first_awareness"
)

// Attribute keys, so every producer writes the same shape into the SIEM.
const (
	AttrSeverity      = "severity"
	AttrMethod        = "method"
	AttrReason        = "reason"
	AttrRequiredScope = "required_scope"
	AttrIDOR          = "idor"
	AttrKind          = "kind"
	AttrIP            = "ip"
	AttrRule          = "rule"
	AttrTarget        = "target"
	AttrPolicy        = "policy"
	AttrKeyRef        = "key_ref"
	AttrAction        = "action"
	AttrRole          = "role"
	AttrDetail        = "detail"
	AttrChange        = "change"
	AttrSummary       = "summary"
	AttrIncidentRef   = "incident_ref"
	AttrAPIKeyRef     = "api_key_ref"
)

// Severity classifies a security event for SIEM triage and log-level mapping.
type Severity string

// Severity levels.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ServiceToken failure kinds for EventServiceToken.
const (
	TokenKindIssuance   = "issuance"
	TokenKindValidation = "validation"
	TokenKindReplay     = "replay"
	TokenKindProof      = "proof"
)
