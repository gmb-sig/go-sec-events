// Package secevents is the NIS2-audit (NIS2 security-operations) event emitter for
// the eSignature Portal. It gives every service one standard way to emit
// structured security events — auth failures, authZ/IDOR denials, DPoP/proof
// failures, egress/NetworkPolicy violations, secret/key access, privileged/admin
// actions, and "first-awareness" incident detections — to the SIEM / central log
// management (Audit Design §5, §8; Services Catalog §3.9.7).
//
// Events are the frozen §8.1 broker.Envelope tagged broker.CategorySecurity,
// stamped with a ULID id, a high-precision occurrence time, and the request's
// correlation/trace ids. A pluggable Sink decides where they go: a LogSink emits
// them as structured log lines the platform's log pipeline ships to the SIEM (the
// common path), or a BrokerSink publishes them onto the event stream. The library
// is decoupled from the concrete transport so it stays in-process glue.
//
// # NIS2 timing (24-72-30)
//
// The occurrence time is a high-precision, synced-clock instant so the NIS2
// reporting clock is defensible: 24 h early warning, 72 h notification, 30 d final
// report from "when we first became aware." FirstAwareness captures that instant
// explicitly and returns it, so the caller can record it in the incident register.
//
// # PII posture
//
// Security events are mostly metadata; pseudonymise actors where possible and keep
// the envelope content-free. The emitter strips free-text/content attribute keys
// defensively, and the publisher strips bearer-token-shaped keys.
//
// eIDAS-audit (signing evidence) and GDPR-audit (GDPR access) are separate mechanisms
// with their own libraries (go-eidas-audit, go-gdpr-audit). A single action may be
// security-relevant *and* a GDPR access (e.g. operator break-glass): the service
// emits both, rather than overloading one event.
package secevents
