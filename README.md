# go-sec-events

The **Regime C** (NIS2 security-operations) event emitter for the eSignature Portal. One
standard way for **every service** to emit structured security events — auth failures,
authZ/IDOR denials, DPoP/proof failures, egress/NetworkPolicy violations, secret/key
access, privileged/admin actions, and **"first-awareness"** incident detections — to the
**SIEM / central log management**, with high-precision synced timestamps so the NIS2
**24-72-30** reporting clock is defensible.

See the [Audit Design](../eSignature-Portal-Audit-Design.md) (§5 Regime C, §6 two breach
clocks, §8) and [Services Catalog](../eSignature-Portal-Services-Catalog.md) §3.9.7.

Events are the **frozen §8.1 `broker.Envelope`** tagged `security`, stamped with a ULID id,
a high-precision occurrence time, and the request's correlation/trace ids. A pluggable
**`Sink`** decides where they go:

| Sink | Destination |
|---|---|
| `LogSink` | structured log lines on the request logger → the log pipeline ships them to the SIEM (the common path) |
| `BrokerSink` | the broker event stream → fans into the SIEM |

Distinct from [`go-eidas-audit`](../go-eidas-audit) (hash-chained signing evidence) and
[`go-gdpr-audit`](../go-gdpr-audit) (GDPR DB log) — different mechanism, different sink.

## Install

```sh
go get github.com/gmb-sig/go-sec-events
```

## Usage

```go
import "github.com/gmb-sig/go-sec-events/secevents"

// LogSink: events become structured log lines the platform ships to the SIEM.
audit := secevents.NewEmitter(secevents.NewLogSink())

// …or BrokerSink where the SIEM ingests from the broker:
// audit := secevents.NewEmitter(secevents.NewBrokerSink(pub, secevents.DefaultTopic))
```

Emit with the typed helpers — severity, category and the lean attribute shape are fixed
for you, and severity maps to the log level so SIEM alerting works without parsing:

```go
// In an authZ middleware / handler:
audit.AuthZDenied(ctx, secevents.Denial{
    Actor:         broker.Actor{ID: ctx.User().ID(), Type: "user"},
    Resource:      broker.Resource{Type: "document", ID: id},
    RequiredScope: "documents:read",
    Reason:        "object not owned by caller",
    IDOR:          true, // raises severity to high
})

// On a network-policy / egress alarm:
audit.EgressViolation(ctx, secevents.Egress{Target: host, Policy: "default-deny"})
```

### First awareness — the NIS2 clock anchor

`FirstAwareness` records the moment a possible significant incident is detected and
**returns the high-precision occurrence time**, so the caller can anchor the 24-hour clock
and the incident register:

```go
anchor, err := audit.FirstAwareness(ctx, secevents.Detection{
    Severity:    secevents.SeverityCritical,
    Summary:     "anomalous egress to unknown host",
    IncidentRef: "INC-2026-014",
    // DetectedAt: detectorTimestamp, // optional; defaults to now
})
// persist `anchor` as "when we first became aware" in the incident register
```

## Events

| Helper | `event_type` | Default severity |
|---|---|---|
| `Authentication` | `auth.login` | info / warning on failure |
| `AuthZDenied` | `authz.denied` | warning / high on IDOR |
| `ServiceTokenFailure` | `auth.service_token` | warning / high on replay·proof |
| `EdgeBlock` | `edge.block` | warning |
| `EgressViolation` | `egress.violation` | high |
| `SigningEgressCall` | `egress.signing` | info / warning on failure |
| `SecretAccess` | `secret.access` | info / high on failure |
| `DataTierAnomaly` | `data.anomaly` | high |
| `ConfigChange` | `config.change` | warning |
| `PrivilegedAccess` | `access.privileged` | high |
| `FirstAwareness` | `incident.first_awareness` | high |

> **PII posture.** Security events are metadata only. The emitter strips free-text/content
> attribute keys defensively, and the publisher strips bearer-token-shaped keys; pseudonymise
> actors where possible. A privileged/break-glass access is *also* a GDPR access — emit the
> Regime B record via [`go-gdpr-audit`](../go-gdpr-audit) too.

## Develop

```sh
go build ./...
go test ./...
go vet ./...
```

## License

MIT — see [LICENSE](./LICENSE).
