package secevents_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/gmb-sig/go-platform-kit/broker"
	"github.com/gmb-sig/go-sec-events/secevents"
)

// captureTransport records every published message for assertion.
type captureTransport struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (t *captureTransport) Publish(_ context.Context, _, _ string, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.msgs = append(t.msgs, append([]byte(nil), payload...))

	return nil
}

func (t *captureTransport) last() *broker.Envelope {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.msgs) == 0 {
		return nil
	}

	ev := &broker.Envelope{}
	_ = json.Unmarshal(t.msgs[len(t.msgs)-1], ev)

	return ev
}

func withCtx(t *testing.T, fn func(ctx *azugo.Context)) {
	t.Helper()

	app := azugo.NewTestApp()
	app.Get("/t", func(ctx *azugo.Context) {
		fn(ctx)
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)

	defer app.Stop()

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)
}

// brokerEmitter wires an Emitter over a BrokerSink and a capture transport.
func brokerEmitter(tr *captureTransport) *secevents.Emitter {
	pub := broker.NewPublisher(tr, "edge-svc")

	return secevents.NewEmitter(secevents.NewBrokerSink(pub, ""))
}

func TestAuthZDenied_IDORIsHighSeverity(t *testing.T) {
	tr := &captureTransport{}
	em := brokerEmitter(tr)

	withCtx(t, func(ctx *azugo.Context) {
		_ = em.AuthZDenied(ctx, secevents.Denial{
			Actor:         broker.Actor{ID: "user-9", Type: "user"},
			Resource:      broker.Resource{Type: "document", ID: "doc-7"},
			RequiredScope: "documents:read",
			Reason:        "object not owned by caller",
			IDOR:          true,
		})
	})

	ev := tr.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventAuthZDenied))
	qt.Check(t, qt.Equals(ev.Categories[0], broker.CategorySecurity))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeDenied))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityHigh)))

	idor, _ := ev.Attributes[secevents.AttrIDOR].(bool)
	qt.Check(t, qt.IsTrue(idor))
}

func TestAuthentication_FailureRaisesWarning(t *testing.T) {
	tr := &captureTransport{}
	em := brokerEmitter(tr)

	withCtx(t, func(ctx *azugo.Context) {
		_ = em.Authentication(ctx, secevents.Auth{
			Actor:   broker.Actor{ID: "user-1", Type: "user"},
			Method:  "eparaksts-mobile",
			Outcome: broker.OutcomeFailure,
		})
	})

	ev := tr.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.Outcome, broker.OutcomeFailure))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityWarning)))
}

func TestFirstAwareness_ReturnsClockAnchor(t *testing.T) {
	tr := &captureTransport{}
	em := brokerEmitter(tr)

	detected := time.Date(2026, 6, 8, 10, 30, 0, 0, time.UTC)

	var (
		anchor time.Time
		err    error
	)

	withCtx(t, func(ctx *azugo.Context) {
		anchor, err = em.FirstAwareness(ctx, secevents.Detection{
			Severity:    secevents.SeverityCritical,
			Summary:     "anomalous egress to unknown host",
			IncidentRef: "INC-1",
			DetectedAt:  detected,
		})
	})

	qt.Assert(t, qt.IsNil(err))
	// The returned anchor is the explicit detection instant (the NIS2 24h clock).
	qt.Check(t, qt.IsTrue(anchor.Equal(detected)))

	ev := tr.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.EventType, secevents.EventFirstAwareness))
	qt.Check(t, qt.Equals(str(ev.Attributes[secevents.AttrSeverity]), string(secevents.SeverityCritical)))
	qt.Check(t, qt.IsTrue(ev.OccurredAt.Equal(detected)))
}

func TestFirstAwareness_DefaultsToNow(t *testing.T) {
	tr := &captureTransport{}
	em := brokerEmitter(tr)

	var anchor time.Time

	withCtx(t, func(ctx *azugo.Context) {
		anchor, _ = em.FirstAwareness(ctx, secevents.Detection{Summary: "probe"})
	})

	// With no explicit DetectedAt, the stamp fills a high-precision time.
	qt.Check(t, qt.IsFalse(anchor.IsZero()))
}

func TestEmit_StripsContentAndTokenAttributes(t *testing.T) {
	tr := &captureTransport{}
	em := brokerEmitter(tr)

	withCtx(t, func(ctx *azugo.Context) {
		_ = em.Emit(ctx, &broker.Envelope{
			EventType: "security.custom",
			Outcome:   broker.OutcomeSuccess,
			Attributes: map[string]any{
				"document_bytes": "%PDF",    // content — must go
				"user_email":     "a@b.c",   // PII — must go
				"dpop_proof":     "eyJ...",  // token — must go
				"target":         "1.2.3.4", // safe metadata — must stay
			},
		})
	})

	ev := tr.last()
	qt.Assert(t, qt.IsNotNil(ev))
	qt.Check(t, qt.Equals(ev.Categories[0], broker.CategorySecurity))

	for _, gone := range []string{"document_bytes", "user_email", "dpop_proof"} {
		_, present := ev.Attributes[gone]
		qt.Check(t, qt.IsFalse(present), qt.Commentf("attribute %q must be stripped", gone))
	}

	_, kept := ev.Attributes["target"]
	qt.Check(t, qt.IsTrue(kept))
}

// TestLogSink_EmitsLeveledLine covers the SIEM-via-logs path: a high-severity
// event is logged at error level with the structured security fields.
func TestLogSink_EmitsLeveledLine(t *testing.T) {
	app := azugo.NewTestApp()
	app.Get("/sec", func(ctx *azugo.Context) {
		em := secevents.NewEmitter(secevents.NewLogSink())
		_ = em.EgressViolation(ctx, secevents.Egress{
			Target: "evil.example",
			Policy: "default-deny",
			Reason: "not on allow-list",
		})
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)

	defer app.Stop()

	obs, logs := observer.New(zap.InfoLevel)
	qt.Assert(t, qt.IsNil(app.ReplaceLogger(zap.New(obs))))

	resp, err := app.TestClient().Get("/sec")
	qt.Assert(t, qt.IsNil(err))
	fasthttp.ReleaseResponse(resp)

	entry, ok := findEntry(logs, "security_event")
	qt.Assert(t, qt.IsTrue(ok), qt.Commentf("expected a security_event log line"))
	qt.Check(t, qt.Equals(entry.Level, zap.ErrorLevel)) // high severity → error
	m := entry.ContextMap()
	qt.Check(t, qt.Equals(str(m["event_type"]), secevents.EventEgressViolation))
	qt.Check(t, qt.Equals(str(m[secevents.AttrSeverity]), string(secevents.SeverityHigh)))
}

func findEntry(logs *observer.ObservedLogs, msg string) (observer.LoggedEntry, bool) {
	for _, e := range logs.All() {
		if e.Message == msg {
			return e, true
		}
	}

	return observer.LoggedEntry{}, false
}

func str(v any) string {
	s, _ := v.(string)

	return s
}
