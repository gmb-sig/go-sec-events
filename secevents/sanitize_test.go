package secevents_test

import (
	"strings"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"

	"github.com/gmb-sig/go-platform-kit/broker"
	"github.com/gmb-sig/go-sec-events/secevents"
)

func TestEmit_CapsLongValuesAndKeepsCallerMapIntact(t *testing.T) {
	tr := &captureTransport{}
	em := brokerEmitter(tr)

	long := strings.Repeat("x", 4*secevents.MaxAttrValueLen)
	caller := map[string]any{
		secevents.AttrReason: long,      // must be truncated on the event…
		"free_text_note":     "secret",  // forbidden key — must be stripped…
		secevents.AttrRule:   "rule-42", // safe — must survive
	}

	withCtx(t, func(ctx *azugo.Context) {
		_ = em.Emit(ctx, &broker.Envelope{
			EventType:  secevents.EventEdgeBlock,
			Outcome:    broker.OutcomeDenied,
			Attributes: caller,
		})
	})

	ev := tr.last()
	qt.Assert(t, qt.IsNotNil(ev))

	reason, _ := ev.Attributes[secevents.AttrReason].(string)
	qt.Check(t, qt.Equals(len([]rune(reason)), secevents.MaxAttrValueLen))

	_, hasNote := ev.Attributes["free_text_note"]
	qt.Check(t, qt.IsFalse(hasNote))
	qt.Check(t, qt.Equals(ev.Attributes[secevents.AttrRule], any("rule-42")))

	// …while the caller-owned map stays untouched (copy-on-write).
	qt.Check(t, qt.Equals(len(caller), 3))
	orig, _ := caller[secevents.AttrReason].(string)
	qt.Check(t, qt.Equals(len(orig), 4*secevents.MaxAttrValueLen))
}
