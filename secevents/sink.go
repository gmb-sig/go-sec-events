package secevents

import (
	"errors"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-platform-kit/broker"
)

// DefaultTopic is the broker topic used by BrokerSink for security events.
const DefaultTopic = "audit.security"

// logMessage is the fixed message every security log line carries, so the SIEM
// can select the stream by message and index on the structured fields.
const logMessage = "security_event"

// LogSink emits security events as structured log lines on the request logger.
// The platform's log pipeline ships them to the SIEM / central log management —
// the common NIS2-audit path. Severity maps to the log level so
// SIEM alerting and dashboards work without parsing the payload.
type LogSink struct{}

// NewLogSink returns a LogSink.
func NewLogSink() *LogSink { return &LogSink{} }

// Emit writes ev to the request logger. The correlation_id/trace_id are already
// on the logger (correlation middleware); this adds the event-specific fields.
func (s *LogSink) Emit(ctx *azugo.Context, ev *broker.Envelope) error {
	if ev == nil {
		return errors.New("secevents: nil envelope")
	}

	fields := make([]zap.Field, 0, 10)
	fields = append(fields,
		zap.String("event_id", ev.EventID),
		zap.Time("occurred_at", ev.OccurredAt),
		zap.String("event_type", ev.EventType),
		zap.String("category", string(broker.CategorySecurity)),
		zap.String("outcome", string(ev.Outcome)),
		zap.String(AttrSeverity, string(severityOf(ev))),
	)

	if ev.Actor != nil {
		fields = append(fields,
			zap.String("actor_id", ev.Actor.ID),
			zap.String("actor_type", ev.Actor.Type),
		)
	}

	if ev.Resource != nil {
		fields = append(fields,
			zap.String("resource_type", ev.Resource.Type),
			zap.String("resource_id", ev.Resource.ID),
		)
	}

	if len(ev.DataSubjects) > 0 {
		fields = append(fields, zap.Strings("data_subjects", ev.DataSubjects))
	}

	if ev.IP != "" {
		fields = append(fields, zap.String("ip", ev.IP))
	}

	if len(ev.Attributes) > 0 {
		fields = append(fields, zap.Any("attributes", ev.Attributes))
	}

	log := ctx.Log()

	switch severityOf(ev) {
	case SeverityCritical, SeverityHigh:
		log.Error(logMessage, fields...)
	case SeverityWarning:
		log.Warn(logMessage, fields...)
	case SeverityInfo:
		log.Info(logMessage, fields...)
	default:
		log.Info(logMessage, fields...)
	}

	return nil
}

// BrokerSink publishes security events onto the broker event stream (the
// alternative path that fans into the SIEM). Use it where the SIEM ingests from
// the broker rather than the log pipeline.
type BrokerSink struct {
	pub   *broker.Publisher
	topic string
}

// NewBrokerSink returns a BrokerSink that publishes to topic over pub. Pass
// DefaultTopic unless the deployment overrides it.
func NewBrokerSink(pub *broker.Publisher, topic string) *BrokerSink {
	if topic == "" {
		topic = DefaultTopic
	}

	return &BrokerSink{pub: pub, topic: topic}
}

// Emit publishes ev to the configured topic. The event is already stamped and
// validated by the Emitter; broker.Publish is idempotent over the stamp.
func (s *BrokerSink) Emit(ctx *azugo.Context, ev *broker.Envelope) error {
	if s == nil || s.pub == nil {
		return errors.New("secevents: broker sink has no publisher")
	}

	return s.pub.Publish(ctx, s.topic, ev)
}
