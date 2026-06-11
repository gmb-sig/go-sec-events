package secevents

import (
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// Configuration is the (small) Regime C emitter configuration, bound as a
// sub-configuration of a consuming service. It only carries the broker topic used
// when a BrokerSink is wired; the LogSink path needs no configuration. Most
// services using the LogSink can skip this entirely.
type Configuration struct {
	// Topic is the broker topic security events are published to when using a
	// BrokerSink (env SEC_EVENTS_TOPIC). Defaults to DefaultTopic.
	Topic string `mapstructure:"topic" validate:"required"`
}

// Bind registers defaults and the environment binding under prefix.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".topic", DefaultTopic)

	_ = v.BindEnv(prefix+".topic", "SEC_EVENTS_TOPIC")
}

// Validate validates the configuration.
func (c *Configuration) Validate(valid *validation.Validate) error {
	return valid.Struct(c)
}
