package config

import "time"

// TimeoutConfig configures timeout behavior for different operations
type TimeoutConfig struct {
	// Request timeouts
	DefaultRequestTimeout    time.Duration `yaml:"default_request_timeout" mapstructure:"default_request_timeout"`
	ChatCompletionTimeout    time.Duration `yaml:"chat_completion_timeout" mapstructure:"chat_completion_timeout"`
	StreamingTimeout         time.Duration `yaml:"streaming_timeout" mapstructure:"streaming_timeout"`
	HealthCheckTimeout       time.Duration `yaml:"health_check_timeout" mapstructure:"health_check_timeout"`
	
	// Provider operation timeouts
	ProviderConnectTimeout   time.Duration `yaml:"provider_connect_timeout" mapstructure:"provider_connect_timeout"`
	ProviderReadTimeout      time.Duration `yaml:"provider_read_timeout" mapstructure:"provider_read_timeout"`
	ProviderWriteTimeout     time.Duration `yaml:"provider_write_timeout" mapstructure:"provider_write_timeout"`
	
	// Database operation timeouts
	DatabaseQueryTimeout     time.Duration `yaml:"database_query_timeout" mapstructure:"database_query_timeout"`
	DatabaseConnectionTimeout time.Duration `yaml:"database_connection_timeout" mapstructure:"database_connection_timeout"`
	
	// Cache operation timeouts
	CacheOperationTimeout    time.Duration `yaml:"cache_operation_timeout" mapstructure:"cache_operation_timeout"`
	
	// Graceful shutdown timeout
	ShutdownTimeout          time.Duration `yaml:"shutdown_timeout" mapstructure:"shutdown_timeout"`
}

// DefaultTimeoutConfig returns sensible default timeout values
func DefaultTimeoutConfig() *TimeoutConfig {
	return &TimeoutConfig{
		DefaultRequestTimeout:      30 * time.Second,
		ChatCompletionTimeout:      60 * time.Second,
		StreamingTimeout:           300 * time.Second, // 5 minutes for streaming
		HealthCheckTimeout:         10 * time.Second,
		ProviderConnectTimeout:     10 * time.Second,
		ProviderReadTimeout:        45 * time.Second,
		ProviderWriteTimeout:       10 * time.Second,
		DatabaseQueryTimeout:       5 * time.Second,
		DatabaseConnectionTimeout:  15 * time.Second,
		CacheOperationTimeout:      2 * time.Second,
		ShutdownTimeout:           30 * time.Second,
	}
} 