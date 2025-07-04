package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ConfigValidator provides comprehensive configuration validation
type ConfigValidator struct {
	rules []ValidationRule
}

// ValidationRule defines a single validation rule
type ValidationRule struct {
	Name        string
	Description string
	Validator   func(*Config) error
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
	Rule    string
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s (value: %v)", ve.Field, ve.Message, ve.Value)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError
}

func (ve *ValidationErrors) Error() string {
	if len(ve.Errors) == 1 {
		return ve.Errors[0].Error()
	}
	
	var messages []string
	for _, err := range ve.Errors {
		messages = append(messages, err.Error())
	}
	
	return fmt.Sprintf("validation failed with %d errors:\n  - %s", 
		len(ve.Errors), strings.Join(messages, "\n  - "))
}

// Add adds a validation error
func (ve *ValidationErrors) Add(field, rule, message string, value interface{}) {
	ve.Errors = append(ve.Errors, ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
		Rule:    rule,
	})
}

// HasErrors returns true if there are validation errors
func (ve *ValidationErrors) HasErrors() bool {
	return len(ve.Errors) > 0
}

// NewConfigValidator creates a new configuration validator with built-in rules
func NewConfigValidator() *ConfigValidator {
	validator := &ConfigValidator{}
	validator.setupBuiltinRules()
	return validator
}

// AddRule adds a custom validation rule
func (cv *ConfigValidator) AddRule(rule ValidationRule) {
	cv.rules = append(cv.rules, rule)
}

// Validate validates the entire configuration
func (cv *ConfigValidator) Validate(config *Config) error {
	var validationErrors ValidationErrors
	
	for _, rule := range cv.rules {
		if err := rule.Validator(config); err != nil {
			if ve, ok := err.(*ValidationError); ok {
				validationErrors.Errors = append(validationErrors.Errors, *ve)
			} else if ves, ok := err.(*ValidationErrors); ok {
				validationErrors.Errors = append(validationErrors.Errors, ves.Errors...)
			} else {
				validationErrors.Add("unknown", rule.Name, err.Error(), nil)
			}
		}
	}
	
	if validationErrors.HasErrors() {
		return &validationErrors
	}
	
	return nil
}

// setupBuiltinRules sets up the built-in validation rules
func (cv *ConfigValidator) setupBuiltinRules() {
	cv.rules = []ValidationRule{
		{
			Name:        "environment",
			Description: "Validates environment setting",
			Validator:   cv.validateEnvironment,
		},
		{
			Name:        "server",
			Description: "Validates server configuration",
			Validator:   cv.validateServer,
		},
		{
			Name:        "database",
			Description: "Validates database configuration",
			Validator:   cv.validateDatabase,
		},
		{
			Name:        "redis",
			Description: "Validates Redis configuration",
			Validator:   cv.validateRedis,
		},
		{
			Name:        "providers",
			Description: "Validates AI provider configuration",
			Validator:   cv.validateProviders,
		},
		{
			Name:        "proxy",
			Description: "Validates proxy configuration",
			Validator:   cv.validateProxy,
		},
		{
			Name:        "security",
			Description: "Validates security configuration",
			Validator:   cv.validateSecurity,
		},
		{
			Name:        "cache",
			Description: "Validates cache configuration",
			Validator:   cv.validateCache,
		},
		{
			Name:        "monitoring",
			Description: "Validates monitoring configuration",
			Validator:   cv.validateMonitoring,
		},
		{
			Name:        "timeouts",
			Description: "Validates timeout configuration",
			Validator:   cv.validateTimeouts,
		},
		{
			Name:        "router",
			Description: "Validates router configuration",
			Validator:   cv.validateRouter,
		},
	}
}

// validateEnvironment validates environment settings
func (cv *ConfigValidator) validateEnvironment(config *Config) error {
	validEnvironments := []string{"development", "staging", "production", "test"}
	
	for _, env := range validEnvironments {
		if config.Environment == env {
			return nil
		}
	}
	
	return &ValidationError{
		Field:   "environment",
		Value:   config.Environment,
		Message: fmt.Sprintf("must be one of: %s", strings.Join(validEnvironments, ", ")),
		Rule:    "environment",
	}
}

// validateServer validates server configuration
func (cv *ConfigValidator) validateServer(config *Config) error {
	var errors ValidationErrors
	
	// Validate port
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		errors.Add("server.port", "port_range", "must be between 1 and 65535", config.Server.Port)
	}
	
	// Validate host
	if config.Server.Host == "" {
		errors.Add("server.host", "required", "cannot be empty", config.Server.Host)
	}
	
	// Validate timeouts
	if config.Server.ReadTimeout < 0 {
		errors.Add("server.read_timeout", "positive", "must be positive", config.Server.ReadTimeout)
	}
	
	if config.Server.WriteTimeout < 0 {
		errors.Add("server.write_timeout", "positive", "must be positive", config.Server.WriteTimeout)
	}
	
	if config.Server.IdleTimeout < 0 {
		errors.Add("server.idle_timeout", "positive", "must be positive", config.Server.IdleTimeout)
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateDatabase validates database configuration
func (cv *ConfigValidator) validateDatabase(config *Config) error {
	var errors ValidationErrors
	
	// Validate host
	if config.Database.Host == "" {
		errors.Add("database.host", "required", "cannot be empty", config.Database.Host)
	}
	
	// Validate port
	if config.Database.Port <= 0 || config.Database.Port > 65535 {
		errors.Add("database.port", "port_range", "must be between 1 and 65535", config.Database.Port)
	}
	
	// Validate database name
	if config.Database.Database == "" {
		errors.Add("database.database", "required", "cannot be empty", config.Database.Database)
	}
	
	// Validate SSL mode
	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full", "prefer"}
	validSSL := false
	for _, mode := range validSSLModes {
		if config.Database.SSLMode == mode {
			validSSL = true
			break
		}
	}
	if !validSSL {
		errors.Add("database.ssl_mode", "ssl_mode", 
			fmt.Sprintf("must be one of: %s", strings.Join(validSSLModes, ", ")), 
			config.Database.SSLMode)
	}
	
	// Validate connection pool settings
	if config.Database.MaxOpenConns < 0 {
		errors.Add("database.max_open_conns", "positive", "must be non-negative", config.Database.MaxOpenConns)
	}
	
	if config.Database.MaxIdleConns < 0 {
		errors.Add("database.max_idle_conns", "positive", "must be non-negative", config.Database.MaxIdleConns)
	}
	
	if config.Database.MaxIdleConns > config.Database.MaxOpenConns && config.Database.MaxOpenConns > 0 {
		errors.Add("database.max_idle_conns", "pool_logic", 
			"cannot exceed max_open_conns", config.Database.MaxIdleConns)
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateRedis validates Redis configuration
func (cv *ConfigValidator) validateRedis(config *Config) error {
	var errors ValidationErrors
	
	// Validate host
	if config.Redis.Host == "" {
		errors.Add("redis.host", "required", "cannot be empty", config.Redis.Host)
	}
	
	// Validate port
	if config.Redis.Port <= 0 || config.Redis.Port > 65535 {
		errors.Add("redis.port", "port_range", "must be between 1 and 65535", config.Redis.Port)
	}
	
	// Validate database number
	if config.Redis.Database < 0 || config.Redis.Database > 15 {
		errors.Add("redis.database", "db_range", "must be between 0 and 15", config.Redis.Database)
	}
	
	// Validate pool size
	if config.Redis.PoolSize <= 0 {
		errors.Add("redis.pool_size", "positive", "must be positive", config.Redis.PoolSize)
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateProviders validates AI provider configuration
func (cv *ConfigValidator) validateProviders(config *Config) error {
	var errors ValidationErrors
	
	// Validate OpenAI configuration
	if err := cv.validateOpenAIConfig(&config.Providers.OpenAI); err != nil {
		if ve, ok := err.(*ValidationErrors); ok {
			for i := range ve.Errors {
				ve.Errors[i].Field = "providers.openai." + ve.Errors[i].Field
			}
			errors.Errors = append(errors.Errors, ve.Errors...)
		}
	}
	
	// Validate Anthropic configuration
	if err := cv.validateAnthropicConfig(&config.Providers.Anthropic); err != nil {
		if ve, ok := err.(*ValidationErrors); ok {
			for i := range ve.Errors {
				ve.Errors[i].Field = "providers.anthropic." + ve.Errors[i].Field
			}
			errors.Errors = append(errors.Errors, ve.Errors...)
		}
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateOpenAIConfig validates OpenAI specific configuration
func (cv *ConfigValidator) validateOpenAIConfig(config *OpenAIConfig) error {
	var errors ValidationErrors
	
	// Validate API key (should not be empty in production)
	if config.APIKey == "" {
		errors.Add("api_key", "required", "API key is required", config.APIKey)
	}
	
	// Validate base URL
	if config.BaseURL != "" {
		if _, err := url.Parse(config.BaseURL); err != nil {
			errors.Add("base_url", "url_format", "must be a valid URL", config.BaseURL)
		}
	}
	
	// Validate timeout
	if config.Timeout <= 0 {
		errors.Add("timeout", "positive", "must be positive", config.Timeout)
	}
	
	// Validate max retries
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		errors.Add("max_retries", "retry_range", "must be between 0 and 10", config.MaxRetries)
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateAnthropicConfig validates Anthropic specific configuration
func (cv *ConfigValidator) validateAnthropicConfig(config *AnthropicConfig) error {
	var errors ValidationErrors
	
	// Validate API key
	if config.APIKey == "" {
		errors.Add("api_key", "required", "API key is required", config.APIKey)
	}
	
	// Validate base URL
	if config.BaseURL != "" {
		if _, err := url.Parse(config.BaseURL); err != nil {
			errors.Add("base_url", "url_format", "must be a valid URL", config.BaseURL)
		}
	}
	
	// Validate timeout
	if config.Timeout <= 0 {
		errors.Add("timeout", "positive", "must be positive", config.Timeout)
	}
	
	// Validate max retries
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		errors.Add("max_retries", "retry_range", "must be between 0 and 10", config.MaxRetries)
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateProxy validates proxy configuration
func (cv *ConfigValidator) validateProxy(config *Config) error {
	var errors ValidationErrors
	
	if !config.Proxy.Enabled {
		return nil // Skip validation if proxy is disabled
	}
	
	// Validate port
	if config.Proxy.Port <= 0 || config.Proxy.Port > 65535 {
		errors.Add("proxy.port", "port_range", "must be between 1 and 65535", config.Proxy.Port)
	}
	
	// Validate SSL configuration
	if config.Proxy.SSLBump {
		if config.Proxy.CertFile == "" {
			errors.Add("proxy.cert_file", "required", "certificate file required when SSL bump is enabled", config.Proxy.CertFile)
		}
		
		if config.Proxy.KeyFile == "" {
			errors.Add("proxy.key_file", "required", "key file required when SSL bump is enabled", config.Proxy.KeyFile)
		}
	}
	
	// Validate target hosts
	if len(config.Proxy.TargetHosts) == 0 {
		errors.Add("proxy.target_hosts", "required", "at least one target host is required", config.Proxy.TargetHosts)
	}
	
	for i, host := range config.Proxy.TargetHosts {
		if host == "" {
			errors.Add(fmt.Sprintf("proxy.target_hosts[%d]", i), "required", "host cannot be empty", host)
		}
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateSecurity validates security configuration
func (cv *ConfigValidator) validateSecurity(config *Config) error {
	var errors ValidationErrors
	
	// Validate JWT secret
	if config.Security.JWTSecret == "" {
		errors.Add("security.jwt_secret", "required", "JWT secret is required", config.Security.JWTSecret)
	} else if len(config.Security.JWTSecret) < 32 {
		errors.Add("security.jwt_secret", "security", "JWT secret should be at least 32 characters", len(config.Security.JWTSecret))
	}
	
	// Validate JWT expiry
	if config.Security.JWTExpiry <= 0 {
		errors.Add("security.jwt_expiry", "positive", "JWT expiry must be positive", config.Security.JWTExpiry)
	}
	
	// Validate TLS version
	validTLSVersions := []string{"1.0", "1.1", "1.2", "1.3"}
	validTLS := false
	for _, version := range validTLSVersions {
		if config.Security.TLSMinVersion == version {
			validTLS = true
			break
		}
	}
	if !validTLS {
		errors.Add("security.tls_min_version", "tls_version", 
			fmt.Sprintf("must be one of: %s", strings.Join(validTLSVersions, ", ")), 
			config.Security.TLSMinVersion)
	}
	
	// Validate CORS origins
	if config.Security.CorsEnabled {
		for i, origin := range config.Security.CorsOrigins {
			if origin != "*" {
				if _, err := url.Parse(origin); err != nil {
					errors.Add(fmt.Sprintf("security.cors_origins[%d]", i), "url_format", 
						"must be a valid URL or '*'", origin)
				}
			}
		}
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateCache validates cache configuration
func (cv *ConfigValidator) validateCache(config *Config) error {
	var errors ValidationErrors
	
	if !config.Cache.Enabled {
		return nil // Skip validation if cache is disabled
	}
	
	// Validate TTL
	if config.Cache.DefaultTTL <= 0 {
		errors.Add("cache.default_ttl", "positive", "default TTL must be positive", config.Cache.DefaultTTL)
	}
	
	// Validate max size format
	if config.Cache.MaxSize != "" {
		if err := cv.validateSizeFormat(config.Cache.MaxSize); err != nil {
			errors.Add("cache.max_size", "size_format", err.Error(), config.Cache.MaxSize)
		}
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateMonitoring validates monitoring configuration
func (cv *ConfigValidator) validateMonitoring(config *Config) error {
	var errors ValidationErrors
	
	if !config.Monitoring.Enabled {
		return nil // Skip validation if monitoring is disabled
	}
	
	// Validate metrics port
	if config.Monitoring.MetricsPort <= 0 || config.Monitoring.MetricsPort > 65535 {
		errors.Add("monitoring.metrics_port", "port_range", "must be between 1 and 65535", config.Monitoring.MetricsPort)
	}
	
	// Validate paths
	if config.Monitoring.MetricsPath == "" {
		errors.Add("monitoring.metrics_path", "required", "metrics path cannot be empty", config.Monitoring.MetricsPath)
	}
	
	if config.Monitoring.HealthPath == "" {
		errors.Add("monitoring.health_path", "required", "health path cannot be empty", config.Monitoring.HealthPath)
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateTimeouts validates timeout configuration
func (cv *ConfigValidator) validateTimeouts(config *Config) error {
	var errors ValidationErrors
	
	timeouts := map[string]time.Duration{
		"default_request_timeout":      config.Timeouts.DefaultRequestTimeout,
		"chat_completion_timeout":      config.Timeouts.ChatCompletionTimeout,
		"streaming_timeout":            config.Timeouts.StreamingTimeout,
		"health_check_timeout":         config.Timeouts.HealthCheckTimeout,
		"provider_connect_timeout":     config.Timeouts.ProviderConnectTimeout,
		"provider_read_timeout":        config.Timeouts.ProviderReadTimeout,
		"provider_write_timeout":       config.Timeouts.ProviderWriteTimeout,
		"database_query_timeout":       config.Timeouts.DatabaseQueryTimeout,
		"database_connection_timeout":  config.Timeouts.DatabaseConnectionTimeout,
		"cache_operation_timeout":      config.Timeouts.CacheOperationTimeout,
		"shutdown_timeout":             config.Timeouts.ShutdownTimeout,
	}
	
	for name, timeout := range timeouts {
		if timeout <= 0 {
			errors.Add(fmt.Sprintf("timeouts.%s", name), "positive", "timeout must be positive", timeout)
		}
		
		if timeout > 24*time.Hour {
			errors.Add(fmt.Sprintf("timeouts.%s", name), "reasonable", "timeout seems unreasonably large", timeout)
		}
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateRouter validates router configuration
func (cv *ConfigValidator) validateRouter(config *Config) error {
	var errors ValidationErrors
	
	// Validate strategy
	validStrategies := []string{"round_robin", "random", "weighted", "health_based", "latency_based"}
	validStrategy := false
	strategyStr := string(config.Router.Strategy)
	for _, strategy := range validStrategies {
		if strategyStr == strategy {
			validStrategy = true
			break
		}
	}
	if !validStrategy {
		errors.Add("router.strategy", "strategy", 
			fmt.Sprintf("must be one of: %s", strings.Join(validStrategies, ", ")), 
			strategyStr)
	}
	
	// Validate max retries
	if config.Router.MaxRetries < 0 || config.Router.MaxRetries > 10 {
		errors.Add("router.max_retries", "retry_range", "must be between 0 and 10", config.Router.MaxRetries)
	}
	
	// Validate circuit breaker settings
	if config.Router.CircuitBreakerEnabled {
		if config.Router.CircuitBreakerThreshold <= 0 {
			errors.Add("router.circuit_breaker_threshold", "positive", 
				"circuit breaker threshold must be positive", config.Router.CircuitBreakerThreshold)
		}
		
		if config.Router.CircuitBreakerWindow <= 0 {
			errors.Add("router.circuit_breaker_window", "positive", 
				"circuit breaker window must be positive", config.Router.CircuitBreakerWindow)
		}
	}
	
	if errors.HasErrors() {
		return &errors
	}
	
	return nil
}

// validateSizeFormat validates size format strings (e.g., "100MB", "1GB")
func (cv *ConfigValidator) validateSizeFormat(size string) error {
	sizeRegex := regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)$`)
	
	if !sizeRegex.MatchString(size) {
		return fmt.Errorf("invalid size format, expected format like '100MB', '1.5GB'")
	}
	
	return nil
}

// IsValidHostPort validates host:port format
func (cv *ConfigValidator) IsValidHostPort(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	
	// Validate port
	if portNum, err := strconv.Atoi(port); err != nil || portNum <= 0 || portNum > 65535 {
		return false
	}
	
	// Validate host (can be IP or hostname)
	if host == "" {
		return false
	}
	
	return true
} 