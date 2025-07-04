package providers

import (
	"ai-gateway-poc/internal/providers/interfaces"
	"context"
	"fmt"
	"sync"
	"time"

	"ai-gateway-poc/internal/providers/anthropic"
	"ai-gateway-poc/internal/providers/openai"
	"github.com/sirupsen/logrus"
)

// Manager manages multiple AI providers
type Manager struct {
	providers map[string]interfaces.Provider
	config    *ManagerConfig
	logger    *logrus.Logger
	mu        sync.RWMutex
	metrics   map[string]*interfaces.ProviderMetrics
}

// ManagerConfig represents the configuration for the provider manager
type ManagerConfig struct {
	Providers map[string]*interfaces.ProviderConfig `yaml:"providers" mapstructure:"providers"`
	
	// Default settings
	DefaultTimeout    time.Duration `yaml:"default_timeout" mapstructure:"default_timeout"`
	DefaultMaxRetries int           `yaml:"default_max_retries" mapstructure:"default_max_retries"`
	DefaultRetryDelay time.Duration `yaml:"default_retry_delay" mapstructure:"default_retry_delay"`
	
	// Global rate limiting
	GlobalRateLimit *interfaces.RateLimitConfig `yaml:"global_rate_limit" mapstructure:"global_rate_limit"`
	
	// Health check settings
	HealthCheckInterval time.Duration `yaml:"health_check_interval" mapstructure:"health_check_interval"`
	HealthCheckTimeout  time.Duration `yaml:"health_check_timeout" mapstructure:"health_check_timeout"`
	
	// Failover settings
	EnableFailover      bool          `yaml:"enable_failover" mapstructure:"enable_failover"`
	FailoverStrategy    string        `yaml:"failover_strategy" mapstructure:"failover_strategy"` // "round_robin", "priority", "load_based"
	MaxFailureCount     int           `yaml:"max_failure_count" mapstructure:"max_failure_count"`
	FailureWindow       time.Duration `yaml:"failure_window" mapstructure:"failure_window"`
}

// NewManager creates a new provider manager
func NewManager(config *ManagerConfig, logger *logrus.Logger) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if logger == nil {
		logger = logrus.New()
	}

	// Set defaults
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 60 * time.Second
	}
	if config.DefaultMaxRetries == 0 {
		config.DefaultMaxRetries = 3
	}
	if config.DefaultRetryDelay == 0 {
		config.DefaultRetryDelay = 1 * time.Second
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 5 * time.Minute
	}
	if config.HealthCheckTimeout == 0 {
		config.HealthCheckTimeout = 10 * time.Second
	}
	if config.MaxFailureCount == 0 {
		config.MaxFailureCount = 5
	}
	if config.FailureWindow == 0 {
		config.FailureWindow = 10 * time.Minute
	}

	manager := &Manager{
		providers: make(map[string]interfaces.Provider),
		config:    config,
		logger:    logger,
		metrics:   make(map[string]*interfaces.ProviderMetrics),
	}

	// Initialize providers
	if err := manager.initializeProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	// Start health checks if enabled
	if config.HealthCheckInterval > 0 {
		go manager.healthCheckRoutine()
	}

	return manager, nil
}

// initializeProviders initializes all configured providers
func (m *Manager) initializeProviders() error {
	for name, providerConfig := range m.config.Providers {
		// Apply defaults
		if providerConfig.Timeout == 0 {
			providerConfig.Timeout = m.config.DefaultTimeout
		}
		if providerConfig.MaxRetries == 0 {
			providerConfig.MaxRetries = m.config.DefaultMaxRetries
		}
		if providerConfig.RetryDelay == 0 {
			providerConfig.RetryDelay = m.config.DefaultRetryDelay
		}

		var provider interfaces.Provider
		var err error

		switch name {
		case "openai":
			provider, err = openai.NewClient(providerConfig)
		case "anthropic":
			provider, err = anthropic.NewClient(providerConfig)
		default:
			m.logger.WithField("provider", name).Warn("Unknown provider type")
			continue
		}

		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"provider": name,
				"error":    err,
			}).Error("Failed to initialize provider")
			continue
		}

		m.providers[name] = provider
		m.metrics[name] = &interfaces.ProviderMetrics{
			ErrorsByCode: make(map[string]int64),
		}

		m.logger.WithField("provider", name).Info("Provider initialized successfully")
	}

	if len(m.providers) == 0 {
		return fmt.Errorf("no providers were successfully initialized")
	}

	return nil
}

// GetProvider returns a specific provider by name
func (m *Manager) GetProvider(name string) (interfaces.Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}

	return provider, nil
}

// ListProviders returns a list of all available providers
func (m *Manager) ListProviders() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]string, 0, len(m.providers))
	for name := range m.providers {
		providers = append(providers, name)
	}

	return providers
}

// ChatCompletion routes a chat completion request to the specified provider
func (m *Manager) ChatCompletion(ctx context.Context, providerName string, request *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Add request metadata
	request.Timestamp = time.Now()

	response, err := provider.ChatCompletion(ctx, request)
	if err != nil {
		m.recordProviderError(providerName, err)
		
		// Try failover if enabled
		if m.config.EnableFailover {
			return m.tryFailover(ctx, providerName, request)
		}
		
		return nil, err
	}

	m.recordProviderSuccess(providerName)
	return response, nil
}

// StreamChatCompletion routes a streaming chat completion request to the specified provider
func (m *Manager) StreamChatCompletion(ctx context.Context, providerName string, request *interfaces.ChatCompletionRequest) (<-chan *interfaces.ChatCompletionStreamResponse, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Add request metadata
	request.Timestamp = time.Now()

	return provider.StreamChatCompletion(ctx, request)
}

// tryFailover attempts to use a different provider when the primary fails
func (m *Manager) tryFailover(ctx context.Context, failedProvider string, request *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error) {
	m.logger.WithField("failed_provider", failedProvider).Info("Attempting failover")

	// Get list of alternative providers
	alternatives := m.getFailoverProviders(failedProvider)
	
	for _, providerName := range alternatives {
		m.logger.WithField("provider", providerName).Debug("Trying failover provider")
		
		provider, err := m.GetProvider(providerName)
		if err != nil {
			continue
		}

		response, err := provider.ChatCompletion(ctx, request)
		if err != nil {
			m.recordProviderError(providerName, err)
			continue
		}

		m.recordProviderSuccess(providerName)
		m.logger.WithFields(logrus.Fields{
			"failed_provider":   failedProvider,
			"failover_provider": providerName,
		}).Info("Failover successful")
		
		return response, nil
	}

	return nil, fmt.Errorf("all failover providers failed")
}

// getFailoverProviders returns a list of providers to try for failover
func (m *Manager) getFailoverProviders(excludeProvider string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var providers []string
	for name := range m.providers {
		if name != excludeProvider {
			providers = append(providers, name)
		}
	}

	// TODO: Implement different failover strategies (priority, load-based, etc.)
	// For now, just return all available providers
	
	return providers
}

// ValidateCredentials validates credentials for all providers
func (m *Manager) ValidateCredentials(ctx context.Context) map[string]error {
	m.mu.RLock()
	providers := make(map[string]interfaces.Provider)
	for name, provider := range m.providers {
		providers[name] = provider
	}
	m.mu.RUnlock()

	results := make(map[string]error)
	
	for name, provider := range providers {
		err := provider.ValidateCredentials(ctx)
		results[name] = err
		
		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"provider": name,
				"error":    err,
			}).Warn("Provider credential validation failed")
		} else {
			m.logger.WithField("provider", name).Info("Provider credentials validated successfully")
		}
	}

	return results
}

// GetModels returns available models from all providers
func (m *Manager) GetModels(ctx context.Context) (map[string][]interfaces.Model, error) {
	m.mu.RLock()
	providers := make(map[string]interfaces.Provider)
	for name, provider := range m.providers {
		providers[name] = provider
	}
	m.mu.RUnlock()

	results := make(map[string][]interfaces.Model)
	
	for name, provider := range providers {
		models, err := provider.GetModels(ctx)
		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"provider": name,
				"error":    err,
			}).Warn("Failed to fetch models from provider")
			continue
		}
		
		results[name] = models
	}

	return results, nil
}

// GetProviderMetrics returns metrics for all providers
func (m *Manager) GetProviderMetrics() map[string]*interfaces.ProviderMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := make(map[string]*interfaces.ProviderMetrics)
	for name, metric := range m.metrics {
		// Create a copy of the metric
		metricCopy := *metric
		metrics[name] = &metricCopy
	}

	return metrics
}

// GetUsageStats returns usage statistics for all providers
func (m *Manager) GetUsageStats(ctx context.Context) (map[string]*interfaces.UsageStats, error) {
	m.mu.RLock()
	providers := make(map[string]interfaces.Provider)
	for name, provider := range m.providers {
		providers[name] = provider
	}
	m.mu.RUnlock()

	results := make(map[string]*interfaces.UsageStats)
	
	for name, provider := range providers {
		stats, err := provider.GetUsage(ctx)
		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"provider": name,
				"error":    err,
			}).Warn("Failed to fetch usage stats from provider")
			continue
		}
		
		results[name] = stats
	}

	return results, nil
}

// Close closes all providers
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error
	
	for name, provider := range m.providers {
		if err := provider.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close provider %s: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing providers: %v", errors)
	}

	return nil
}

// healthCheckRoutine performs periodic health checks on all providers
func (m *Manager) healthCheckRoutine() {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.performHealthChecks()
	}
}

// performHealthChecks checks the health of all providers
func (m *Manager) performHealthChecks() {
	m.mu.RLock()
	providers := make(map[string]interfaces.Provider)
	for name, provider := range m.providers {
		providers[name] = provider
	}
	m.mu.RUnlock()

	for name, provider := range providers {
		go func(providerName string, p interfaces.Provider) {
			ctx, cancel := context.WithTimeout(context.Background(), m.config.HealthCheckTimeout)
			defer cancel()

			err := p.ValidateCredentials(ctx)
			if err != nil {
				m.logger.WithFields(logrus.Fields{
					"provider": providerName,
					"error":    err,
				}).Warn("Provider health check failed")
				m.recordProviderError(providerName, err)
			} else {
				m.logger.WithField("provider", providerName).Debug("Provider health check passed")
			}
		}(name, provider)
	}
}

// recordProviderError records an error for a provider
func (m *Manager) recordProviderError(providerName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	metric, exists := m.metrics[providerName]
	if !exists {
		return
	}

	metric.FailedRequests++
	
	if providerErr, ok := err.(*interfaces.ProviderError); ok {
		metric.ErrorsByCode[providerErr.Code]++
	} else {
		metric.ErrorsByCode[interfaces.ErrorCodeUnknownError]++
	}
}

// recordProviderSuccess records a successful operation for a provider
func (m *Manager) recordProviderSuccess(providerName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	metric, exists := m.metrics[providerName]
	if !exists {
		return
	}

	metric.SuccessfulRequests++
	metric.TotalRequests++
}

// GetHealthStatus returns the health status of all providers
func (m *Manager) GetHealthStatus(ctx context.Context) map[string]bool {
	m.mu.RLock()
	providers := make(map[string]interfaces.Provider)
	for name, provider := range m.providers {
		providers[name] = provider
	}
	m.mu.RUnlock()

	results := make(map[string]bool)
	
	for name, provider := range providers {
		healthCtx, cancel := context.WithTimeout(ctx, m.config.HealthCheckTimeout)
		err := provider.ValidateCredentials(healthCtx)
		cancel()
		
		results[name] = err == nil
	}

	return results
}

// IsProviderHealthy checks if a specific provider is healthy
func (m *Manager) IsProviderHealthy(ctx context.Context, providerName string) bool {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return false
	}

	healthCtx, cancel := context.WithTimeout(ctx, m.config.HealthCheckTimeout)
	defer cancel()

	err = provider.ValidateCredentials(healthCtx)
	return err == nil
} 