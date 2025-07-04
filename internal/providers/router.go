package providers

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
)

// RoutingStrategy defines different routing strategies
type RoutingStrategy string

const (
	StrategyRoundRobin    RoutingStrategy = "round_robin"
	StrategyRandom        RoutingStrategy = "random"
	StrategyWeighted      RoutingStrategy = "weighted"
	StrategyHealthBased   RoutingStrategy = "health_based"
	StrategyLatencyBased  RoutingStrategy = "latency_based"
)

// ProviderWeight represents the weight for weighted routing
type ProviderWeight struct {
	ProviderName string
	Weight       int
}

// RouterConfig configures the routing behavior
type RouterConfig struct {
	Strategy              RoutingStrategy   `yaml:"strategy" mapstructure:"strategy"`
	EnableFailover        bool              `yaml:"enable_failover" mapstructure:"enable_failover"`
	MaxRetries            int               `yaml:"max_retries" mapstructure:"max_retries"`
	FailoverTimeout       time.Duration     `yaml:"failover_timeout" mapstructure:"failover_timeout"`
	HealthCheckInterval   time.Duration     `yaml:"health_check_interval" mapstructure:"health_check_interval"`
	CircuitBreakerEnabled bool              `yaml:"circuit_breaker_enabled" mapstructure:"circuit_breaker_enabled"`
	CircuitBreakerThreshold int             `yaml:"circuit_breaker_threshold" mapstructure:"circuit_breaker_threshold"`
	CircuitBreakerWindow  time.Duration     `yaml:"circuit_breaker_window" mapstructure:"circuit_breaker_window"`
	WeightedProviders     []ProviderWeight  `yaml:"weighted_providers" mapstructure:"weighted_providers"`
}

// ProviderState tracks the state of each provider
type ProviderState struct {
	Name               string
	Healthy            bool
	LastHealthCheck    time.Time
	ConsecutiveFailures int
	AverageLatency     time.Duration
	TotalRequests      int64
	SuccessfulRequests int64
	CircuitBreakerOpen bool
	CircuitBreakerOpenTime time.Time
}

// Router implements AI provider routing with various strategies
type Router struct {
	config           *RouterConfig
	providers        map[string]interfaces.Provider
	providerStates   map[string]*ProviderState
	roundRobinIndex  int
	weightedPool     []string
	mu               sync.RWMutex
	healthTicker     *time.Ticker
	stopChan         chan struct{}
}

// NewRouter creates a new provider router
func NewRouter(config *RouterConfig) *Router {
	if config == nil {
		config = &RouterConfig{
			Strategy:              StrategyRoundRobin,
			EnableFailover:        true,
			MaxRetries:            3,
			FailoverTimeout:       30 * time.Second,
			HealthCheckInterval:   5 * time.Minute,
			CircuitBreakerEnabled: true,
			CircuitBreakerThreshold: 5,
			CircuitBreakerWindow:  5 * time.Minute,
		}
	}

	router := &Router{
		config:         config,
		providers:      make(map[string]interfaces.Provider),
		providerStates: make(map[string]*ProviderState),
		weightedPool:   make([]string, 0),
		stopChan:       make(chan struct{}),
	}

	// Initialize weighted pool if using weighted strategy
	if config.Strategy == StrategyWeighted {
		router.buildWeightedPool()
	}

	// Start health monitoring
	if config.HealthCheckInterval > 0 {
		router.startHealthMonitoring()
	}

	return router
}

// AddProvider adds a provider to the router
func (r *Router) AddProvider(name string, provider interfaces.Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider %s already exists", name)
	}

	r.providers[name] = provider
	r.providerStates[name] = &ProviderState{
		Name:            name,
		Healthy:         true,
		LastHealthCheck: time.Now(),
	}

	// Rebuild weighted pool if using weighted strategy
	if r.config.Strategy == StrategyWeighted {
		r.buildWeightedPool()
	}

	return nil
}

// RemoveProvider removes a provider from the router
func (r *Router) RemoveProvider(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.providers, name)
	delete(r.providerStates, name)

	// Rebuild weighted pool if using weighted strategy
	if r.config.Strategy == StrategyWeighted {
		r.buildWeightedPool()
	}
}

// RouteRequest routes a chat completion request to an appropriate provider
func (r *Router) RouteRequest(ctx context.Context, request *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error) {
	var lastErr error
	
	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		// Select provider based on strategy
		providerName, err := r.selectProvider(request)
		if err != nil {
			return nil, fmt.Errorf("failed to select provider: %w", err)
		}

		// Get provider
		r.mu.RLock()
		provider, exists := r.providers[providerName]
		providerState := r.providerStates[providerName]
		r.mu.RUnlock()

		if !exists {
			lastErr = fmt.Errorf("provider %s not found", providerName)
			continue
		}

		// Check circuit breaker
		if r.isCircuitBreakerOpen(providerState) {
			lastErr = &interfaces.ProviderError{
				Code:     interfaces.ErrorCodeServiceUnavailable,
				Message:  fmt.Sprintf("Circuit breaker open for provider %s", providerName),
				Provider: providerName,
				Retryable: true,
			}
			r.recordFailure(providerName, lastErr)
			continue
		}

		// Execute request with timing
		start := time.Now()
		response, err := provider.ChatCompletion(ctx, request)
		duration := time.Since(start)

		if err != nil {
			lastErr = err
			r.recordFailure(providerName, err)
			
			// Check if error is retryable
			if providerErr, ok := err.(*interfaces.ProviderError); ok && !providerErr.IsRetryable() {
				break // Don't retry non-retryable errors
			}
			continue
		}

		// Record success
		r.recordSuccess(providerName, duration)
		return response, nil
	}

	return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
}

// RouteStreamRequest routes a streaming chat completion request
func (r *Router) RouteStreamRequest(ctx context.Context, request *interfaces.ChatCompletionRequest) (<-chan *interfaces.ChatCompletionStreamResponse, error) {
	// Select provider based on strategy
	providerName, err := r.selectProvider(request)
	if err != nil {
		return nil, fmt.Errorf("failed to select provider: %w", err)
	}

	// Get provider
	r.mu.RLock()
	provider, exists := r.providers[providerName]
	providerState := r.providerStates[providerName]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	// Check circuit breaker
	if r.isCircuitBreakerOpen(providerState) {
		return nil, &interfaces.ProviderError{
			Code:     interfaces.ErrorCodeServiceUnavailable,
			Message:  fmt.Sprintf("Circuit breaker open for provider %s", providerName),
			Provider: providerName,
			Retryable: true,
		}
	}

	// Execute streaming request
	start := time.Now()
	respChan, err := provider.StreamChatCompletion(ctx, request)
	if err != nil {
		r.recordFailure(providerName, err)
		return nil, err
	}

	// Wrap the response channel to record metrics
	wrappedChan := make(chan *interfaces.ChatCompletionStreamResponse, 10)
	go func() {
		defer close(wrappedChan)
		streamComplete := false
		
		for response := range respChan {
			if response.Done && !streamComplete {
				// Record success when stream completes successfully
				duration := time.Since(start)
				r.recordSuccess(providerName, duration)
				streamComplete = true
			}
			
			if response.Error != nil && !streamComplete {
				// Record failure if stream encounters an error
				err := &interfaces.ProviderError{
					Code:     response.Error.Code,
					Message:  response.Error.Message,
					Provider: providerName,
				}
				r.recordFailure(providerName, err)
				streamComplete = true
			}
			
			wrappedChan <- response
		}
	}()

	return wrappedChan, nil
}

// selectProvider selects a provider based on the configured strategy
func (r *Router) selectProvider(request *interfaces.ChatCompletionRequest) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Get healthy providers
	healthyProviders := r.getHealthyProviders()
	if len(healthyProviders) == 0 {
		return "", fmt.Errorf("no healthy providers available")
	}

	switch r.config.Strategy {
	case StrategyRoundRobin:
		return r.selectRoundRobin(healthyProviders), nil
	case StrategyRandom:
		return r.selectRandom(healthyProviders), nil
	case StrategyWeighted:
		return r.selectWeighted(healthyProviders), nil
	case StrategyHealthBased:
		return r.selectHealthBased(healthyProviders), nil
	case StrategyLatencyBased:
		return r.selectLatencyBased(healthyProviders), nil
	default:
		return r.selectRoundRobin(healthyProviders), nil
	}
}

// getHealthyProviders returns a list of healthy provider names
func (r *Router) getHealthyProviders() []string {
	healthy := make([]string, 0, len(r.providers))
	for name, state := range r.providerStates {
		if state.Healthy && !r.isCircuitBreakerOpen(state) {
			healthy = append(healthy, name)
		}
	}
	return healthy
}

// selectRoundRobin implements round-robin provider selection
func (r *Router) selectRoundRobin(providers []string) string {
	if len(providers) == 0 {
		return ""
	}
	
	selected := providers[r.roundRobinIndex%len(providers)]
	r.roundRobinIndex++
	return selected
}

// selectRandom implements random provider selection
func (r *Router) selectRandom(providers []string) string {
	if len(providers) == 0 {
		return ""
	}
	return providers[rand.Intn(len(providers))]
}

// selectWeighted implements weighted provider selection
func (r *Router) selectWeighted(providers []string) string {
	if len(r.weightedPool) == 0 {
		return r.selectRoundRobin(providers)
	}
	
	// Filter weighted pool to only include healthy providers
	availableFromPool := make([]string, 0)
	providerSet := make(map[string]bool)
	for _, p := range providers {
		providerSet[p] = true
	}
	
	for _, p := range r.weightedPool {
		if providerSet[p] {
			availableFromPool = append(availableFromPool, p)
		}
	}
	
	if len(availableFromPool) == 0 {
		return r.selectRoundRobin(providers)
	}
	
	return availableFromPool[rand.Intn(len(availableFromPool))]
}

// selectHealthBased selects provider with the best health score
func (r *Router) selectHealthBased(providers []string) string {
	if len(providers) == 0 {
		return ""
	}
	
	bestProvider := providers[0]
	bestScore := r.calculateHealthScore(bestProvider)
	
	for _, provider := range providers[1:] {
		score := r.calculateHealthScore(provider)
		if score > bestScore {
			bestScore = score
			bestProvider = provider
		}
	}
	
	return bestProvider
}

// selectLatencyBased selects provider with the lowest average latency
func (r *Router) selectLatencyBased(providers []string) string {
	if len(providers) == 0 {
		return ""
	}
	
	bestProvider := providers[0]
	bestLatency := r.providerStates[bestProvider].AverageLatency
	
	for _, provider := range providers[1:] {
		latency := r.providerStates[provider].AverageLatency
		if latency < bestLatency || bestLatency == 0 {
			bestLatency = latency
			bestProvider = provider
		}
	}
	
	return bestProvider
}

// calculateHealthScore calculates a health score for a provider
func (r *Router) calculateHealthScore(providerName string) float64 {
	state := r.providerStates[providerName]
	if state.TotalRequests == 0 {
		return 1.0 // New provider gets full score
	}
	
	successRate := float64(state.SuccessfulRequests) / float64(state.TotalRequests)
	latencyPenalty := float64(state.AverageLatency.Milliseconds()) / 1000.0
	failurePenalty := float64(state.ConsecutiveFailures) * 0.1
	
	score := successRate - (latencyPenalty * 0.01) - failurePenalty
	if score < 0 {
		score = 0
	}
	
	return score
}

// buildWeightedPool builds the weighted provider pool for weighted selection
func (r *Router) buildWeightedPool() {
	r.weightedPool = make([]string, 0)
	
	for _, weight := range r.config.WeightedProviders {
		for i := 0; i < weight.Weight; i++ {
			r.weightedPool = append(r.weightedPool, weight.ProviderName)
		}
	}
}

// recordSuccess records a successful request
func (r *Router) recordSuccess(providerName string, duration time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	state := r.providerStates[providerName]
	state.TotalRequests++
	state.SuccessfulRequests++
	state.ConsecutiveFailures = 0
	
	// Update average latency
	if state.AverageLatency == 0 {
		state.AverageLatency = duration
	} else {
		// Simple moving average
		state.AverageLatency = (state.AverageLatency + duration) / 2
	}
	
	// Close circuit breaker if it was open
	if state.CircuitBreakerOpen {
		state.CircuitBreakerOpen = false
	}
}

// recordFailure records a failed request
func (r *Router) recordFailure(providerName string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	state := r.providerStates[providerName]
	state.TotalRequests++
	state.ConsecutiveFailures++
	
	// Open circuit breaker if threshold is reached
	if r.config.CircuitBreakerEnabled && 
		state.ConsecutiveFailures >= r.config.CircuitBreakerThreshold {
		state.CircuitBreakerOpen = true
		state.CircuitBreakerOpenTime = time.Now()
	}
}

// isCircuitBreakerOpen checks if the circuit breaker is open for a provider
func (r *Router) isCircuitBreakerOpen(state *ProviderState) bool {
	if !r.config.CircuitBreakerEnabled || !state.CircuitBreakerOpen {
		return false
	}
	
	// Check if circuit breaker window has passed
	if time.Since(state.CircuitBreakerOpenTime) > r.config.CircuitBreakerWindow {
		state.CircuitBreakerOpen = false
		return false
	}
	
	return true
}

// startHealthMonitoring starts the health monitoring goroutine
func (r *Router) startHealthMonitoring() {
	r.healthTicker = time.NewTicker(r.config.HealthCheckInterval)
	
	go func() {
		for {
			select {
			case <-r.healthTicker.C:
				r.performHealthChecks()
			case <-r.stopChan:
				return
			}
		}
	}()
}

// performHealthChecks checks the health of all providers
func (r *Router) performHealthChecks() {
	r.mu.RLock()
	providers := make(map[string]interfaces.Provider)
	for name, provider := range r.providers {
		providers[name] = provider
	}
	r.mu.RUnlock()
	
	for name, provider := range providers {
		go func(providerName string, p interfaces.Provider) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			err := p.ValidateCredentials(ctx)
			
			r.mu.Lock()
			state := r.providerStates[providerName]
			state.LastHealthCheck = time.Now()
			state.Healthy = (err == nil)
			r.mu.Unlock()
		}(name, provider)
	}
}

// GetProviderStates returns the current state of all providers
func (r *Router) GetProviderStates() map[string]*ProviderState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	states := make(map[string]*ProviderState)
	for name, state := range r.providerStates {
		// Create a copy to avoid race conditions
		stateCopy := *state
		states[name] = &stateCopy
	}
	
	return states
}

// GetHealthyProviders returns a list of currently healthy providers
func (r *Router) GetHealthyProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return r.getHealthyProviders()
}

// Close stops the router and cleanup resources
func (r *Router) Close() error {
	if r.healthTicker != nil {
		r.healthTicker.Stop()
	}
	
	close(r.stopChan)
	
	// Close all providers
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	for _, provider := range r.providers {
		provider.Close()
	}
	
	return nil
} 