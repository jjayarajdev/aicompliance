package providers

import (
	"context"
	"testing"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
)

// MockProvider for testing the router
type MockRouterProvider struct {
	name      string
	healthy   bool
	latency   time.Duration
	shouldFail bool
	failureError error
}

func (m *MockRouterProvider) GetName() string {
	return m.name
}

func (m *MockRouterProvider) ChatCompletion(ctx context.Context, request *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error) {
	if m.shouldFail {
		return nil, m.failureError
	}
	
	// Simulate latency
	time.Sleep(m.latency)
	
	return &interfaces.ChatCompletionResponse{
		ID:       "test-" + m.name,
		Provider: m.name,
		Choices: []interfaces.Choice{
			{
				Message: interfaces.Message{
					Role:    "assistant",
					Content: "Response from " + m.name,
				},
			},
		},
	}, nil
}

func (m *MockRouterProvider) StreamChatCompletion(ctx context.Context, request *interfaces.ChatCompletionRequest) (<-chan *interfaces.ChatCompletionStreamResponse, error) {
	if m.shouldFail {
		return nil, m.failureError
	}
	
	ch := make(chan *interfaces.ChatCompletionStreamResponse, 1)
	go func() {
		defer close(ch)
		time.Sleep(m.latency)
		ch <- &interfaces.ChatCompletionStreamResponse{
			ID:       "test-stream-" + m.name,
			Provider: m.name,
			Done:     true,
		}
	}()
	return ch, nil
}

func (m *MockRouterProvider) ValidateCredentials(ctx context.Context) error {
	if !m.healthy {
		return &interfaces.ProviderError{
			Code:     interfaces.ErrorCodeServiceUnavailable,
			Message:  "Provider unhealthy",
			Provider: m.name,
		}
	}
	return nil
}

func (m *MockRouterProvider) GetModels(ctx context.Context) ([]interfaces.Model, error) {
	return []interfaces.Model{{ID: m.name + "-model"}}, nil
}

func (m *MockRouterProvider) GetUsage(ctx context.Context) (*interfaces.UsageStats, error) {
	return &interfaces.UsageStats{}, nil
}

func (m *MockRouterProvider) Close() error {
	return nil
}

func TestRouter_RoundRobinStrategy(t *testing.T) {
	config := &RouterConfig{
		Strategy:       StrategyRoundRobin,
		EnableFailover: true,
		MaxRetries:     2,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	// Add providers
	provider1 := &MockRouterProvider{name: "provider1", healthy: true, latency: 10 * time.Millisecond}
	provider2 := &MockRouterProvider{name: "provider2", healthy: true, latency: 20 * time.Millisecond}
	
	router.AddProvider("provider1", provider1)
	router.AddProvider("provider2", provider2)
	
	request := &interfaces.ChatCompletionRequest{
		Model: "test-model",
		Messages: []interfaces.Message{
			{Role: "user", Content: "Hello"},
		},
	}
	
	// Test round-robin selection
	providers := make(map[string]int)
	for i := 0; i < 10; i++ {
		response, err := router.RouteRequest(context.Background(), request)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		providers[response.Provider]++
	}
	
	// Should have roughly equal distribution
	if providers["provider1"] < 3 || providers["provider1"] > 7 {
		t.Errorf("Expected provider1 to be used 3-7 times, got %d", providers["provider1"])
	}
	if providers["provider2"] < 3 || providers["provider2"] > 7 {
		t.Errorf("Expected provider2 to be used 3-7 times, got %d", providers["provider2"])
	}
}

func TestRouter_LatencyBasedStrategy(t *testing.T) {
	config := &RouterConfig{
		Strategy:       StrategyLatencyBased,
		EnableFailover: true,
		MaxRetries:     2,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	// Add providers with different latencies
	fastProvider := &MockRouterProvider{name: "fast", healthy: true, latency: 10 * time.Millisecond}
	slowProvider := &MockRouterProvider{name: "slow", healthy: true, latency: 100 * time.Millisecond}
	
	router.AddProvider("fast", fastProvider)
	router.AddProvider("slow", slowProvider)
	
	request := &interfaces.ChatCompletionRequest{
		Model: "test-model",
		Messages: []interfaces.Message{
			{Role: "user", Content: "Hello"},
		},
	}
	
	// Make some initial requests to establish latency baselines
	for i := 0; i < 3; i++ {
		router.RouteRequest(context.Background(), request)
	}
	
	// Now test that the fast provider is preferred
	fastCount := 0
	for i := 0; i < 10; i++ {
		response, err := router.RouteRequest(context.Background(), request)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		if response.Provider == "fast" {
			fastCount++
		}
	}
	
	// Fast provider should be selected more often
	if fastCount < 6 {
		t.Errorf("Expected fast provider to be used at least 6 times, got %d", fastCount)
	}
}

func TestRouter_FailoverHandling(t *testing.T) {
	config := &RouterConfig{
		Strategy:       StrategyRoundRobin,
		EnableFailover: true,
		MaxRetries:     3,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	// Add one failing provider and one healthy provider
	failingProvider := &MockRouterProvider{
		name:       "failing",
		healthy:    true,
		shouldFail: true,
		failureError: &interfaces.ProviderError{
			Code:      interfaces.ErrorCodeServerError,
			Message:   "Server error",
			Provider:  "failing",
			Retryable: true,
		},
	}
	healthyProvider := &MockRouterProvider{name: "healthy", healthy: true}
	
	router.AddProvider("failing", failingProvider)
	router.AddProvider("healthy", healthyProvider)
	
	request := &interfaces.ChatCompletionRequest{
		Model: "test-model",
		Messages: []interfaces.Message{
			{Role: "user", Content: "Hello"},
		},
	}
	
	// Should eventually succeed with healthy provider
	response, err := router.RouteRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("Request should have succeeded through failover: %v", err)
	}
	
	if response.Provider != "healthy" {
		t.Errorf("Expected response from healthy provider, got %s", response.Provider)
	}
}

func TestRouter_CircuitBreaker(t *testing.T) {
	config := &RouterConfig{
		Strategy:                StrategyRoundRobin,
		EnableFailover:          false,
		MaxRetries:              1,
		CircuitBreakerEnabled:   true,
		CircuitBreakerThreshold: 2,
		CircuitBreakerWindow:    5 * time.Second,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	failingProvider := &MockRouterProvider{
		name:       "failing",
		healthy:    true,
		shouldFail: true,
		failureError: &interfaces.ProviderError{
			Code:      interfaces.ErrorCodeServerError,
			Message:   "Server error",
			Provider:  "failing",
			Retryable: true,
		},
	}
	
	router.AddProvider("failing", failingProvider)
	
	request := &interfaces.ChatCompletionRequest{
		Model: "test-model",
		Messages: []interfaces.Message{
			{Role: "user", Content: "Hello"},
		},
	}
	
	// Make requests to trigger circuit breaker
	for i := 0; i < 3; i++ {
		router.RouteRequest(context.Background(), request)
	}
	
	// Check provider state
	states := router.GetProviderStates()
	failingState := states["failing"]
	
	if !failingState.CircuitBreakerOpen {
		t.Error("Circuit breaker should be open after consecutive failures")
	}
	
	if failingState.ConsecutiveFailures < 2 {
		t.Errorf("Expected at least 2 consecutive failures, got %d", failingState.ConsecutiveFailures)
	}
}

func TestRouter_WeightedStrategy(t *testing.T) {
	config := &RouterConfig{
		Strategy: StrategyWeighted,
		WeightedProviders: []ProviderWeight{
			{ProviderName: "heavy", Weight: 3},
			{ProviderName: "light", Weight: 1},
		},
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	heavyProvider := &MockRouterProvider{name: "heavy", healthy: true}
	lightProvider := &MockRouterProvider{name: "light", healthy: true}
	
	router.AddProvider("heavy", heavyProvider)
	router.AddProvider("light", lightProvider)
	
	request := &interfaces.ChatCompletionRequest{
		Model: "test-model",
		Messages: []interfaces.Message{
			{Role: "user", Content: "Hello"},
		},
	}
	
	// Test weighted distribution
	providers := make(map[string]int)
	for i := 0; i < 20; i++ {
		response, err := router.RouteRequest(context.Background(), request)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		providers[response.Provider]++
	}
	
	// Heavy provider should be used more often (3:1 ratio)
	heavyRatio := float64(providers["heavy"]) / float64(providers["heavy"]+providers["light"])
	if heavyRatio < 0.6 || heavyRatio > 1.0 {
		t.Errorf("Expected heavy provider ratio to be 0.6-1.0, got %.2f (heavy: %d, light: %d)", heavyRatio, providers["heavy"], providers["light"])
	}
}

func TestRouter_StreamingRequests(t *testing.T) {
	config := &RouterConfig{
		Strategy:       StrategyRoundRobin,
		EnableFailover: true,
		MaxRetries:     2,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	provider := &MockRouterProvider{name: "streaming", healthy: true}
	router.AddProvider("streaming", provider)
	
	request := &interfaces.ChatCompletionRequest{
		Model: "test-model",
		Messages: []interfaces.Message{
			{Role: "user", Content: "Hello"},
		},
	}
	
	respChan, err := router.RouteStreamRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("Streaming request failed: %v", err)
	}
	
	// Read from stream
	var responses []*interfaces.ChatCompletionStreamResponse
	for response := range respChan {
		responses = append(responses, response)
	}
	
	if len(responses) == 0 {
		t.Error("Expected at least one streaming response")
	}
	
	if responses[len(responses)-1].Provider != "streaming" {
		t.Errorf("Expected response from streaming provider, got %s", responses[len(responses)-1].Provider)
	}
}

func TestRouter_HealthMonitoring(t *testing.T) {
	config := &RouterConfig{
		Strategy:            StrategyRoundRobin,
		HealthCheckInterval: 100 * time.Millisecond,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	provider := &MockRouterProvider{name: "test", healthy: true}
	router.AddProvider("test", provider)
	
	// Wait for initial health check
	time.Sleep(150 * time.Millisecond)
	
	states := router.GetProviderStates()
	testState := states["test"]
	
	if !testState.Healthy {
		t.Error("Provider should be healthy")
	}
	
	// Make provider unhealthy
	provider.healthy = false
	
	// Wait for health check to detect unhealthy state
	time.Sleep(150 * time.Millisecond)
	
	states = router.GetProviderStates()
	testState = states["test"]
	
	if testState.Healthy {
		t.Error("Provider should be unhealthy after health check")
	}
}

func TestRouter_HealthyProvidersOnly(t *testing.T) {
	config := &RouterConfig{
		Strategy:            StrategyRoundRobin,
		HealthCheckInterval: 50 * time.Millisecond,
	}
	
	router := NewRouter(config)
	defer router.Close()
	
	healthyProvider := &MockRouterProvider{name: "healthy", healthy: true}
	unhealthyProvider := &MockRouterProvider{name: "unhealthy", healthy: false}
	
	router.AddProvider("healthy", healthyProvider)
	router.AddProvider("unhealthy", unhealthyProvider)
	
	// Wait for health check to run
	time.Sleep(100 * time.Millisecond)
	
	healthyProviders := router.GetHealthyProviders()
	
	if len(healthyProviders) != 1 {
		t.Errorf("Expected 1 healthy provider, got %d: %v", len(healthyProviders), healthyProviders)
	}
	
	if len(healthyProviders) > 0 && healthyProviders[0] != "healthy" {
		t.Errorf("Expected 'healthy' provider, got %s", healthyProviders[0])
	}
} 