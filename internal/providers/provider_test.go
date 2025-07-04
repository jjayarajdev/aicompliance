package providers

import (
	"testing"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
)

// Simple test to verify provider system works
func TestProviderSystemBasics(t *testing.T) {
	// Test that we can create provider configs
	config := &interfaces.ProviderConfig{
		Name:         "test-provider",
		APIKey:       "test-key",
		BaseURL:      "https://api.test.com",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		DefaultModel: "test-model",
	}

	if config.Name != "test-provider" {
		t.Errorf("Expected name 'test-provider', got '%s'", config.Name)
	}

	// Test that we can create chat completion requests
	request := &interfaces.ChatCompletionRequest{
		Model: "gpt-3.5-turbo",
		Messages: []interfaces.Message{
			{
				Role:    "user",
				Content: "Hello world",
			},
		},
		RequestID: "test-123",
	}

	if len(request.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(request.Messages))
	}

	if request.Messages[0].Content != "Hello world" {
		t.Errorf("Expected content 'Hello world', got '%s'", request.Messages[0].Content)
	}

	// Test error creation
	err := &interfaces.ProviderError{
		Code:     interfaces.ErrorCodeInvalidAPIKey,
		Message:  "Invalid API key",
		Provider: "test",
		Retryable: false,
	}

	if !err.IsAuthenticationError() {
		t.Error("Expected authentication error")
	}

	if err.IsRetryable() {
		t.Error("Expected non-retryable error")
	}
}

func TestProviderMetrics(t *testing.T) {
	metrics := &interfaces.ProviderMetrics{
		TotalRequests:      100,
		SuccessfulRequests: 95,
		FailedRequests:     5,
		TotalTokens:        10000,
		TotalCost:          5.50,
		ErrorsByCode:       make(map[string]int64),
	}

	metrics.ErrorsByCode[interfaces.ErrorCodeRateLimitExceeded] = 3
	metrics.ErrorsByCode[interfaces.ErrorCodeServerError] = 2

	if metrics.TotalRequests != 100 {
		t.Errorf("Expected 100 total requests, got %d", metrics.TotalRequests)
	}

	if metrics.ErrorsByCode[interfaces.ErrorCodeRateLimitExceeded] != 3 {
		t.Errorf("Expected 3 rate limit errors, got %d", metrics.ErrorsByCode[interfaces.ErrorCodeRateLimitExceeded])
	}
} 