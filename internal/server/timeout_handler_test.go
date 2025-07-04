package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/providers/interfaces"
)

func TestDefaultTimeoutConfig(t *testing.T) {
	timeoutConfig := config.DefaultTimeoutConfig()
	
	if timeoutConfig.DefaultRequestTimeout != 30*time.Second {
		t.Errorf("Expected default request timeout 30s, got %v", timeoutConfig.DefaultRequestTimeout)
	}
	
	if timeoutConfig.ChatCompletionTimeout != 60*time.Second {
		t.Errorf("Expected chat completion timeout 60s, got %v", timeoutConfig.ChatCompletionTimeout)
	}
	
	if timeoutConfig.StreamingTimeout != 300*time.Second {
		t.Errorf("Expected streaming timeout 300s, got %v", timeoutConfig.StreamingTimeout)
	}
}

func TestTimeoutHandler_WithTimeout(t *testing.T) {
	handler := NewTimeoutHandler(nil)
	
	ctx := context.Background()
	timeoutCtx, cancel := handler.WithTimeout(ctx, OperationChatCompletion)
	defer cancel()
	
	deadline, ok := timeoutCtx.Deadline()
	if !ok {
		t.Error("Expected context to have a deadline")
	}
	
	expectedDeadline := time.Now().Add(60 * time.Second)
	if deadline.Before(expectedDeadline.Add(-1*time.Second)) || deadline.After(expectedDeadline.Add(1*time.Second)) {
		t.Errorf("Deadline not within expected range. Got: %v, Expected around: %v", deadline, expectedDeadline)
	}
}

func TestTimeoutHandler_HandleTimeoutError(t *testing.T) {
	handler := NewTimeoutHandler(nil)
	
	tests := []struct {
		name      string
		ctxErr    error
		operation TimeoutOperation
		wantCode  string
		wantRetryable bool
	}{
		{
			name:      "deadline exceeded",
			ctxErr:    context.DeadlineExceeded,
			operation: OperationChatCompletion,
			wantCode:  interfaces.ErrorCodeTimeout,
			wantRetryable: true,
		},
		{
			name:      "context canceled",
			ctxErr:    context.Canceled,
			operation: OperationChatCompletion,
			wantCode:  "request_canceled",
			wantRetryable: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tt.ctxErr == context.DeadlineExceeded {
				ctx, cancel = context.WithTimeout(context.Background(), 1*time.Nanosecond)
				time.Sleep(2 * time.Nanosecond) // Ensure timeout
			} else if tt.ctxErr == context.Canceled {
				cancel()
			}
			defer cancel()
			
			err := handler.HandleTimeoutError(ctx, tt.operation, tt.ctxErr)
			
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			
			providerErr, ok := err.(*interfaces.ProviderError)
			if !ok {
				t.Fatalf("Expected ProviderError, got %T", err)
			}
			
			if providerErr.Code != tt.wantCode {
				t.Errorf("Expected code %s, got %s", tt.wantCode, providerErr.Code)
			}
			
			if providerErr.Retryable != tt.wantRetryable {
				t.Errorf("Expected retryable %v, got %v", tt.wantRetryable, providerErr.Retryable)
			}
		})
	}
}

func TestTimeoutHandler_HTTPTimeoutMiddleware(t *testing.T) {
	handler := NewTimeoutHandler(&config.TimeoutConfig{
		DefaultRequestTimeout: 100 * time.Millisecond,
	})
	
	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Longer than timeout
		w.WriteHeader(http.StatusOK)
	})
	
	middleware := handler.HTTPTimeoutMiddleware(slowHandler)
	
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	
	middleware.ServeHTTP(rr, req)
	
	if rr.Code != http.StatusGatewayTimeout {
		t.Errorf("Expected status %d, got %d", http.StatusGatewayTimeout, rr.Code)
	}
	
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", rr.Header().Get("Content-Type"))
	}
}

func TestTimeoutHandler_StreamingTimeoutWrapper(t *testing.T) {
	handler := NewTimeoutHandler(&config.TimeoutConfig{
		StreamingTimeout: 100 * time.Millisecond,
	})
	
	// Create a slow streaming channel
	originalChan := make(chan *interfaces.ChatCompletionStreamResponse, 1)
	
	ctx := context.Background()
	wrappedChan := handler.StreamingTimeoutWrapper(ctx, originalChan, OperationStreaming)
	
	// Start a goroutine that will send data after the timeout
	go func() {
		time.Sleep(200 * time.Millisecond) // Longer than timeout
		originalChan <- &interfaces.ChatCompletionStreamResponse{
			ID: "test",
		}
		close(originalChan)
	}()
	
	// Read from wrapped channel
	var responses []*interfaces.ChatCompletionStreamResponse
	for response := range wrappedChan {
		responses = append(responses, response)
	}
	
	// Should receive timeout error
	if len(responses) != 1 {
		t.Fatalf("Expected 1 response (timeout error), got %d", len(responses))
	}
	
	if responses[0].Error == nil {
		t.Error("Expected timeout error in response")
	}
	
	if !responses[0].Done {
		t.Error("Expected response to be marked as done")
	}
}

func TestTimeoutHandler_RetryWithTimeout(t *testing.T) {
	handler := NewTimeoutHandler(&config.TimeoutConfig{
		DefaultRequestTimeout: 50 * time.Millisecond,
	})
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return &interfaces.ProviderError{
				Code:      "temporary_error",
				Message:   "Temporary error",
				Retryable: true,
			}
		}
		return nil // Success on third attempt
	}
	
	ctx := context.Background()
	err := handler.RetryWithTimeout(ctx, OperationDefault, 3, 10*time.Millisecond, fn)
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestTimeoutHandler_RetryWithTimeout_NonRetryableError(t *testing.T) {
	handler := NewTimeoutHandler(nil)
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		return &interfaces.ProviderError{
			Code:      "non_retryable_error",
			Message:   "Non-retryable error",
			Retryable: false,
		}
	}
	
	ctx := context.Background()
	err := handler.RetryWithTimeout(ctx, OperationDefault, 3, 10*time.Millisecond, fn)
	
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if attempts != 1 {
		t.Errorf("Expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestTimeoutHandler_getOperationFromPath(t *testing.T) {
	handler := NewTimeoutHandler(nil)
	
	tests := []struct {
		path     string
		expected TimeoutOperation
	}{
		{"/v1/chat/completions", OperationChatCompletion},
		{"/v1/chat/completions/stream", OperationStreaming},
		{"/health", OperationHealthCheck},
		{"/healthz", OperationHealthCheck},
		{"/unknown", OperationDefault},
	}
	
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := handler.getOperationFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestTimeoutHandler_GracefulShutdownContext(t *testing.T) {
	handler := NewTimeoutHandler(&config.TimeoutConfig{
		ShutdownTimeout: 100 * time.Millisecond,
	})
	
	ctx, cancel := handler.GracefulShutdownContext()
	defer cancel()
	
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("Expected shutdown context to have a deadline")
	}
	
	expectedDeadline := time.Now().Add(100 * time.Millisecond)
	if deadline.Before(expectedDeadline.Add(-10*time.Millisecond)) || deadline.After(expectedDeadline.Add(10*time.Millisecond)) {
		t.Errorf("Shutdown deadline not within expected range. Got: %v, Expected around: %v", deadline, expectedDeadline)
	}
}

func TestTimeoutHandler_MonitorContext(t *testing.T) {
	handler := NewTimeoutHandler(nil)
	
	timeoutCalled := false
	onTimeout := func() {
		timeoutCalled = true
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	handler.MonitorContext(ctx, OperationDefault, onTimeout)
	
	// Wait for timeout
	time.Sleep(100 * time.Millisecond)
	
	if !timeoutCalled {
		t.Error("Expected timeout callback to be called")
	}
}

// Benchmark tests
func BenchmarkTimeoutHandler_WithTimeout(b *testing.B) {
	handler := NewTimeoutHandler(nil)
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		timeoutCtx, cancel := handler.WithTimeout(ctx, OperationChatCompletion)
		cancel()
		_ = timeoutCtx
	}
}

func BenchmarkTimeoutHandler_HandleTimeoutError(b *testing.B) {
	handler := NewTimeoutHandler(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	
	time.Sleep(2 * time.Nanosecond) // Ensure timeout
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := handler.HandleTimeoutError(ctx, OperationChatCompletion, context.DeadlineExceeded)
		_ = err
	}
} 