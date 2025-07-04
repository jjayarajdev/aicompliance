package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/providers/interfaces"
)



// TimeoutHandler provides context-aware timeout management
type TimeoutHandler struct {
	config *config.TimeoutConfig
}

// NewTimeoutHandler creates a new timeout handler
func NewTimeoutHandler(timeoutConfig *config.TimeoutConfig) *TimeoutHandler {
	if timeoutConfig == nil {
		timeoutConfig = config.DefaultTimeoutConfig()
	}
	return &TimeoutHandler{config: timeoutConfig}
}

// TimeoutOperation represents different types of operations that can timeout
type TimeoutOperation string

const (
	OperationChatCompletion TimeoutOperation = "chat_completion"
	OperationStreaming      TimeoutOperation = "streaming"
	OperationHealthCheck    TimeoutOperation = "health_check"
	OperationDatabaseQuery  TimeoutOperation = "database_query"
	OperationCacheOp        TimeoutOperation = "cache_operation"
	OperationProviderCall   TimeoutOperation = "provider_call"
	OperationDefault        TimeoutOperation = "default"
)

// WithTimeout creates a context with timeout for the specified operation
func (th *TimeoutHandler) WithTimeout(ctx context.Context, operation TimeoutOperation) (context.Context, context.CancelFunc) {
	timeout := th.getTimeoutForOperation(operation)
	return context.WithTimeout(ctx, timeout)
}

// WithDeadline creates a context with a specific deadline
func (th *TimeoutHandler) WithDeadline(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, deadline)
}

// WithTimeoutDuration creates a context with a custom timeout duration
func (th *TimeoutHandler) WithTimeoutDuration(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// getTimeoutForOperation returns the appropriate timeout for an operation
func (th *TimeoutHandler) getTimeoutForOperation(operation TimeoutOperation) time.Duration {
	switch operation {
	case OperationChatCompletion:
		return th.config.ChatCompletionTimeout
	case OperationStreaming:
		return th.config.StreamingTimeout
	case OperationHealthCheck:
		return th.config.HealthCheckTimeout
	case OperationDatabaseQuery:
		return th.config.DatabaseQueryTimeout
	case OperationCacheOp:
		return th.config.CacheOperationTimeout
	case OperationProviderCall:
		return th.config.ProviderConnectTimeout + th.config.ProviderReadTimeout
	default:
		return th.config.DefaultRequestTimeout
	}
}

// HandleTimeoutError creates appropriate error responses for timeout scenarios
func (th *TimeoutHandler) HandleTimeoutError(ctx context.Context, operation TimeoutOperation, err error) *interfaces.ProviderError {
	if ctx.Err() == context.DeadlineExceeded {
		return &interfaces.ProviderError{
			Code:     interfaces.ErrorCodeTimeout,
			Message:  fmt.Sprintf("Operation %s timed out after %v", operation, th.getTimeoutForOperation(operation)),
			Type:     "timeout_error",
			Provider: "gateway",
			Retryable: true,
			OriginalError: err,
		}
	}
	
	if ctx.Err() == context.Canceled {
		return &interfaces.ProviderError{
			Code:     "request_canceled",
			Message:  fmt.Sprintf("Operation %s was canceled", operation),
			Type:     "cancellation_error", 
			Provider: "gateway",
			Retryable: false,
			OriginalError: err,
		}
	}
	
	// If it's not a context error, wrap the original error
	if err != nil {
		return &interfaces.ProviderError{
			Code:     interfaces.ErrorCodeUnknownError,
			Message:  fmt.Sprintf("Operation %s failed: %v", operation, err),
			Type:     "operation_error",
			Provider: "gateway",
			Retryable: false,
			OriginalError: err,
		}
	}
	
	return nil
}

// HTTPTimeoutMiddleware provides HTTP-level timeout handling
func (th *TimeoutHandler) HTTPTimeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Create a context with timeout based on the request path
		operation := th.getOperationFromPath(r.URL.Path)
		ctx, cancel := th.WithTimeout(r.Context(), operation)
		defer cancel()
		
		// Create a new request with the timeout context
		r = r.WithContext(ctx)
		
		// Use a channel to handle the response
		done := make(chan struct{})
		var panicErr interface{}
		
		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicErr = p
				}
				close(done)
			}()
			next.ServeHTTP(w, r)
		}()
		
		select {
		case <-done:
			// Request completed normally
			if panicErr != nil {
				panic(panicErr) // Re-panic if there was a panic
			}
			
		case <-ctx.Done():
			// Request timed out or was canceled
			if ctx.Err() == context.DeadlineExceeded {
				th.writeTimeoutResponse(w, operation)
			} else if ctx.Err() == context.Canceled {
				th.writeCanceledResponse(w, operation)
			}
		}
	})
}

// getOperationFromPath determines the operation type based on the request path
func (th *TimeoutHandler) getOperationFromPath(path string) TimeoutOperation {
	switch {
	case path == "/v1/chat/completions":
		return OperationChatCompletion
	case path == "/v1/chat/completions/stream":
		return OperationStreaming
	case path == "/health" || path == "/healthz":
		return OperationHealthCheck
	default:
		return OperationDefault
	}
}

// writeTimeoutResponse writes an HTTP timeout response
func (th *TimeoutHandler) writeTimeoutResponse(w http.ResponseWriter, operation TimeoutOperation) {
	timeout := th.getTimeoutForOperation(operation)
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGatewayTimeout)
	
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"code":      "timeout",
			"message":   fmt.Sprintf("Request timed out after %v", timeout),
			"type":      "timeout_error",
			"operation": string(operation),
		},
		"timestamp": time.Now().Unix(),
	}
	
	// Try to write response, but don't panic if it fails (connection might be closed)
	if err := writeJSONResponse(w, response); err != nil {
		// Log the error but don't fail - connection might already be closed
	}
}

// writeCanceledResponse writes an HTTP cancellation response
func (th *TimeoutHandler) writeCanceledResponse(w http.ResponseWriter, operation TimeoutOperation) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusRequestTimeout)
	
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"code":      "canceled",
			"message":   "Request was canceled",
			"type":      "cancellation_error",
			"operation": string(operation),
		},
		"timestamp": time.Now().Unix(),
	}
	
	writeJSONResponse(w, response)
}

// GracefulShutdownContext creates a context for graceful shutdown
func (th *TimeoutHandler) GracefulShutdownContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), th.config.ShutdownTimeout)
}

// StreamingTimeoutWrapper wraps a streaming response channel with timeout handling
func (th *TimeoutHandler) StreamingTimeoutWrapper(
	ctx context.Context,
	originalChan <-chan *interfaces.ChatCompletionStreamResponse,
	operation TimeoutOperation,
) <-chan *interfaces.ChatCompletionStreamResponse {
	
	wrappedChan := make(chan *interfaces.ChatCompletionStreamResponse, 10)
	
	go func() {
		defer close(wrappedChan)
		
		// Create a timeout context for the streaming operation
		streamCtx, cancel := th.WithTimeout(ctx, operation)
		defer cancel()
		
		for {
			select {
			case response, ok := <-originalChan:
				if !ok {
					// Original channel closed normally
					return
				}
				
				select {
				case wrappedChan <- response:
					// Response sent successfully
				case <-streamCtx.Done():
					// Timeout while sending response
					th.sendStreamTimeoutError(wrappedChan, streamCtx, operation)
					return
				}
				
			case <-streamCtx.Done():
				// Timeout while waiting for response
				th.sendStreamTimeoutError(wrappedChan, streamCtx, operation)
				return
			}
		}
	}()
	
	return wrappedChan
}

// sendStreamTimeoutError sends a timeout error through the streaming channel
func (th *TimeoutHandler) sendStreamTimeoutError(
	ch chan<- *interfaces.ChatCompletionStreamResponse,
	ctx context.Context,
	operation TimeoutOperation,
) {
	timeoutErr := th.HandleTimeoutError(ctx, operation, ctx.Err())
	
	errorResponse := &interfaces.ChatCompletionStreamResponse{
		Error: &interfaces.StreamError{
			Code:    timeoutErr.Code,
			Message: timeoutErr.Message,
			Type:    timeoutErr.Type,
		},
		Done: true,
	}
	
	select {
	case ch <- errorResponse:
		// Error sent successfully
	default:
		// Channel might be full or closed, skip
	}
}

// RetryWithTimeout executes a function with retries and timeout handling
func (th *TimeoutHandler) RetryWithTimeout(
	ctx context.Context,
	operation TimeoutOperation,
	maxRetries int,
	retryDelay time.Duration,
	fn func(context.Context) error,
) error {
	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Create timeout context for this attempt
		attemptCtx, cancel := th.WithTimeout(ctx, operation)
		
		// Execute the function
		err := fn(attemptCtx)
		cancel() // Always cancel the timeout context
		
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Check if it's a timeout error
		if attemptCtx.Err() == context.DeadlineExceeded {
			// Don't retry timeout errors on the last attempt
			if attempt == maxRetries {
				return th.HandleTimeoutError(attemptCtx, operation, err)
			}
		}
		
		// Check if the parent context is done
		if ctx.Err() != nil {
			return th.HandleTimeoutError(ctx, operation, ctx.Err())
		}
		
		// Wait before retrying (except on last attempt)
		if attempt < maxRetries {
			select {
			case <-time.After(retryDelay):
				// Continue to next attempt
			case <-ctx.Done():
				return th.HandleTimeoutError(ctx, operation, ctx.Err())
			}
		}
	}
	
	return lastErr
}

// MonitorContext monitors a context and logs when it times out or is canceled
func (th *TimeoutHandler) MonitorContext(ctx context.Context, operation TimeoutOperation, onTimeout func()) {
	go func() {
		<-ctx.Done()
		
		if ctx.Err() == context.DeadlineExceeded {
			// Log timeout
			fmt.Printf("Operation %s timed out after %v\n", operation, th.getTimeoutForOperation(operation))
			if onTimeout != nil {
				onTimeout()
			}
		} else if ctx.Err() == context.Canceled {
			// Log cancellation
			fmt.Printf("Operation %s was canceled\n", operation)
		}
	}()
}

// Helper function to write JSON response safely
func writeJSONResponse(w http.ResponseWriter, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		// Fallback to simple error message
		jsonData = []byte(`{"error": {"code": "json_marshal_error", "message": "Failed to serialize response"}}`)
	}
	
	_, writeErr := w.Write(jsonData)
	return writeErr
} 