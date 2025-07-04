package server

import (
	"context"
	"fmt"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
)

// ContextWrapper provides enhanced context management for AI Gateway operations
type ContextWrapper struct {
	timeoutHandler *TimeoutHandler
	requestTracker *RequestTracker
}

// RequestTracker tracks request metadata and timing
type RequestTracker struct {
	RequestID    string
	UserID       string
	SessionID    string
	StartTime    time.Time
	Operation    TimeoutOperation
	Provider     string
	Metadata     map[string]interface{}
}

// NewContextWrapper creates a new context wrapper
func NewContextWrapper(timeoutHandler *TimeoutHandler) *ContextWrapper {
	return &ContextWrapper{
		timeoutHandler: timeoutHandler,
	}
}

// WrapRequest wraps a request with timeout and tracking context
func (cw *ContextWrapper) WrapRequest(
	ctx context.Context,
	operation TimeoutOperation,
	metadata map[string]interface{},
) (context.Context, *RequestTracker, context.CancelFunc) {
	
	// Create timeout context
	timeoutCtx, timeoutCancel := cw.timeoutHandler.WithTimeout(ctx, operation)
	
	// Create request tracker
	tracker := &RequestTracker{
		RequestID: cw.generateRequestID(),
		StartTime: time.Now(),
		Operation: operation,
		Metadata:  metadata,
	}
	
	// Extract user info from context if available
	if userID, ok := ctx.Value("user_id").(string); ok {
		tracker.UserID = userID
	}
	if sessionID, ok := ctx.Value("session_id").(string); ok {
		tracker.SessionID = sessionID
	}
	
	// Add tracker to context
	wrappedCtx := context.WithValue(timeoutCtx, "request_tracker", tracker)
	cw.requestTracker = tracker
	
	// Monitor the context
	cw.timeoutHandler.MonitorContext(wrappedCtx, operation, func() {
		cw.onTimeout(tracker)
	})
	
	return wrappedCtx, tracker, timeoutCancel
}

// WrapProviderCall wraps a provider call with enhanced error handling
func (cw *ContextWrapper) WrapProviderCall(
	ctx context.Context,
	providerName string,
	fn func(context.Context) error,
) error {
	
	// Create provider operation context
	providerCtx, tracker, cancel := cw.WrapRequest(ctx, OperationProviderCall, map[string]interface{}{
		"provider": providerName,
	})
	defer cancel()
	
	tracker.Provider = providerName
	
	// Execute the provider function
	err := fn(providerCtx)
	
	// Handle any timeout or cancellation errors
	if providerCtx.Err() != nil {
		return cw.timeoutHandler.HandleTimeoutError(providerCtx, OperationProviderCall, err)
	}
	
	return err
}

// WrapChatCompletion wraps a chat completion request with full context handling
func (cw *ContextWrapper) WrapChatCompletion(
	ctx context.Context,
	request *interfaces.ChatCompletionRequest,
	fn func(context.Context, *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error),
) (*interfaces.ChatCompletionResponse, error) {
	
	// Create chat completion context
	chatCtx, tracker, cancel := cw.WrapRequest(ctx, OperationChatCompletion, map[string]interface{}{
		"model":      request.Model,
		"message_count": len(request.Messages),
		"stream":     request.Stream,
	})
	defer cancel()
	
	// Add request metadata
	request.RequestID = tracker.RequestID
	request.Timestamp = tracker.StartTime
	
	// Execute the chat completion
	response, err := fn(chatCtx, request)
	
	// Handle timeout/cancellation
	if chatCtx.Err() != nil {
		timeoutErr := cw.timeoutHandler.HandleTimeoutError(chatCtx, OperationChatCompletion, err)
		return nil, timeoutErr
	}
	
	// Add response metadata
	if response != nil {
		response.RequestID = tracker.RequestID
		response.ProcessingTimeMs = time.Since(tracker.StartTime).Milliseconds()
	}
	
	return response, err
}

// WrapStreamingCompletion wraps a streaming chat completion with timeout handling
func (cw *ContextWrapper) WrapStreamingCompletion(
	ctx context.Context,
	request *interfaces.ChatCompletionRequest,
	fn func(context.Context, *interfaces.ChatCompletionRequest) (<-chan *interfaces.ChatCompletionStreamResponse, error),
) (<-chan *interfaces.ChatCompletionStreamResponse, error) {
	
	// Create streaming context
	streamCtx, tracker, cancel := cw.WrapRequest(ctx, OperationStreaming, map[string]interface{}{
		"model":      request.Model,
		"message_count": len(request.Messages),
		"stream":     true,
	})
	
	// Add request metadata
	request.RequestID = tracker.RequestID
	request.Timestamp = tracker.StartTime
	
	// Execute the streaming function
	originalChan, err := fn(streamCtx, request)
	if err != nil {
		cancel()
		if streamCtx.Err() != nil {
			return nil, cw.timeoutHandler.HandleTimeoutError(streamCtx, OperationStreaming, err)
		}
		return nil, err
	}
	
	// Wrap the response channel with timeout handling
	wrappedChan := cw.timeoutHandler.StreamingTimeoutWrapper(streamCtx, originalChan, OperationStreaming)
	
	// Clean up when streaming is done
	go func() {
		defer cancel()
		// Wait for the wrapped channel to close
		for range wrappedChan {
			// Consume all responses until channel closes
		}
	}()
	
	return wrappedChan, nil
}

// WrapDatabaseOperation wraps database operations with timeout handling
func (cw *ContextWrapper) WrapDatabaseOperation(
	ctx context.Context,
	operation string,
	fn func(context.Context) error,
) error {
	
	dbCtx, _, cancel := cw.WrapRequest(ctx, OperationDatabaseQuery, map[string]interface{}{
		"operation": operation,
	})
	defer cancel()
	
	err := fn(dbCtx)
	
	if dbCtx.Err() != nil {
		return cw.timeoutHandler.HandleTimeoutError(dbCtx, OperationDatabaseQuery, err)
	}
	
	return err
}

// WrapCacheOperation wraps cache operations with timeout handling
func (cw *ContextWrapper) WrapCacheOperation(
	ctx context.Context,
	operation string,
	fn func(context.Context) error,
) error {
	
	cacheCtx, _, cancel := cw.WrapRequest(ctx, OperationCacheOp, map[string]interface{}{
		"operation": operation,
	})
	defer cancel()
	
	err := fn(cacheCtx)
	
	if cacheCtx.Err() != nil {
		return cw.timeoutHandler.HandleTimeoutError(cacheCtx, OperationCacheOp, err)
	}
	
	return err
}

// GetRequestTracker extracts request tracker from context
func (cw *ContextWrapper) GetRequestTracker(ctx context.Context) *RequestTracker {
	if tracker, ok := ctx.Value("request_tracker").(*RequestTracker); ok {
		return tracker
	}
	return nil
}

// UpdateTracker updates the request tracker with new information
func (cw *ContextWrapper) UpdateTracker(ctx context.Context, updates map[string]interface{}) {
	if tracker := cw.GetRequestTracker(ctx); tracker != nil {
		for key, value := range updates {
			if tracker.Metadata == nil {
				tracker.Metadata = make(map[string]interface{})
			}
			tracker.Metadata[key] = value
		}
	}
}

// CreateCancellableContext creates a context that can be canceled externally
func (cw *ContextWrapper) CreateCancellableContext(
	parent context.Context,
	operation TimeoutOperation,
) (context.Context, context.CancelFunc) {
	
	// Create a cancellable context first
	cancelCtx, cancelFunc := context.WithCancel(parent)
	
	// Then add timeout
	timeoutCtx, timeoutCancel := cw.timeoutHandler.WithTimeout(cancelCtx, operation)
	
	// Return a combined cancel function
	combinedCancel := func() {
		timeoutCancel()
		cancelFunc()
	}
	
	return timeoutCtx, combinedCancel
}

// HandleGracefulShutdown handles graceful shutdown with timeout
func (cw *ContextWrapper) HandleGracefulShutdown(cleanupFn func(context.Context) error) error {
	shutdownCtx, cancel := cw.timeoutHandler.GracefulShutdownContext()
	defer cancel()
	
	fmt.Println("Starting graceful shutdown...")
	
	done := make(chan error, 1)
	go func() {
		done <- cleanupFn(shutdownCtx)
	}()
	
	select {
	case err := <-done:
		if err != nil {
			fmt.Printf("Shutdown completed with error: %v\n", err)
		} else {
			fmt.Println("Graceful shutdown completed successfully")
		}
		return err
		
	case <-shutdownCtx.Done():
		fmt.Printf("Shutdown timed out after %v\n", cw.timeoutHandler.config.ShutdownTimeout)
		return fmt.Errorf("shutdown timed out")
	}
}

// RetryWithBackoff executes a function with exponential backoff and timeout handling
func (cw *ContextWrapper) RetryWithBackoff(
	ctx context.Context,
	operation TimeoutOperation,
	maxRetries int,
	initialDelay time.Duration,
	fn func(context.Context) error,
) error {
	
	var lastErr error
	delay := initialDelay
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Create timeout context for this attempt
		attemptCtx, _, cancel := cw.WrapRequest(ctx, operation, map[string]interface{}{
			"attempt": attempt + 1,
			"max_retries": maxRetries,
		})
		
		// Execute the function
		err := fn(attemptCtx)
		cancel()
		
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Check if parent context is done
		if ctx.Err() != nil {
			return cw.timeoutHandler.HandleTimeoutError(ctx, operation, ctx.Err())
		}
		
		// Check if it's a non-retryable error
		if providerErr, ok := err.(*interfaces.ProviderError); ok && !providerErr.IsRetryable() {
			return err
		}
		
		// Wait before retrying (except on last attempt)
		if attempt < maxRetries {
			select {
			case <-time.After(delay):
				delay *= 2 // Exponential backoff
				if delay > 30*time.Second {
					delay = 30 * time.Second // Cap at 30 seconds
				}
			case <-ctx.Done():
				return cw.timeoutHandler.HandleTimeoutError(ctx, operation, ctx.Err())
			}
		}
	}
	
	return lastErr
}

// generateRequestID generates a unique request ID
func (cw *ContextWrapper) generateRequestID() string {
	// In a real implementation, you'd use a proper UUID library
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// onTimeout is called when a request times out
func (cw *ContextWrapper) onTimeout(tracker *RequestTracker) {
	fmt.Printf("Request %s timed out after %v (operation: %s, provider: %s)\n",
		tracker.RequestID,
		time.Since(tracker.StartTime),
		tracker.Operation,
		tracker.Provider,
	)
	
	// Here you could add metrics collection, alerting, etc.
} 