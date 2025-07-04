package main

import (
	"context"
	"fmt"
	"time"

	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/providers/interfaces"
	"ai-gateway-poc/internal/server"
)

// Simple demo showing timeout functionality
func main() {
	fmt.Println("🚀 AI Gateway Timeout Handler Demo")
	fmt.Println("==================================")
	
	// Create timeout configuration
	timeoutConfig := &config.TimeoutConfig{
		DefaultRequestTimeout:  3 * time.Second,
		ChatCompletionTimeout:  5 * time.Second,
		StreamingTimeout:       8 * time.Second,
		HealthCheckTimeout:     2 * time.Second,
		ShutdownTimeout:        10 * time.Second,
	}
	
	// Create timeout handler and context wrapper
	timeoutHandler := server.NewTimeoutHandler(timeoutConfig)
	contextWrapper := server.NewContextWrapper(timeoutHandler)
	
	// Demo 1: Basic timeout context creation
	fmt.Println("\n📋 Demo 1: Creating timeout contexts")
	ctx := context.Background()
	
	chatCtx, cancel1 := timeoutHandler.WithTimeout(ctx, server.OperationChatCompletion)
	deadline, ok := chatCtx.Deadline()
	if ok {
		fmt.Printf("✅ Chat completion timeout: %v\n", time.Until(deadline))
	}
	cancel1()
	
	streamCtx, cancel2 := timeoutHandler.WithTimeout(ctx, server.OperationStreaming)
	deadline, ok = streamCtx.Deadline()
	if ok {
		fmt.Printf("✅ Streaming timeout: %v\n", time.Until(deadline))
	}
	cancel2()
	
	// Demo 2: Timeout error handling
	fmt.Println("\n📋 Demo 2: Timeout error handling")
	timedOutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	time.Sleep(2 * time.Nanosecond) // Ensure timeout
	
	timeoutErr := timeoutHandler.HandleTimeoutError(timedOutCtx, server.OperationChatCompletion, context.DeadlineExceeded)
	if timeoutErr != nil {
		fmt.Printf("✅ Timeout error: %v\n", timeoutErr)
	}
	cancel()
	
	// Demo 3: Request tracking
	fmt.Println("\n📋 Demo 3: Request tracking")
	wrappedCtx, tracker, cancel3 := contextWrapper.WrapRequest(
		context.Background(),
		server.OperationChatCompletion,
		map[string]interface{}{
			"model": "demo-model",
			"user":  "demo-user",
		},
	)
	defer cancel3()
	
	fmt.Printf("✅ Request ID: %s\n", tracker.RequestID)
	fmt.Printf("✅ Operation: %s\n", tracker.Operation)
	fmt.Printf("✅ Start time: %v\n", tracker.StartTime)
	
	// Update tracker
	contextWrapper.UpdateTracker(wrappedCtx, map[string]interface{}{
		"status": "processing",
	})
	
	retrievedTracker := contextWrapper.GetRequestTracker(wrappedCtx)
	if retrievedTracker != nil {
		fmt.Printf("✅ Updated metadata: %+v\n", retrievedTracker.Metadata)
	}
	
	// Demo 4: Retry with backoff simulation
	fmt.Println("\n📋 Demo 4: Retry with backoff (simulation)")
	attempts := 0
	retryFn := func(ctx context.Context) error {
		attempts++
		fmt.Printf("🔄 Attempt %d\n", attempts)
		
		if attempts < 3 {
			return &interfaces.ProviderError{
				Code:      "temporary_error",
				Message:   "Simulated temporary error",
				Retryable: true,
			}
		}
		return nil // Success on third attempt
	}
	
	err := contextWrapper.RetryWithBackoff(
		context.Background(),
		server.OperationDefault,
		3,                        // max retries
		100*time.Millisecond,     // initial delay
		retryFn,
	)
	
	if err != nil {
		fmt.Printf("❌ Final error: %v\n", err)
	} else {
		fmt.Printf("✅ Operation succeeded after %d attempts\n", attempts)
	}
	
	// Demo 5: Graceful shutdown simulation
	fmt.Println("\n📋 Demo 5: Graceful shutdown (simulation)")
	cleanupFn := func(ctx context.Context) error {
		fmt.Println("🧹 Starting cleanup...")
		
		// Simulate cleanup work
		for i := 1; i <= 3; i++ {
			select {
			case <-time.After(200 * time.Millisecond):
				fmt.Printf("🧹 Cleanup step %d/3 completed\n", i)
			case <-ctx.Done():
				fmt.Println("🧹 Cleanup interrupted")
				return ctx.Err()
			}
		}
		
		fmt.Println("🧹 Cleanup completed")
		return nil
	}
	
	err = contextWrapper.HandleGracefulShutdown(cleanupFn)
	if err != nil {
		fmt.Printf("❌ Shutdown error: %v\n", err)
	} else {
		fmt.Printf("✅ Graceful shutdown completed\n")
	}
	
	fmt.Println("\n✅ Demo completed successfully!")
} 