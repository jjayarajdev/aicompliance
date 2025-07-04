package anthropic

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
)

// RateLimiter implements rate limiting for Anthropic requests
type RateLimiter struct {
	config         *interfaces.RateLimitConfig
	requestBucket  *TokenBucket
	tokenBucket    *TokenBucket
	mu             sync.RWMutex
	stopped        bool
	stopCh         chan struct{}
	cleanupTicker  *time.Ticker
}

// TokenBucket implements a token bucket for rate limiting
type TokenBucket struct {
	capacity    int64
	tokens      int64
	refillRate  int64 // tokens per minute
	lastRefill  time.Time
	mu          sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *interfaces.RateLimitConfig) *RateLimiter {
	if config == nil || !config.Enabled {
		return nil
	}

	rl := &RateLimiter{
		config: config,
		stopCh: make(chan struct{}),
	}

	// Initialize request bucket
	if config.RequestsPerMin > 0 {
		rl.requestBucket = &TokenBucket{
			capacity:   int64(config.BurstSize),
			tokens:     int64(config.BurstSize),
			refillRate: int64(config.RequestsPerMin),
			lastRefill: time.Now(),
		}

		// If burst size is not configured, use requests per minute
		if config.BurstSize == 0 {
			rl.requestBucket.capacity = int64(config.RequestsPerMin)
			rl.requestBucket.tokens = int64(config.RequestsPerMin)
		}
	}

	// Initialize token bucket
	if config.TokensPerMin > 0 {
		rl.tokenBucket = &TokenBucket{
			capacity:   int64(config.TokensPerMin * 2), // Allow burst of 2x rate
			tokens:     int64(config.TokensPerMin * 2),
			refillRate: int64(config.TokensPerMin),
			lastRefill: time.Now(),
		}
	}

	// Start cleanup routine
	if config.CleanupInterval > 0 {
		rl.cleanupTicker = time.NewTicker(config.CleanupInterval)
		go rl.cleanupRoutine()
	}

	return rl
}

// Wait waits for permission to make a request
func (rl *RateLimiter) Wait(ctx context.Context) error {
	return rl.WaitN(ctx, 1, 0)
}

// WaitN waits for permission to make a request that will consume n requests and tokens
func (rl *RateLimiter) WaitN(ctx context.Context, requests int64, tokens int64) error {
	if rl == nil || !rl.config.Enabled {
		return nil
	}

	rl.mu.RLock()
	if rl.stopped {
		rl.mu.RUnlock()
		return fmt.Errorf("rate limiter stopped")
	}
	rl.mu.RUnlock()

	// Check request rate limit
	if rl.requestBucket != nil && requests > 0 {
		if err := rl.waitForTokens(ctx, rl.requestBucket, requests); err != nil {
			return err
		}
	}

	// Check token rate limit
	if rl.tokenBucket != nil && tokens > 0 {
		if err := rl.waitForTokens(ctx, rl.tokenBucket, tokens); err != nil {
			return err
		}
	}

	return nil
}

// waitForTokens waits for the specified number of tokens to be available
func (rl *RateLimiter) waitForTokens(ctx context.Context, bucket *TokenBucket, tokens int64) error {
	for {
		// Check if we have enough tokens
		if bucket.tryConsume(tokens) {
			return nil
		}

		// Calculate wait time
		waitTime := bucket.timeUntilAvailable(tokens)
		if waitTime <= 0 {
			continue // Try again immediately
		}

		// Wait for tokens to be available or context cancellation
		timer := time.NewTimer(waitTime)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-rl.stopCh:
			timer.Stop()
			return fmt.Errorf("rate limiter stopped")
		case <-timer.C:
			// Continue loop to check again
		}
	}
}

// TryConsume attempts to consume the specified number of tokens without waiting
func (rl *RateLimiter) TryConsume(requests int64, tokens int64) bool {
	if rl == nil || !rl.config.Enabled {
		return true
	}

	rl.mu.RLock()
	if rl.stopped {
		rl.mu.RUnlock()
		return false
	}
	rl.mu.RUnlock()

	// Check request rate limit
	if rl.requestBucket != nil && requests > 0 {
		if !rl.requestBucket.tryConsume(requests) {
			return false
		}
	}

	// Check token rate limit
	if rl.tokenBucket != nil && tokens > 0 {
		if !rl.tokenBucket.tryConsume(tokens) {
			// Refund request tokens if we already consumed them
			if rl.requestBucket != nil && requests > 0 {
				rl.requestBucket.addTokens(requests)
			}
			return false
		}
	}

	return true
}

// GetStats returns current rate limiter statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	if rl == nil {
		return nil
	}

	stats := make(map[string]interface{})

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if rl.requestBucket != nil {
		rl.requestBucket.mu.Lock()
		rl.requestBucket.refill()
		stats["request_tokens_available"] = rl.requestBucket.tokens
		stats["request_tokens_capacity"] = rl.requestBucket.capacity
		stats["request_refill_rate"] = rl.requestBucket.refillRate
		rl.requestBucket.mu.Unlock()
	}

	if rl.tokenBucket != nil {
		rl.tokenBucket.mu.Lock()
		rl.tokenBucket.refill()
		stats["token_tokens_available"] = rl.tokenBucket.tokens
		stats["token_tokens_capacity"] = rl.tokenBucket.capacity
		stats["token_refill_rate"] = rl.tokenBucket.refillRate
		rl.tokenBucket.mu.Unlock()
	}

	return stats
}

// Stop stops the rate limiter
func (rl *RateLimiter) Stop() {
	if rl == nil {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.stopped {
		return
	}

	rl.stopped = true
	close(rl.stopCh)

	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
}

// cleanupRoutine performs periodic cleanup
func (rl *RateLimiter) cleanupRoutine() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			// Refill buckets
			if rl.requestBucket != nil {
				rl.requestBucket.mu.Lock()
				rl.requestBucket.refill()
				rl.requestBucket.mu.Unlock()
			}
			if rl.tokenBucket != nil {
				rl.tokenBucket.mu.Lock()
				rl.tokenBucket.refill()
				rl.tokenBucket.mu.Unlock()
			}
		case <-rl.stopCh:
			return
		}
	}
}

// Token bucket methods

// tryConsume attempts to consume the specified number of tokens
func (tb *TokenBucket) tryConsume(tokens int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= tokens {
		tb.tokens -= tokens
		return true
	}

	return false
}

// addTokens adds tokens back to the bucket (for refunds)
func (tb *TokenBucket) addTokens(tokens int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens += tokens
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
}

// refill refills the bucket based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	
	if elapsed <= 0 {
		return
	}

	// Calculate tokens to add based on elapsed time
	tokensToAdd := int64(elapsed.Minutes() * float64(tb.refillRate))
	
	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}
}

// timeUntilAvailable calculates time until the specified number of tokens are available
func (tb *TokenBucket) timeUntilAvailable(tokens int64) time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= tokens {
		return 0
	}

	tokensNeeded := tokens - tb.tokens
	if tb.refillRate <= 0 {
		return time.Hour // Very long time if no refill rate
	}

	// Calculate time needed to get required tokens
	minutesNeeded := float64(tokensNeeded) / float64(tb.refillRate)
	return time.Duration(minutesNeeded * float64(time.Minute))
}

// GetAvailable returns the number of tokens currently available
func (tb *TokenBucket) GetAvailable() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.tokens
}

// GetCapacity returns the bucket capacity
func (tb *TokenBucket) GetCapacity() int64 {
	return tb.capacity
} 