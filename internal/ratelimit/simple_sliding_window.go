package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// SimpleSlidingWindowRateLimiter implements a simpler sliding window rate limiter
type SimpleSlidingWindowRateLimiter struct {
	redisClient *redis.Client
	config      *SlidingWindowConfig
	logger      *logrus.Logger
	metrics     *RateLimitMetrics
}

// NewSimpleSlidingWindowRateLimiter creates a new simple sliding window rate limiter
func NewSimpleSlidingWindowRateLimiter(redisClient *redis.Client, config *SlidingWindowConfig, logger *logrus.Logger) *SimpleSlidingWindowRateLimiter {
	if config == nil {
		config = getDefaultSlidingWindowConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	return &SimpleSlidingWindowRateLimiter{
		redisClient: redisClient,
		config:      config,
		logger:      logger,
		metrics:     &RateLimitMetrics{},
	}
}

// CheckRateLimit checks if a request is within rate limits using simplified sliding window
func (swrl *SimpleSlidingWindowRateLimiter) CheckRateLimit(ctx context.Context, request *RateLimitRequest, limit int64) (*RateLimitResult, error) {
	start := time.Now()
	
	// Generate Redis key for this rate limit check
	redisKey := swrl.generateRedisKey(request)
	
	// Get current time
	now := request.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	
	// Calculate window boundaries
	windowStart := now.Add(-swrl.config.WindowSize)
	
	// Use simplified Redis operations
	pipe := swrl.redisClient.Pipeline()
	
	// Remove old entries
	pipe.ZRemRangeByScore(ctx, redisKey, "0", strconv.FormatInt(windowStart.Unix(), 10))
	
	// Get current count
	countCmd := pipe.ZCard(ctx, redisKey)
	
	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline failed: %w", err)
	}
	
	currentCount := countCmd.Val()
	allowed := currentCount < limit
	
	if allowed {
		// Add current request
		err = swrl.redisClient.ZAdd(ctx, redisKey, redis.Z{
			Score:  float64(now.Unix()),
			Member: fmt.Sprintf("%d:%d", now.Unix(), request.TokenCount),
		}).Err()
		
		if err != nil {
			return nil, fmt.Errorf("failed to add request to window: %w", err)
		}
		
		// Set TTL
		swrl.redisClient.Expire(ctx, redisKey, swrl.config.KeyTTL)
		
		currentCount++
	}
	
	// Calculate metrics
	remaining := limit - currentCount
	if remaining < 0 {
		remaining = 0
	}
	
	resetTime := now.Add(swrl.config.WindowSize)
	windowUsage := float64(currentCount) / float64(limit) * 100
	
	var retryAfter time.Duration
	if !allowed {
		retryAfter = time.Duration(5) * time.Second // Simple retry after
	}
	
	result := &RateLimitResult{
		Allowed:      allowed,
		Limit:        limit,
		Remaining:    remaining,
		ResetTime:    resetTime,
		RetryAfter:   retryAfter,
		WindowUsage:  windowUsage,
		CurrentCount: currentCount,
		CheckLatency: time.Since(start),
	}
	
	// Add violation details if denied
	if !allowed {
		result.ViolationType = "rate_limit_exceeded"
		result.ViolationDetails = fmt.Sprintf("Request denied: %d/%d requests in window", currentCount, limit)
	}
	
	// Update metrics
	swrl.updateMetrics(result, time.Since(start))
	
	return result, nil
}

// generateRedisKey generates a Redis key for the rate limit check
func (swrl *SimpleSlidingWindowRateLimiter) generateRedisKey(request *RateLimitRequest) string {
	if request.Key != "" {
		return fmt.Sprintf("%s%s", swrl.config.RedisKeyPrefix, request.Key)
	}
	
	// Generate key based on user/org/endpoint
	return fmt.Sprintf("%suser:%s:endpoint:%s", swrl.config.RedisKeyPrefix, request.UserID, request.Endpoint)
}

// updateMetrics updates rate limiting metrics
func (swrl *SimpleSlidingWindowRateLimiter) updateMetrics(result *RateLimitResult, latency time.Duration) {
	if !swrl.config.EnableMetrics {
		return
	}
	
	swrl.metrics.TotalRequests++
	
	if result.Allowed {
		swrl.metrics.AllowedRequests++
	} else {
		swrl.metrics.DeniedRequests++
	}
	
	// Update latency metrics
	if swrl.metrics.TotalRequests == 1 {
		swrl.metrics.AverageLatency = latency
		swrl.metrics.MinLatency = latency
		swrl.metrics.MaxLatency = latency
	} else {
		// Update average latency
		totalTime := time.Duration(swrl.metrics.TotalRequests-1) * swrl.metrics.AverageLatency
		swrl.metrics.AverageLatency = (totalTime + latency) / time.Duration(swrl.metrics.TotalRequests)
		
		// Update min/max latency
		if latency < swrl.metrics.MinLatency {
			swrl.metrics.MinLatency = latency
		}
		if latency > swrl.metrics.MaxLatency {
			swrl.metrics.MaxLatency = latency
		}
	}
}

// GetMetrics returns current rate limiting metrics
func (swrl *SimpleSlidingWindowRateLimiter) GetMetrics() *RateLimitMetrics {
	metricsCopy := *swrl.metrics
	return &metricsCopy
} 