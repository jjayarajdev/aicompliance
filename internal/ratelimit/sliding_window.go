package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// SlidingWindowRateLimiter implements distributed sliding window rate limiting using Redis
type SlidingWindowRateLimiter struct {
	redisClient *redis.Client
	config      *SlidingWindowConfig
	logger      *logrus.Logger
	metrics     *RateLimitMetrics
	mu          sync.RWMutex
}

// SlidingWindowConfig holds sliding window rate limiter configuration
type SlidingWindowConfig struct {
	// Redis configuration
	RedisKeyPrefix    string        `json:"redis_key_prefix" yaml:"redis_key_prefix"`
	KeyTTL           time.Duration `json:"key_ttl" yaml:"key_ttl"`
	
	// Window configuration
	WindowSize       time.Duration `json:"window_size" yaml:"window_size"`
	SubWindowCount   int           `json:"sub_window_count" yaml:"sub_window_count"`
	
	// Performance settings
	MaxConcurrency   int           `json:"max_concurrency" yaml:"max_concurrency"`
	CleanupInterval  time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	
	// Logging and monitoring
	EnableMetrics    bool          `json:"enable_metrics" yaml:"enable_metrics"`
	LogViolations    bool          `json:"log_violations" yaml:"log_violations"`
}

// RateLimitRequest represents a rate limit check request
type RateLimitRequest struct {
	Key        string            `json:"key"`         // Unique identifier (user:endpoint, org:global, etc.)
	UserID     string            `json:"user_id"`     // User identifier
	OrgID      string            `json:"org_id"`      // Organization identifier
	Endpoint   string            `json:"endpoint"`    // API endpoint
	Method     string            `json:"method"`      // HTTP method
	ClientIP   string            `json:"client_ip"`   // Client IP address
	UserAgent  string            `json:"user_agent"`  // User agent
	Metadata   map[string]string `json:"metadata"`    // Additional metadata
	TokenCount int64             `json:"token_count"` // Number of tokens to consume
	Timestamp  time.Time         `json:"timestamp"`   // Request timestamp
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed           bool          `json:"allowed"`
	Limit             int64         `json:"limit"`              // Rate limit threshold
	Remaining         int64         `json:"remaining"`          // Remaining requests in window
	ResetTime         time.Time     `json:"reset_time"`         // When the window resets
	RetryAfter        time.Duration `json:"retry_after"`        // Time to wait before retrying
	WindowUsage       float64       `json:"window_usage"`       // Usage percentage of window
	CurrentCount      int64         `json:"current_count"`      // Current count in window
	SubWindowBreakdown []SubWindow  `json:"sub_window_breakdown"` // Breakdown by sub-windows
	
	// Violation details
	ViolationType     string        `json:"violation_type,omitempty"`     // Type of violation
	ViolationDetails  string        `json:"violation_details,omitempty"`  // Detailed violation info
	
	// Performance metrics
	CheckLatency      time.Duration `json:"check_latency"`      // Time taken for check
	ProcessingTime    time.Time     `json:"processing_time"`    // When processed
}

// SubWindow represents a sub-window in the sliding window
type SubWindow struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Count     int64     `json:"count"`
	TokenSum  int64     `json:"token_sum"`
}

// RateLimitMetrics tracks rate limiting performance and statistics
type RateLimitMetrics struct {
	// Request metrics
	TotalRequests     int64 `json:"total_requests"`
	AllowedRequests   int64 `json:"allowed_requests"`
	DeniedRequests    int64 `json:"denied_requests"`
	
	// Performance metrics
	AverageLatency    time.Duration `json:"average_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	MinLatency        time.Duration `json:"min_latency"`
	
	// Window metrics
	ActiveWindows     int64 `json:"active_windows"`
	WindowHits        int64 `json:"window_hits"`
	WindowMisses      int64 `json:"window_misses"`
	
	// Error metrics
	RedisErrors       int64 `json:"redis_errors"`
	TimeoutErrors     int64 `json:"timeout_errors"`
	ProcessingErrors  int64 `json:"processing_errors"`
	
	// Rate limit violations
	UserViolations    int64 `json:"user_violations"`
	OrgViolations     int64 `json:"org_violations"`
	IPViolations      int64 `json:"ip_violations"`
	
	mu sync.RWMutex
}

// NewSlidingWindowRateLimiter creates a new sliding window rate limiter
func NewSlidingWindowRateLimiter(redisClient *redis.Client, config *SlidingWindowConfig, logger *logrus.Logger) *SlidingWindowRateLimiter {
	if config == nil {
		config = getDefaultSlidingWindowConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	swrl := &SlidingWindowRateLimiter{
		redisClient: redisClient,
		config:      config,
		logger:      logger,
		metrics:     &RateLimitMetrics{},
	}
	
	// Start background cleanup if configured
	if config.CleanupInterval > 0 {
		go swrl.startCleanupWorker()
	}
	
	return swrl
}

// CheckRateLimit checks if a request is within rate limits using sliding window algorithm
func (swrl *SlidingWindowRateLimiter) CheckRateLimit(ctx context.Context, request *RateLimitRequest, limit int64) (*RateLimitResult, error) {
	start := time.Now()
	
	// Generate Redis key for this rate limit check
	redisKey := swrl.generateRedisKey(request)
	
	// Execute sliding window algorithm
	result, err := swrl.executeSlidingWindowCheck(ctx, redisKey, request, limit)
	if err != nil {
		swrl.recordError("processing")
		return nil, fmt.Errorf("sliding window check failed: %w", err)
	}
	
	// Update metrics
	swrl.updateMetrics(result, time.Since(start))
	
	// Log violations if enabled
	if swrl.config.LogViolations && !result.Allowed {
		swrl.logViolation(request, result)
	}
	
	result.CheckLatency = time.Since(start)
	result.ProcessingTime = time.Now()
	
	return result, nil
}

// executeSlidingWindowCheck performs the core sliding window algorithm
func (swrl *SlidingWindowRateLimiter) executeSlidingWindowCheck(ctx context.Context, redisKey string, request *RateLimitRequest, limit int64) (*RateLimitResult, error) {
	now := request.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	
	// Calculate window boundaries
	windowSize := swrl.config.WindowSize
	subWindowSize := windowSize / time.Duration(swrl.config.SubWindowCount)
	// windowStart := now.Truncate(subWindowSize).Add(-windowSize + subWindowSize) // Calculated in Lua script
	
	// Use Redis Lua script for atomic sliding window operation
	luaScript := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_size = tonumber(ARGV[2])
		local sub_window_size = tonumber(ARGV[3])
		local sub_window_count = tonumber(ARGV[4])
		local limit = tonumber(ARGV[5])
		local token_count = tonumber(ARGV[6])
		local ttl = tonumber(ARGV[7])
		
		-- Validate inputs to prevent NaN/Inf
		if not now or not window_size or not sub_window_size or not limit then
			return redis.error_reply("Invalid arguments")
		end
		
		if sub_window_size <= 0 then
			return redis.error_reply("Invalid sub_window_size")
		end
		
		-- Calculate window boundaries
		local window_start = now - window_size
		
		-- Clean old sub-windows
		redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
		
		-- Get current count in window - simplified approach
		local current_count = redis.call('ZCARD', key) or 0
		local token_sum = 0
		
		-- Check if adding this request would exceed limit
		local new_count = current_count + 1
		local allowed = new_count <= limit
		
		if allowed then
			-- Add current request with current timestamp as score
			redis.call('ZADD', key, now, now .. ":" .. token_count)
			
			-- Set TTL
			redis.call('EXPIRE', key, ttl)
		end
		
		-- Calculate remaining and reset time
		local remaining = math.max(0, limit - new_count)
		local reset_time = now + window_size
		
		return {
			allowed and 1 or 0,
			current_count,
			token_sum,
			remaining,
			reset_time,
			limit
		}
	`
	
	// Prepare script arguments
	args := []interface{}{
		now.Unix(),                                    // current timestamp
		int64(windowSize.Seconds()),                   // window size in seconds
		int64(subWindowSize.Seconds()),                // sub-window size in seconds
		swrl.config.SubWindowCount,                    // number of sub-windows
		limit,                                         // rate limit
		request.TokenCount,                            // tokens to consume
		int64(swrl.config.KeyTTL.Seconds()),          // TTL in seconds
	}
	
	// Execute Lua script
	results, err := swrl.redisClient.Eval(ctx, luaScript, []string{redisKey}, args...).Result()
	if err != nil {
		swrl.recordError("redis")
		return nil, fmt.Errorf("redis script execution failed: %w", err)
	}
	
	// Parse results
	resultSlice, ok := results.([]interface{})
	if !ok || len(resultSlice) < 6 {
		return nil, fmt.Errorf("unexpected redis script result format")
	}
	
	allowed := resultSlice[0].(int64) == 1
	currentCount := resultSlice[1].(int64)
	tokenSum := resultSlice[2].(int64)
	remaining := resultSlice[3].(int64)
	resetTime := time.Unix(resultSlice[4].(int64), 0)
	limitValue := resultSlice[5].(int64)
	
	// Get sub-window breakdown
	subWindows, err := swrl.getSubWindowBreakdown(ctx, redisKey, now)
	if err != nil {
		swrl.logger.WithError(err).Warn("Failed to get sub-window breakdown")
		subWindows = []SubWindow{}
	}
	
	// Calculate additional metrics
	windowUsage := float64(currentCount) / float64(limit) * 100
	retryAfter := time.Duration(0)
	if !allowed {
		retryAfter = resetTime.Sub(now)
		if retryAfter < 0 {
			retryAfter = 0
		}
	}
	
	result := &RateLimitResult{
		Allowed:            allowed,
		Limit:              limitValue,
		Remaining:          remaining,
		ResetTime:          resetTime,
		RetryAfter:         retryAfter,
		WindowUsage:        windowUsage,
		CurrentCount:       currentCount,
		SubWindowBreakdown: subWindows,
	}
	
	// Add violation details if denied
	if !allowed {
		result.ViolationType = "rate_limit_exceeded"
		result.ViolationDetails = fmt.Sprintf("Request denied: %d/%d requests in window, tokens: %d", 
			currentCount+1, limit, tokenSum+request.TokenCount)
	}
	
	return result, nil
}

// getSubWindowBreakdown retrieves detailed breakdown of sub-windows
func (swrl *SlidingWindowRateLimiter) getSubWindowBreakdown(ctx context.Context, redisKey string, now time.Time) ([]SubWindow, error) {
	windowSize := swrl.config.WindowSize
	subWindowSize := windowSize / time.Duration(swrl.config.SubWindowCount)
	windowStart := now.Add(-windowSize)
	
	// Get all sub-windows in range
	results, err := swrl.redisClient.ZRangeByScoreWithScores(ctx, redisKey, &redis.ZRangeBy{
		Min: strconv.FormatInt(windowStart.Unix(), 10),
		Max: strconv.FormatInt(now.Unix(), 10),
	}).Result()
	
	if err != nil {
		return nil, err
	}
	
	var subWindows []SubWindow
	for _, result := range results {
		startTime := time.Unix(int64(result.Score), 0)
		endTime := startTime.Add(subWindowSize)
		
		// Parse sub-window data (simplified - in production would parse JSON)
		count := int64(1) // Simplified parsing
		tokenSum := int64(0)
		
		subWindows = append(subWindows, SubWindow{
			StartTime: startTime,
			EndTime:   endTime,
			Count:     count,
			TokenSum:  tokenSum,
		})
	}
	
	return subWindows, nil
}

// generateRedisKey generates a Redis key for the rate limit check
func (swrl *SlidingWindowRateLimiter) generateRedisKey(request *RateLimitRequest) string {
	if request.Key != "" {
		return fmt.Sprintf("%s%s", swrl.config.RedisKeyPrefix, request.Key)
	}
	
	// Generate key based on user/org/endpoint
	return fmt.Sprintf("%suser:%s:endpoint:%s", swrl.config.RedisKeyPrefix, request.UserID, request.Endpoint)
}

// updateMetrics updates rate limiting metrics
func (swrl *SlidingWindowRateLimiter) updateMetrics(result *RateLimitResult, latency time.Duration) {
	if !swrl.config.EnableMetrics {
		return
	}
	
	swrl.metrics.mu.Lock()
	defer swrl.metrics.mu.Unlock()
	
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

// recordError records different types of errors
func (swrl *SlidingWindowRateLimiter) recordError(errorType string) {
	if !swrl.config.EnableMetrics {
		return
	}
	
	swrl.metrics.mu.Lock()
	defer swrl.metrics.mu.Unlock()
	
	switch errorType {
	case "redis":
		swrl.metrics.RedisErrors++
	case "timeout":
		swrl.metrics.TimeoutErrors++
	case "processing":
		swrl.metrics.ProcessingErrors++
	}
}

// logViolation logs rate limit violations
func (swrl *SlidingWindowRateLimiter) logViolation(request *RateLimitRequest, result *RateLimitResult) {
	swrl.logger.WithFields(logrus.Fields{
		"user_id":         request.UserID,
		"org_id":          request.OrgID,
		"endpoint":        request.Endpoint,
		"client_ip":       request.ClientIP,
		"current_count":   result.CurrentCount,
		"limit":           result.Limit,
		"window_usage":    result.WindowUsage,
		"violation_type":  result.ViolationType,
		"retry_after":     result.RetryAfter,
	}).Warn("Rate limit violation detected")
}

// GetMetrics returns current rate limiting metrics
func (swrl *SlidingWindowRateLimiter) GetMetrics() *RateLimitMetrics {
	swrl.metrics.mu.RLock()
	defer swrl.metrics.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	metricsCopy := *swrl.metrics
	return &metricsCopy
}

// startCleanupWorker starts background cleanup of old windows
func (swrl *SlidingWindowRateLimiter) startCleanupWorker() {
	ticker := time.NewTicker(swrl.config.CleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		swrl.performCleanup()
	}
}

// performCleanup removes old sliding window data
func (swrl *SlidingWindowRateLimiter) performCleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Find keys with our prefix
	pattern := swrl.config.RedisKeyPrefix + "*"
	keys, err := swrl.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		swrl.logger.WithError(err).Error("Failed to get keys for cleanup")
		return
	}
	
	now := time.Now()
	cleanupBefore := now.Add(-swrl.config.WindowSize * 2) // Clean windows older than 2x window size
	
	for _, key := range keys {
		// Remove old entries from each sorted set
		_, err := swrl.redisClient.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(cleanupBefore.Unix(), 10)).Result()
		if err != nil {
			swrl.logger.WithError(err).WithField("key", key).Error("Failed to cleanup old entries")
		}
	}
}

// getDefaultSlidingWindowConfig returns default sliding window configuration
func getDefaultSlidingWindowConfig() *SlidingWindowConfig {
	return &SlidingWindowConfig{
		RedisKeyPrefix:   "ai_gateway:ratelimit:",
		KeyTTL:           2 * time.Hour,
		WindowSize:       1 * time.Minute,
		SubWindowCount:   12, // 5-second sub-windows for 1-minute window
		MaxConcurrency:   100,
		CleanupInterval:  5 * time.Minute,
		EnableMetrics:    true,
		LogViolations:    true,
	}
} 