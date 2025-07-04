package ratelimit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestRedis() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       1, // Use test database
	})
}

func TestRateLimitManager_Basic(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	manager, err := NewRateLimitManager(redisClient, nil, logger)
	require.NoError(t, err)
	require.NotNil(t, manager)
	
	// Test basic rate limit check
	request := &RateLimitCheckRequest{
		UserID:     "test-user-1",
		OrgID:      "test-org-1",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.1",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	response, err := manager.CheckRateLimit(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, response)
	
	// First request should be allowed
	assert.True(t, response.Allowed)
	assert.Empty(t, response.DenialReason)
	assert.NotEmpty(t, response.UserLimits)
}

func TestRateLimitManager_UserLimits(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise
	
	// Create config with very low limits for testing
	config := getDefaultRateLimitConfig()
	config.DefaultUserLimits.RequestsPerSecond = 2
	config.DefaultUserLimits.RequestsPerMinute = 5
	
	manager, err := NewRateLimitManager(redisClient, config, logger)
	require.NoError(t, err)
	
	request := &RateLimitCheckRequest{
		UserID:     "test-user-limit",
		OrgID:      "test-org-1",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.1",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	// First few requests should be allowed
	for i := 0; i < 2; i++ {
		response, err := manager.CheckRateLimit(context.Background(), request)
		require.NoError(t, err)
		assert.True(t, response.Allowed, "Request %d should be allowed", i+1)
	}
	
	// Next request should be denied due to per-second limit
	response, err := manager.CheckRateLimit(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, response.Allowed, "Request should be denied due to rate limit")
	assert.Contains(t, response.DenialReason, "per-second")
}

func TestRateLimitManager_EndpointLimits(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := getDefaultRateLimitConfig()
	// Set very low endpoint-specific limits
	config.PerEndpointLimits["/v1/chat/completions"].RequestsPerMinute = 2
	
	manager, err := NewRateLimitManager(redisClient, config, logger)
	require.NoError(t, err)
	
	request := &RateLimitCheckRequest{
		UserID:     "test-user-endpoint",
		OrgID:      "test-org-1",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.1",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	// First two requests should be allowed
	for i := 0; i < 2; i++ {
		response, err := manager.CheckRateLimit(context.Background(), request)
		require.NoError(t, err)
		assert.True(t, response.Allowed, "Request %d should be allowed", i+1)
	}
	
	// Third request should be denied due to endpoint limit
	response, err := manager.CheckRateLimit(context.Background(), request)
	require.NoError(t, err)
	assert.False(t, response.Allowed, "Request should be denied due to endpoint rate limit")
	assert.Contains(t, response.DenialReason, "Endpoint")
}

func TestRateLimitManager_IPLimits(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewRateLimitManager(redisClient, nil, logger)
	require.NoError(t, err)
	
	// Test with many requests from same IP to trigger IP rate limiting
	// Note: Default IP limit is 1000 per minute, so we won't hit it in normal tests
	// This test mainly verifies the IP check runs without error
	request := &RateLimitCheckRequest{
		UserID:     "test-user-ip",
		OrgID:      "test-org-1",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.100",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	response, err := manager.CheckRateLimit(context.Background(), request)
	require.NoError(t, err)
	assert.True(t, response.Allowed)
	assert.NotNil(t, response.IPLimits)
	assert.NotEmpty(t, response.IPLimits["per_minute"])
}

func TestRateLimitManager_Headers(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewRateLimitManager(redisClient, nil, logger)
	require.NoError(t, err)
	
	request := &RateLimitCheckRequest{
		UserID:     "test-user-headers",
		OrgID:      "test-org-1",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.1",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	response, err := manager.CheckRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	// Check that rate limit headers are generated
	assert.NotEmpty(t, response.RateLimitHeaders)
	assert.Contains(t, response.RateLimitHeaders, "X-RateLimit-Limit")
	assert.Contains(t, response.RateLimitHeaders, "X-RateLimit-Remaining")
	assert.Contains(t, response.RateLimitHeaders, "X-RateLimit-Reset")
}

func TestRateLimitManager_Metrics(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewRateLimitManager(redisClient, nil, logger)
	require.NoError(t, err)
	
	// Make some requests to generate metrics
	for i := 0; i < 5; i++ {
		request := &RateLimitCheckRequest{
			UserID:     "test-user-metrics",
			OrgID:      "test-org-1",
			Endpoint:   "/v1/chat/completions",
			Method:     "POST",
			ClientIP:   "192.168.1.1",
			TokenCount: 100,
			Timestamp:  time.Now(),
		}
		
		_, err := manager.CheckRateLimit(context.Background(), request)
		require.NoError(t, err)
	}
	
	// Get metrics
	metrics := manager.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Contains(t, metrics, "sliding_window")
}

func TestRateLimitManager_Disabled(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := getDefaultRateLimitConfig()
	config.Enabled = false
	
	manager, err := NewRateLimitManager(redisClient, config, logger)
	require.NoError(t, err)
	
	request := &RateLimitCheckRequest{
		UserID:     "test-user-disabled",
		OrgID:      "test-org-1",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.1",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	response, err := manager.CheckRateLimit(context.Background(), request)
	require.NoError(t, err)
	
	// When disabled, all requests should be allowed
	assert.True(t, response.Allowed)
	assert.Contains(t, response.ProcessingDetails, "rate_limiting")
	assert.Equal(t, "disabled", response.ProcessingDetails["rate_limiting"])
}

func TestSlidingWindowRateLimiter_Basic(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &SlidingWindowConfig{
		RedisKeyPrefix: "test:ratelimit:",
		WindowSize:     1 * time.Minute,
		SubWindowCount: 12,
		KeyTTL:         2 * time.Minute,
	}
	
	limiter := NewSlidingWindowRateLimiter(redisClient, config, logger)
	require.NotNil(t, limiter)
	
	request := &RateLimitRequest{
		Key:        "test:user:1",
		UserID:     "test-user-1",
		Endpoint:   "/v1/chat/completions",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	// Test with limit of 5 requests
	limit := int64(5)
	
	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result, err := limiter.CheckRateLimit(context.Background(), request, limit)
		require.NoError(t, err)
		assert.True(t, result.Allowed, "Request %d should be allowed", i+1)
		assert.Equal(t, limit, result.Limit)
		assert.Equal(t, int64(i+1), result.CurrentCount)
	}
	
	// 6th request should be denied
	result, err := limiter.CheckRateLimit(context.Background(), request, limit)
	require.NoError(t, err)
	assert.False(t, result.Allowed, "Request 6 should be denied")
	assert.Equal(t, "rate_limit_exceeded", result.ViolationType)
}

func TestSlidingWindowRateLimiter_WindowSliding(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := &SlidingWindowConfig{
		RedisKeyPrefix: "test:ratelimit:",
		WindowSize:     5 * time.Second, // Short window for testing
		SubWindowCount: 5,
		KeyTTL:         10 * time.Second,
	}
	
	limiter := NewSlidingWindowRateLimiter(redisClient, config, logger)
	
	request := &RateLimitRequest{
		Key:        "test:sliding:1",
		UserID:     "test-user-sliding",
		Endpoint:   "/v1/chat/completions",
		TokenCount: 1,
		Timestamp:  time.Now(),
	}
	
	limit := int64(3)
	
	// Fill up the limit
	for i := 0; i < 3; i++ {
		result, err := limiter.CheckRateLimit(context.Background(), request, limit)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}
	
	// Should be denied now
	result, err := limiter.CheckRateLimit(context.Background(), request, limit)
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	
	// Wait for window to slide (longer than window size)
	time.Sleep(6 * time.Second)
	
	// Should be allowed again
	result, err = limiter.CheckRateLimit(context.Background(), request, limit)
	require.NoError(t, err)
	assert.True(t, result.Allowed, "Request should be allowed after window slides")
}

func TestSlidingWindowRateLimiter_Metrics(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	limiter := NewSlidingWindowRateLimiter(redisClient, nil, logger)
	
	request := &RateLimitRequest{
		Key:        "test:metrics:1",
		UserID:     "test-user-metrics",
		Endpoint:   "/v1/chat/completions",
		TokenCount: 1,
		Timestamp:  time.Now(),
	}
	
	// Make some requests
	for i := 0; i < 10; i++ {
		_, err := limiter.CheckRateLimit(context.Background(), request, 100)
		require.NoError(t, err)
	}
	
	metrics := limiter.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(10), metrics.TotalRequests)
	assert.Equal(t, int64(10), metrics.AllowedRequests)
	assert.Equal(t, int64(0), metrics.DeniedRequests)
	assert.Greater(t, metrics.AverageLatency, time.Duration(0))
}

func BenchmarkRateLimitManager_CheckRateLimit(b *testing.B) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewRateLimitManager(redisClient, nil, logger)
	require.NoError(b, err)
	
	request := &RateLimitCheckRequest{
		UserID:     "bench-user",
		OrgID:      "bench-org",
		Endpoint:   "/v1/chat/completions",
		Method:     "POST",
		ClientIP:   "192.168.1.1",
		TokenCount: 100,
		Timestamp:  time.Now(),
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := manager.CheckRateLimit(context.Background(), request)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkSlidingWindowRateLimiter_CheckRateLimit(b *testing.B) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	limiter := NewSlidingWindowRateLimiter(redisClient, nil, logger)
	
	request := &RateLimitRequest{
		Key:        "bench:sliding",
		UserID:     "bench-user",
		Endpoint:   "/v1/chat/completions",
		TokenCount: 1,
		Timestamp:  time.Now(),
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := limiter.CheckRateLimit(context.Background(), request, 1000)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func TestRateLimitManager_ConcurrentUsers(t *testing.T) {
	redisClient := setupTestRedis()
	defer redisClient.FlushDB(context.Background())
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	config := getDefaultRateLimitConfig()
	config.DefaultUserLimits.RequestsPerMinute = 10 // Low limit for testing
	
	manager, err := NewRateLimitManager(redisClient, config, logger)
	require.NoError(t, err)
	
	// Test concurrent requests from different users
	numUsers := 5
	requestsPerUser := 5
	
	results := make(chan bool, numUsers*requestsPerUser)
	
	for userID := 0; userID < numUsers; userID++ {
		go func(uid int) {
			for i := 0; i < requestsPerUser; i++ {
				request := &RateLimitCheckRequest{
					UserID:     fmt.Sprintf("concurrent-user-%d", uid),
					OrgID:      "test-org-1",
					Endpoint:   "/v1/chat/completions",
					Method:     "POST",
					ClientIP:   "192.168.1.1",
					TokenCount: 100,
					Timestamp:  time.Now(),
				}
				
				response, err := manager.CheckRateLimit(context.Background(), request)
				require.NoError(t, err)
				results <- response.Allowed
			}
		}(userID)
	}
	
	// Collect results
	allowedCount := 0
	for i := 0; i < numUsers*requestsPerUser; i++ {
		if <-results {
			allowedCount++
		}
	}
	
	// All requests should be allowed since each user is under their limit
	assert.Equal(t, numUsers*requestsPerUser, allowedCount, "All requests should be allowed for different users")
} 