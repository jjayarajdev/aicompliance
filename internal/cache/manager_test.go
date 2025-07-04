package cache

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers
func setupTestCacheManager(t *testing.T) (*ResponseCacheManager, *redis.Client) {
	// Use Redis test instance or mock
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use test database
	})
	
	// Test Redis connection
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available for testing")
	}
	
	// Clean test database
	rdb.FlushDB(ctx)
	
	config := &CacheConfig{
		RedisKeyPrefix:       "test:cache:",
		DefaultTTL:           1 * time.Hour,
		MaxRequestSize:       1024,
		MaxResponseSize:      1024,
		CompressionThreshold: 100,
		CompressionEnabled:   true,
		MemoryCacheEnabled:   true,
		MemoryCacheSize:      10,
		MemoryCacheTTL:       5 * time.Minute,
		TTLPolicies: map[string]time.Duration{
			"test": 30 * time.Minute,
		},
		InvalidationEnabled:  true,
		CacheKeyMaxLength:    200,
		BatchSize:           100,
		PipelineEnabled:     true,
		MetricsEnabled:      true,
		HealthCheckInterval: 10 * time.Second,
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewResponseCacheManager(rdb, config, logger)
	require.NoError(t, err)
	
	return manager, rdb
}

func createTestRequest() *CacheRequest {
	return &CacheRequest{
		Method:         "POST",
		URL:            "https://api.openai.com/v1/chat/completions",
		Headers:        map[string]string{"Content-Type": "application/json"},
		Body:           `{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}]}`,
		UserID:         "user123",
		OrganizationID: "org456",
		RequestType:    "chat",
		Timestamp:      time.Now(),
		ClientIP:       "192.168.1.1",
	}
}

func createTestResponse() *CacheResponse {
	return &CacheResponse{
		StatusCode:    200,
		Headers:       map[string]string{"Content-Type": "application/json"},
		Body:          `{"choices":[{"message":{"content":"Hello! How can I help you?"}}]}`,
		ContentType:   "application/json",
		ContentLength: 58,
		CachedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		HitCount:      0,
		LastAccessed:  time.Now(),
		Compressed:    false,
		TTL:           1 * time.Hour,
	}
}

// Unit Tests
func TestNewResponseCacheManager(t *testing.T) {
	tests := []struct {
		name        string
		redisClient *redis.Client
		config      *CacheConfig
		expectError bool
	}{
		{
			name:        "nil redis client",
			redisClient: nil,
			config:      getDefaultCacheConfig(),
			expectError: true,
		},
		{
			name:        "nil config uses defaults",
			redisClient: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
			config:      nil,
			expectError: false,
		},
		{
			name:        "valid config",
			redisClient: redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
			config:      getDefaultCacheConfig(),
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewResponseCacheManager(tt.redisClient, tt.config, nil)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				if manager != nil {
					assert.NotNil(t, manager.config)
					assert.NotNil(t, manager.metrics)
				}
			}
		})
	}
}

func TestCacheGetSet(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	ctx := context.Background()
	request := createTestRequest()
	response := createTestResponse()
	
	// Test cache miss
	cached, err := manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.Nil(t, cached)
	
	// Test cache set
	err = manager.Set(ctx, request, response)
	assert.NoError(t, err)
	
	// Test cache hit
	cached, err = manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, cached)
	assert.Equal(t, response.Body, cached.Body)
	assert.Equal(t, response.StatusCode, cached.StatusCode)
	
	// Verify metrics
	metrics := manager.GetMetrics()
	assert.Equal(t, int64(2), metrics.TotalRequests)
	assert.Equal(t, int64(1), metrics.RedisMisses)
	assert.Equal(t, int64(1), metrics.RedisHits)
}

func TestCacheKeyGeneration(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	request1 := createTestRequest()
	request2 := createTestRequest()
	request3 := createTestRequest()
	request3.Body = "different body"
	
	key1, err := manager.generateCacheKey(request1)
	assert.NoError(t, err)
	
	key2, err := manager.generateCacheKey(request2)
	assert.NoError(t, err)
	
	key3, err := manager.generateCacheKey(request3)
	assert.NoError(t, err)
	
	// Same requests should generate same keys
	assert.Equal(t, key1, key2)
	
	// Different requests should generate different keys
	assert.NotEqual(t, key1, key3)
	
	// Keys should have proper prefix
	assert.True(t, strings.HasPrefix(key1, manager.config.RedisKeyPrefix))
}

func TestCompressionDecompression(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	// Create response with large body (over compression threshold)
	response := createTestResponse()
	response.Body = strings.Repeat("This is a test response body. ", 50) // ~1500 chars
	
	compressed, ratio, err := manager.compressResponse(response)
	assert.NoError(t, err)
	assert.Less(t, ratio, 1.0) // Should achieve some compression
	assert.NotEmpty(t, compressed)
	
	// Test decompression
	compressedResponse := &CacheResponse{Body: compressed, Compressed: true}
	decompressed, err := manager.decompressResponse(compressedResponse)
	assert.NoError(t, err)
	assert.Equal(t, response.Body, decompressed)
}

func TestMemoryCache(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	ctx := context.Background()
	request := createTestRequest()
	response := createTestResponse()
	
	// Set in cache
	err := manager.Set(ctx, request, response)
	assert.NoError(t, err)
	
	// First get should hit Redis and populate memory cache
	cached, err := manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, cached)
	
	// Second get should hit memory cache
	cached, err = manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, cached)
	
	// Check metrics show memory cache hit
	metrics := manager.GetMetrics()
	assert.True(t, metrics.MemoryHits > 0)
}

func TestCacheInvalidation(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	ctx := context.Background()
	
	// Create multiple cache entries
	for i := 0; i < 3; i++ {
		request := createTestRequest()
		request.URL = fmt.Sprintf("https://api.test.com/endpoint%d", i)
		response := createTestResponse()
		
		err := manager.Set(ctx, request, response)
		assert.NoError(t, err)
	}
	
	// Invalidate with pattern
	err := manager.Invalidate(ctx, []string{"*"})
	assert.NoError(t, err)
	
	// Verify entries are gone
	request := createTestRequest()
	cached, err := manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.Nil(t, cached)
}

func TestTTLPolicies(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	request := createTestRequest()
	request.RequestType = "test" // Should use 30 minute TTL from config
	
	ttl := manager.getTTLForRequest(request)
	assert.Equal(t, 30*time.Minute, ttl)
	
	// Test default TTL
	request.RequestType = "unknown"
	ttl = manager.getTTLForRequest(request)
	assert.Equal(t, manager.config.DefaultTTL, ttl)
}

func TestHealthStatus(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	// Wait for health check
	time.Sleep(100 * time.Millisecond)
	
	health := manager.GetHealthStatus()
	assert.NotEmpty(t, health.Status)
	assert.True(t, health.RedisConnected)
	assert.True(t, health.MemoryCacheActive)
}

func TestSizeLimits(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	ctx := context.Background()
	
	// Test request size limit
	request := createTestRequest()
	request.Body = strings.Repeat("x", 2000) // Exceeds 1024 limit
	response := createTestResponse()
	
	err := manager.Set(ctx, request, response)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request body too large")
	
	// Test response size limit
	request = createTestRequest()
	response.Body = strings.Repeat("x", 2000) // Exceeds 1024 limit
	
	err = manager.Set(ctx, request, response)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "response body too large")
}

// Integration Tests
func TestCacheIntegration(t *testing.T) {
	manager, rdb := setupTestCacheManager(t)
	defer rdb.Close()
	
	ctx := context.Background()
	
	// Simulate real usage pattern
	requests := make([]*CacheRequest, 10)
	responses := make([]*CacheResponse, 10)
	
	for i := 0; i < 10; i++ {
		requests[i] = createTestRequest()
		requests[i].URL = fmt.Sprintf("https://api.test.com/endpoint%d", i)
		responses[i] = createTestResponse()
		responses[i].Body = fmt.Sprintf(`{"result": "response %d"}`, i)
	}
	
	// Set all entries
	for i := 0; i < 10; i++ {
		err := manager.Set(ctx, requests[i], responses[i])
		assert.NoError(t, err)
	}
	
	// Get all entries (should hit cache)
	for i := 0; i < 10; i++ {
		cached, err := manager.Get(ctx, requests[i])
		assert.NoError(t, err)
		assert.NotNil(t, cached)
		assert.Equal(t, responses[i].Body, cached.Body)
	}
	
	// Check metrics
	metrics := manager.GetMetrics()
	assert.Equal(t, int64(20), metrics.TotalRequests) // 10 gets + 10 sets
	assert.Equal(t, int64(10), metrics.RedisHits)
	assert.Equal(t, int64(10), metrics.RedisMisses) // First gets were misses
}

// Performance Tests
func BenchmarkCacheGet(b *testing.B) {
	manager, rdb := setupTestCacheManager(b)
	defer rdb.Close()
	
	ctx := context.Background()
	request := createTestRequest()
	response := createTestResponse()
	
	// Pre-populate cache
	manager.Set(ctx, request, response)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.Get(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCacheSet(b *testing.B) {
	manager, rdb := setupTestCacheManager(b)
	defer rdb.Close()
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := createTestRequest()
		request.URL = fmt.Sprintf("https://api.test.com/endpoint%d", i)
		response := createTestResponse()
		
		err := manager.Set(ctx, request, response)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCacheKeyGeneration(b *testing.B) {
	manager, rdb := setupTestCacheManager(b)
	defer rdb.Close()
	
	request := createTestRequest()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.generateCacheKey(request)
		if err != nil {
			b.Fatal(err)
		}
	}
} 