package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"ai-gateway-poc/internal/cache"
)

func main() {
	fmt.Println("🚀 AI Gateway Redis Response Cache Demo")
	fmt.Println("========================================")

	// Initialize Redis connection
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create cache manager with comprehensive config
	cacheConfig := &cache.CacheConfig{
		RedisKeyPrefix:       "ai_gateway:cache:",
		DefaultTTL:           1 * time.Hour,
		MaxRequestSize:       10 * 1024 * 1024,
		MaxResponseSize:      50 * 1024 * 1024,
		CompressionThreshold: 1024,
		CompressionEnabled:   true,
		MemoryCacheEnabled:   true,
		MemoryCacheSize:      100,
		MemoryCacheTTL:       5 * time.Minute,
		TTLPolicies: map[string]time.Duration{
			"chat":       15 * time.Minute,
			"completion": 30 * time.Minute,
			"embedding":  2 * time.Hour,
			"image":      1 * time.Hour,
			"default":    1 * time.Hour,
		},
		InvalidationEnabled:  true,
		CacheKeyMaxLength:    250,
		MetricsEnabled:       true,
		HealthCheckInterval:  30 * time.Second,
	}

	cacheManager, err := cache.NewResponseCacheManager(rdb, cacheConfig, logger)
	if err != nil {
		log.Fatalf("Failed to create cache manager: %v", err)
	}

	runDemo(ctx, cacheManager, logger)
	rdb.Close()
	fmt.Println("\n✅ Demo completed successfully!")
}

func runDemo(ctx context.Context, cacheManager *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n📋 Running Redis Cache Demo Sections:")

	// Basic cache operations demo
	fmt.Println("\n🔹 Section 1: Basic Cache Operations")
	request := &cache.CacheRequest{
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

	response := &cache.CacheResponse{
		StatusCode:    200,
		Headers:       map[string]string{"Content-Type": "application/json"},
		Body:          `{"choices":[{"message":{"content":"Hello! How can I help you?"}}]}`,
		ContentType:   "application/json",
		ContentLength: 58,
		CachedAt:      time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		TTL:           1 * time.Hour,
	}

	// Test cache miss
	fmt.Println("Testing cache miss...")
	start := time.Now()
	cached, err := cacheManager.Get(ctx, request)
	missLatency := time.Since(start)
	if err != nil {
		logger.WithError(err).Error("Cache get failed")
	} else if cached == nil {
		fmt.Printf("✅ Cache miss (as expected) - Latency: %v\n", missLatency)
	}

	// Test cache set
	fmt.Println("Setting cache entry...")
	start = time.Now()
	err = cacheManager.Set(ctx, request, response)
	setLatency := time.Since(start)
	if err != nil {
		logger.WithError(err).Error("Cache set failed")
	} else {
		fmt.Printf("✅ Cache set successful - Latency: %v\n", setLatency)
	}

	// Test cache hit
	fmt.Println("Testing cache hit...")
	start = time.Now()
	cached, err = cacheManager.Get(ctx, request)
	hitLatency := time.Since(start)
	if err != nil {
		logger.WithError(err).Error("Cache get failed")
	} else if cached != nil {
		fmt.Printf("✅ Cache hit successful - Latency: %v\n", hitLatency)
		fmt.Printf("   Response Status: %d\n", cached.StatusCode)
		fmt.Printf("   Response Size: %d bytes\n", len(cached.Body))
		fmt.Printf("   Hit Count: %d\n", cached.HitCount)
		fmt.Printf("   Speed improvement: %.1fx faster than miss\n", float64(missLatency)/float64(hitLatency))
	}

	// Multi-level caching demo
	fmt.Println("\n🔹 Section 2: Multi-Level Caching Test")
	
	// First get should hit Redis
	start = time.Now()
	cached, _ = cacheManager.Get(ctx, request)
	redisLatency := time.Since(start)
	
	// Second get should hit memory cache (faster)
	start = time.Now()
	cached, _ = cacheManager.Get(ctx, request)
	memoryLatency := time.Since(start)
	
	if redisLatency > 0 && memoryLatency > 0 {
		fmt.Printf("✅ Multi-level caching working:\n")
		fmt.Printf("   Redis access: %v\n", redisLatency)
		fmt.Printf("   Memory access: %v\n", memoryLatency)
		fmt.Printf("   Memory cache is %.1fx faster\n", float64(redisLatency)/float64(memoryLatency))
	}

	// TTL demonstration
	fmt.Println("\n🔹 Section 3: TTL Policies")
	testRequests := []struct {
		name string
		reqType string
		expectedTTL string
	}{
		{"Chat Request", "chat", "15 minutes"},
		{"Completion Request", "completion", "30 minutes"},
		{"Embedding Request", "embedding", "2 hours"},
		{"Unknown Request", "unknown", "1 hour (default)"},
	}

	for _, tr := range testRequests {
		req := *request
		req.RequestType = tr.reqType
		req.URL = fmt.Sprintf("https://api.openai.com/v1/%s", tr.reqType)
		
		resp := *response
		resp.Body = fmt.Sprintf(`{"result": "test %s response"}`, tr.reqType)
		
		err := cacheManager.Set(ctx, &req, &resp)
		if err == nil {
			cached, _ := cacheManager.Get(ctx, &req)
			if cached != nil {
				fmt.Printf("✅ %s: TTL=%v (%s)\n", tr.name, cached.TTL, tr.expectedTTL)
			}
		}
	}

	time.Sleep(1 * time.Second)
	showMetrics(cacheManager)
}

func showMetrics(cm *cache.ResponseCacheManager) {
	fmt.Println("\n📈 Final Cache Metrics and Health Status:")
	
	health := cm.GetHealthStatus()
	metrics := cm.GetMetrics()
	
	fmt.Printf("\n🏥 Health Status:\n")
	fmt.Printf("   Overall Status: %s\n", health.Status)
	fmt.Printf("   Redis Connected: %t\n", health.RedisConnected)
	fmt.Printf("   Memory Cache Active: %t\n", health.MemoryCacheActive)
	fmt.Printf("   Last Health Check: %v ago\n", time.Since(health.LastHealthCheck).Round(time.Second))
	fmt.Printf("   Error Count: %d\n", health.ErrorCount)
	
	fmt.Printf("\n📊 Performance Metrics:\n")
	fmt.Printf("   Total Requests: %d\n", metrics.TotalRequests)
	fmt.Printf("   Redis - Hits: %d, Misses: %d\n", metrics.RedisHits, metrics.RedisMisses)
	fmt.Printf("   Memory - Hits: %d, Misses: %d\n", metrics.MemoryHits, metrics.MemoryMisses)
	
	if metrics.RedisHits+metrics.RedisMisses > 0 {
		redisHitRate := float64(metrics.RedisHits) / float64(metrics.RedisHits+metrics.RedisMisses) * 100
		fmt.Printf("   Redis Hit Rate: %.1f%%\n", redisHitRate)
	}
	
	if metrics.MemoryHits+metrics.MemoryMisses > 0 {
		memoryHitRate := float64(metrics.MemoryHits) / float64(metrics.MemoryHits+metrics.MemoryMisses) * 100
		fmt.Printf("   Memory Hit Rate: %.1f%%\n", memoryHitRate)
	}
	
	totalHits := metrics.RedisHits + metrics.MemoryHits
	totalMisses := metrics.RedisMisses + metrics.MemoryMisses
	if totalHits+totalMisses > 0 {
		overallHitRate := float64(totalHits) / float64(totalHits+totalMisses) * 100
		fmt.Printf("   Overall Hit Rate: %.1f%%\n", overallHitRate)
	}
	
	fmt.Printf("   Average GET Latency: %v\n", metrics.AverageGetLatency)
	fmt.Printf("   Average SET Latency: %v\n", metrics.AverageSetLatency)
	fmt.Printf("   Total Cache Entries: %d\n", metrics.TotalEntries)
	fmt.Printf("   Total Size Cached: %d bytes\n", metrics.TotalSizeBytes)
	
	if metrics.CompressionSaved > 0 {
		fmt.Printf("   Compression Savings: %d bytes\n", metrics.CompressionSaved)
	}
	
	if metrics.Errors > 0 {
		fmt.Printf("   ⚠️  Errors: %d\n", metrics.Errors)
	}
} 