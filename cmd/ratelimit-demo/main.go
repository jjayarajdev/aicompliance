package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"ai-gateway-poc/internal/ratelimit"
)

// Demo configuration
type DemoConfig struct {
	Redis struct {
		Address  string `json:"address"`
		Password string `json:"password"`
		DB       int    `json:"db"`
	} `json:"redis"`
	
	Simulation struct {
		NumUsers           int           `json:"num_users"`
		RequestsPerUser    int           `json:"requests_per_user"`
		SimulationDuration time.Duration `json:"simulation_duration"`
		ConcurrentWorkers  int           `json:"concurrent_workers"`
	} `json:"simulation"`
}

// DemoMetrics tracks demo performance
type DemoMetrics struct {
	TotalRequests     int           `json:"total_requests"`
	AllowedRequests   int           `json:"allowed_requests"`
	DeniedRequests    int           `json:"denied_requests"`
	AverageLatency    time.Duration `json:"average_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	MinLatency        time.Duration `json:"min_latency"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	
	UserMetrics map[string]*UserDemoMetrics `json:"user_metrics"`
	
	mu sync.RWMutex
}

// UserDemoMetrics tracks per-user demo metrics
type UserDemoMetrics struct {
	TotalRequests   int     `json:"total_requests"`
	AllowedRequests int     `json:"allowed_requests"`
	DeniedRequests  int     `json:"denied_requests"`
	ErrorRate       float64 `json:"error_rate"`
	LastDenialTime  *time.Time `json:"last_denial_time,omitempty"`
	DenialReasons   map[string]int `json:"denial_reasons"`
}

func main() {
	fmt.Println("🚀 AI Gateway Rate Limiting Demo - Task 4.5")
	fmt.Println("============================================")
	fmt.Println()

	// Initialize logging
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Setup Redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		PoolSize:     20,
	})

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("❌ Failed to connect to Redis: %v", err)
	}
	fmt.Println("✅ Connected to Redis successfully")

	// Create rate limit manager with demo configuration
	config := createDemoRateLimitConfig()
	rateLimitManager, err := ratelimit.NewRateLimitManager(redisClient, config, logger)
	if err != nil {
		log.Fatalf("❌ Failed to create rate limit manager: %v", err)
	}
	fmt.Println("✅ Rate limit manager initialized")

	// Run demonstrations
	runDemonstrations(rateLimitManager, logger)

	fmt.Println("\n🎯 Demo completed successfully!")
}

func createDemoRateLimitConfig() *ratelimit.RateLimitConfig {
	return &ratelimit.RateLimitConfig{
		Enabled: true,
		DefaultUserLimits: &ratelimit.UserRateLimits{
			RequestsPerSecond: 5,   // Very low for demonstration
			RequestsPerMinute: 20,  // Low for demo
			RequestsPerHour:   100,
			RequestsPerDay:    1000,
			TokensPerMinute:   10000,
			TokensPerHour:     100000,
			TokensPerDay:      1000000,
			ConcurrentRequests: 3,
			UserTier:          "demo",
		},
		DefaultOrgLimits: &ratelimit.OrgRateLimits{
			RequestsPerSecond: 50,
			RequestsPerMinute: 200,
			RequestsPerHour:   1000,
			RequestsPerDay:    10000,
			TokensPerMinute:   100000,
			TokensPerHour:     1000000,
			TokensPerDay:      10000000,
			ConcurrentRequests: 50,
			MaxUsersPerOrg:    20,
			OrgTier:           "demo",
		},
		PerEndpointLimits: map[string]*ratelimit.EndpointLimits{
			"/v1/chat/completions": {
				RequestsPerSecond:  2,  // Very restrictive for demo
				RequestsPerMinute:  10,
				RequestsPerHour:    50,
				TokensPerMinute:    5000,
				ConcurrentRequests: 2,
				CostMultiplier:     1.0,
			},
			"/v1/completions": {
				RequestsPerSecond:  3,
				RequestsPerMinute:  15,
				RequestsPerHour:    75,
				TokensPerMinute:    7500,
				ConcurrentRequests: 3,
				CostMultiplier:     0.8,
			},
			"/v1/embeddings": {
				RequestsPerSecond:  10,
				RequestsPerMinute:  50,
				RequestsPerHour:    200,
				TokensPerMinute:    25000,
				ConcurrentRequests: 5,
				CostMultiplier:     0.3,
			},
		},
		SlidingWindowConfig: &ratelimit.SlidingWindowConfig{
			RedisKeyPrefix:   "demo:ratelimit:",
			KeyTTL:           5 * time.Minute,
			WindowSize:       1 * time.Minute,
			SubWindowCount:   12, // 5-second sub-windows
			MaxConcurrency:   50,
			CleanupInterval:  2 * time.Minute,
			EnableMetrics:    true,
			LogViolations:    true,
		},
		BurstAllowance:    1.2,
		GracePeriod:       10 * time.Second,
		BackoffMultiplier: 2.0,
		MaxBackoff:        30 * time.Second,
		EnableAnalytics:   true,
		AnalyticsRetention: 1 * time.Hour,
		AlertThresholds: &ratelimit.AlertThresholds{
			WarningThreshold:  70.0,
			CriticalThreshold: 90.0,
			ViolationCount:    5,
			ViolationWindow:   2 * time.Minute,
		},
	}
}

func runDemonstrations(manager *ratelimit.RateLimitManager, logger *logrus.Logger) {
	fmt.Println("\n📊 Starting Rate Limiting Demonstrations")
	fmt.Println("========================================")

	// Demo 1: Basic per-user rate limiting
	fmt.Println("\n🔹 Demo 1: Basic Per-User Rate Limiting")
	runBasicUserRateLimitDemo(manager)

	// Demo 2: Sliding window behavior
	fmt.Println("\n🔹 Demo 2: Sliding Window Behavior")
	runSlidingWindowDemo(manager)

	// Demo 3: Different endpoint limits
	fmt.Println("\n🔹 Demo 3: Per-Endpoint Rate Limits")
	runEndpointLimitsDemo(manager)

	// Demo 4: Organization-level limits
	fmt.Println("\n🔹 Demo 4: Organization-Level Limits")
	runOrgLimitsDemo(manager)

	// Demo 5: Concurrent users simulation
	fmt.Println("\n🔹 Demo 5: Concurrent Users Simulation")
	runConcurrentUsersDemo(manager)

	// Demo 6: Rate limit recovery
	fmt.Println("\n🔹 Demo 6: Rate Limit Recovery")
	runRateLimitRecoveryDemo(manager)

	// Demo 7: Analytics and monitoring
	fmt.Println("\n🔹 Demo 7: Analytics and Monitoring")
	runAnalyticsDemo(manager)
}

func runBasicUserRateLimitDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Testing basic user rate limiting with 5 requests/second limit...")
	
	userID := "demo-user-1"
	
	for i := 1; i <= 8; i++ {
		request := &ratelimit.RateLimitCheckRequest{
			UserID:     userID,
			OrgID:      "demo-org-1",
			Endpoint:   "/v1/chat/completions",
			Method:     "POST",
			ClientIP:   "192.168.1.100",
			TokenCount: 1000,
			Timestamp:  time.Now(),
		}
		
		response, err := manager.CheckRateLimit(context.Background(), request)
		if err != nil {
			fmt.Printf("❌ Request %d failed: %v\n", i, err)
			continue
		}
		
		status := "✅ ALLOWED"
		if !response.Allowed {
			status = "❌ DENIED"
		}
		
		fmt.Printf("Request %d: %s", i, status)
		if !response.Allowed {
			fmt.Printf(" (Reason: %s)", response.DenialReason)
		}
		
		if perMinute, exists := response.UserLimits["per_minute"]; exists {
			fmt.Printf(" [Usage: %d/%d, Remaining: %d]",
				perMinute.CurrentCount, perMinute.Limit, perMinute.Remaining)
		}
		fmt.Println()
		
		time.Sleep(200 * time.Millisecond) // Small delay between requests
	}
}

func runSlidingWindowDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Demonstrating sliding window behavior over time...")
	
	userID := "demo-user-sliding"
	
	// Fill up the limit quickly
	fmt.Println("Phase 1: Filling up rate limit (5 requests rapidly)")
	for i := 1; i <= 5; i++ {
		request := &ratelimit.RateLimitCheckRequest{
			UserID:     userID,
			OrgID:      "demo-org-1",
			Endpoint:   "/v1/chat/completions",
			Method:     "POST",
			ClientIP:   "192.168.1.101",
			TokenCount: 1000,
		}
		
		response, err := manager.CheckRateLimit(context.Background(), request)
		if err != nil {
			continue
		}
		
		status := "✅"
		if !response.Allowed {
			status = "❌"
		}
		fmt.Printf("  Quick request %d: %s\n", i, status)
	}
	
	// Try one more (should be denied)
	fmt.Println("Phase 2: Testing rate limit enforcement")
	request := &ratelimit.RateLimitCheckRequest{
		UserID:   userID,
		OrgID:    "demo-org-1",
		Endpoint: "/v1/chat/completions",
		Method:   "POST",
		ClientIP: "192.168.1.101",
		TokenCount: 1000,
	}
	
	response, err := manager.CheckRateLimit(context.Background(), request)
	if err == nil {
		if !response.Allowed {
			fmt.Printf("  ❌ Request correctly denied: %s\n", response.DenialReason)
		} else {
			fmt.Println("  ⚠️  Request unexpectedly allowed")
		}
	}
	
	// Wait for window to slide
	fmt.Println("Phase 3: Waiting for sliding window to allow new requests...")
	fmt.Print("  Waiting")
	for i := 0; i < 15; i++ {
		fmt.Print(".")
		time.Sleep(1 * time.Second)
	}
	fmt.Println()
	
	// Try again (should be allowed)
	response, err = manager.CheckRateLimit(context.Background(), request)
	if err == nil {
		if response.Allowed {
			fmt.Println("  ✅ Request allowed after window slide")
		} else {
			fmt.Printf("  ❌ Request still denied: %s\n", response.DenialReason)
		}
	}
}

func runEndpointLimitsDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Testing different rate limits for different endpoints...")
	
	userID := "demo-user-endpoint"
	endpoints := []string{
		"/v1/chat/completions", // 2 req/sec limit
		"/v1/completions",      // 3 req/sec limit
		"/v1/embeddings",       // 10 req/sec limit
	}
	
	for _, endpoint := range endpoints {
		fmt.Printf("\nTesting endpoint: %s\n", endpoint)
		
		allowedCount := 0
		for i := 1; i <= 5; i++ {
			request := &ratelimit.RateLimitCheckRequest{
				UserID:     userID,
				OrgID:      "demo-org-1",
				Endpoint:   endpoint,
				Method:     "POST",
				ClientIP:   "192.168.1.102",
				TokenCount: 500,
			}
			
			response, err := manager.CheckRateLimit(context.Background(), request)
			if err != nil {
				continue
			}
			
			if response.Allowed {
				allowedCount++
				fmt.Printf("  Request %d: ✅ ALLOWED\n", i)
			} else {
				fmt.Printf("  Request %d: ❌ DENIED (%s)\n", i, response.DenialReason)
			}
			
			time.Sleep(100 * time.Millisecond)
		}
		
		fmt.Printf("  Summary: %d/5 requests allowed for %s\n", allowedCount, endpoint)
	}
}

func runOrgLimitsDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Testing organization-level rate limits...")
	
	orgID := "demo-org-limits"
	users := []string{"user-1", "user-2", "user-3"}
	
	totalAllowed := 0
	totalRequests := 0
	
	for _, userID := range users {
		fmt.Printf("\nTesting requests from user: %s\n", userID)
		
		for i := 1; i <= 4; i++ {
			request := &ratelimit.RateLimitCheckRequest{
				UserID:     userID,
				OrgID:      orgID,
				Endpoint:   "/v1/chat/completions",
				Method:     "POST",
				ClientIP:   fmt.Sprintf("192.168.1.%d", 103+len(userID)), // Different IPs
				TokenCount: 1000,
			}
			
			response, err := manager.CheckRateLimit(context.Background(), request)
			totalRequests++
			
			if err != nil {
				continue
			}
			
			if response.Allowed {
				totalAllowed++
				fmt.Printf("  Request %d: ✅ ALLOWED", i)
			} else {
				fmt.Printf("  Request %d: ❌ DENIED (%s)", i, response.DenialReason)
			}
			
			// Show org limit status
			if orgLimit, exists := response.OrgLimits["per_minute"]; exists {
				fmt.Printf(" [Org usage: %d/%d]", orgLimit.CurrentCount, orgLimit.Limit)
			}
			fmt.Println()
			
			time.Sleep(150 * time.Millisecond)
		}
	}
	
	fmt.Printf("\nOrganization summary: %d/%d total requests allowed\n", totalAllowed, totalRequests)
}

func runConcurrentUsersDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Simulating concurrent users with different request patterns...")
	
	numUsers := 5
	requestsPerUser := 6
	
	var wg sync.WaitGroup
	results := make(chan DemoResult, numUsers*requestsPerUser)
	
	// Launch concurrent users
	for userNum := 1; userNum <= numUsers; userNum++ {
		wg.Add(1)
		go func(userID string) {
			defer wg.Done()
			
			for i := 1; i <= requestsPerUser; i++ {
				request := &ratelimit.RateLimitCheckRequest{
					UserID:     userID,
					OrgID:      "demo-org-concurrent",
					Endpoint:   "/v1/chat/completions",
					Method:     "POST",
					ClientIP:   fmt.Sprintf("192.168.2.%d", userNum+100),
					TokenCount: 1000,
					Timestamp:  time.Now(),
				}
				
				start := time.Now()
				response, err := manager.CheckRateLimit(context.Background(), request)
				latency := time.Since(start)
				
				result := DemoResult{
					UserID:    userID,
					RequestID: i,
					Allowed:   err == nil && response.Allowed,
					Latency:   latency,
					Error:     err,
				}
				
				if response != nil {
					result.DenialReason = response.DenialReason
				}
				
				results <- result
				
				// Random delay between requests
				time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
			}
		}(fmt.Sprintf("concurrent-user-%d", userNum))
	}
	
	// Wait for all users to complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect and analyze results
	userResults := make(map[string][]DemoResult)
	for result := range results {
		userResults[result.UserID] = append(userResults[result.UserID], result)
	}
	
	// Display results
	for userID, userRes := range userResults {
		allowed := 0
		denied := 0
		totalLatency := time.Duration(0)
		
		for _, res := range userRes {
			if res.Allowed {
				allowed++
			} else {
				denied++
			}
			totalLatency += res.Latency
		}
		
		avgLatency := totalLatency / time.Duration(len(userRes))
		successRate := float64(allowed) / float64(len(userRes)) * 100
		
		fmt.Printf("  %s: %d allowed, %d denied (%.1f%% success) - Avg latency: %v\n",
			userID, allowed, denied, successRate, avgLatency)
	}
}

func runRateLimitRecoveryDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Demonstrating rate limit recovery over time...")
	
	userID := "demo-user-recovery"
	
	fmt.Println("Phase 1: Exhausting rate limit")
	deniedCount := 0
	for i := 1; i <= 10; i++ {
		request := &ratelimit.RateLimitCheckRequest{
			UserID:     userID,
			OrgID:      "demo-org-1",
			Endpoint:   "/v1/chat/completions",
			Method:     "POST",
			ClientIP:   "192.168.1.110",
			TokenCount: 1000,
		}
		
		response, err := manager.CheckRateLimit(context.Background(), request)
		if err != nil {
			continue
		}
		
		if response.Allowed {
			fmt.Printf("  Request %d: ✅ ALLOWED\n", i)
		} else {
			deniedCount++
			fmt.Printf("  Request %d: ❌ DENIED\n", i)
		}
	}
	
	fmt.Printf("Phase 1 complete: %d requests denied\n", deniedCount)
	
	fmt.Println("\nPhase 2: Monitoring recovery (checking every 5 seconds)")
	for attempt := 1; attempt <= 6; attempt++ {
		time.Sleep(5 * time.Second)
		
		request := &ratelimit.RateLimitCheckRequest{
			UserID:     userID,
			OrgID:      "demo-org-1",
			Endpoint:   "/v1/chat/completions",
			Method:     "POST",
			ClientIP:   "192.168.1.110",
			TokenCount: 1000,
		}
		
		response, err := manager.CheckRateLimit(context.Background(), request)
		if err != nil {
			continue
		}
		
		status := "❌ DENIED"
		if response.Allowed {
			status = "✅ ALLOWED"
		}
		
		retryAfter := ""
		if !response.Allowed && len(response.UserLimits) > 0 {
			if perMinute, exists := response.UserLimits["per_minute"]; exists {
				retryAfter = fmt.Sprintf(" (Retry after: %.0fs)", perMinute.RetryAfter.Seconds())
			}
		}
		
		fmt.Printf("  Recovery attempt %d: %s%s\n", attempt, status, retryAfter)
		
		if response.Allowed {
			fmt.Println("  ✅ Rate limit has recovered!")
			break
		}
	}
}

func runAnalyticsDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Generating analytics data...")
	
	// Generate some traffic for analytics
	users := []string{"analytics-user-1", "analytics-user-2", "analytics-user-3"}
	endpoints := []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings"}
	
	for _, userID := range users {
		for _, endpoint := range endpoints {
			for i := 0; i < 3; i++ {
				request := &ratelimit.RateLimitCheckRequest{
					UserID:     userID,
					OrgID:      "analytics-org",
					Endpoint:   endpoint,
					Method:     "POST",
					ClientIP:   fmt.Sprintf("192.168.3.%d", i+1),
					TokenCount: int64(rand.Intn(2000) + 500),
				}
				
				manager.CheckRateLimit(context.Background(), request)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	
	// Get and display metrics
	fmt.Println("\nRate Limiting Metrics:")
	metrics := manager.GetMetrics()
	
	if metricsJSON, err := json.MarshalIndent(metrics, "", "  "); err == nil {
		fmt.Println(string(metricsJSON))
	} else {
		fmt.Printf("Available metrics components: %v\n", getMapKeys(metrics))
	}
}

// Helper types and functions

type DemoResult struct {
	UserID       string
	RequestID    int
	Allowed      bool
	Latency      time.Duration
	DenialReason string
	Error        error
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
} 