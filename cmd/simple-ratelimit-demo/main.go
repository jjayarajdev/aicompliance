package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"ai-gateway-poc/internal/ratelimit"
)

func main() {
	fmt.Println("🚀 AI Gateway Rate Limiting Demo - Task 4.5")
	fmt.Println("============================================")

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Printf("⚠️  Redis not available: %v (using mock mode)", err)
		fmt.Println("Running without Redis - using simple in-memory rate limiting")
	} else {
		fmt.Println("✅ Connected to Redis successfully")
	}

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create rate limit manager
	manager, err := ratelimit.NewRateLimitManager(redisClient, nil, logger)
	if err != nil {
		log.Fatalf("❌ Failed to create rate limit manager: %v", err)
	}
	fmt.Println("✅ Rate limit manager initialized")

	// Demo 1: Basic user rate limiting
	fmt.Println("\n🔹 Demo 1: Basic User Rate Limiting")
	runBasicDemo(manager)

	// Demo 2: Different endpoints
	fmt.Println("\n🔹 Demo 2: Endpoint-Specific Rate Limits")
	runEndpointDemo(manager)

	// Demo 3: Organization limits
	fmt.Println("\n🔹 Demo 3: Organization-Level Limits")
	runOrgDemo(manager)

	fmt.Println("\n🎯 Rate limiting demo completed successfully!")
}

func runBasicDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Testing per-user rate limiting with multiple requests...")

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
			fmt.Printf("  ❌ Request %d failed: %v\n", i, err)
			continue
		}

		status := "✅ ALLOWED"
		if !response.Allowed {
			status = "❌ DENIED"
		}

		fmt.Printf("  Request %d: %s", i, status)
		if !response.Allowed {
			fmt.Printf(" (Reason: %s)", response.DenialReason)
		}

		// Show rate limit info
		if perMinute, exists := response.UserLimits["per_minute"]; exists {
			fmt.Printf(" [Usage: %d/%d, Remaining: %d]",
				perMinute.CurrentCount, perMinute.Limit, perMinute.Remaining)
		}
		fmt.Println()

		time.Sleep(100 * time.Millisecond)
	}
}

func runEndpointDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Testing different rate limits for different endpoints...")

	userID := "demo-user-endpoint"
	endpoints := []string{
		"/v1/chat/completions", // Lower limit
		"/v1/completions",      // Medium limit
		"/v1/embeddings",       // Higher limit
	}

	for _, endpoint := range endpoints {
		fmt.Printf("\n  Testing endpoint: %s\n", endpoint)

		allowedCount := 0
		for i := 1; i <= 5; i++ {
			request := &ratelimit.RateLimitCheckRequest{
				UserID:     userID,
				OrgID:      "demo-org-1",
				Endpoint:   endpoint,
				Method:     "POST",
				ClientIP:   "192.168.1.102",
				TokenCount: 500,
				Timestamp:  time.Now(),
			}

			response, err := manager.CheckRateLimit(context.Background(), request)
			if err != nil {
				continue
			}

			if response.Allowed {
				allowedCount++
				fmt.Printf("    Request %d: ✅ ALLOWED\n", i)
			} else {
				fmt.Printf("    Request %d: ❌ DENIED (%s)\n", i, response.DenialReason)
			}

			time.Sleep(50 * time.Millisecond)
		}

		fmt.Printf("    Summary: %d/5 requests allowed for %s\n", allowedCount, endpoint)
	}
}

func runOrgDemo(manager *ratelimit.RateLimitManager) {
	fmt.Println("Testing organization-level rate limits...")

	orgID := "demo-org-limits"
	users := []string{"user-1", "user-2", "user-3"}

	totalAllowed := 0
	totalRequests := 0

	for _, userID := range users {
		fmt.Printf("\n  Testing requests from user: %s\n", userID)

		for i := 1; i <= 3; i++ {
			request := &ratelimit.RateLimitCheckRequest{
				UserID:     userID,
				OrgID:      orgID,
				Endpoint:   "/v1/chat/completions",
				Method:     "POST",
				ClientIP:   fmt.Sprintf("192.168.1.%d", 103+len(userID)),
				TokenCount: 1000,
				Timestamp:  time.Now(),
			}

			response, err := manager.CheckRateLimit(context.Background(), request)
			totalRequests++

			if err != nil {
				continue
			}

			if response.Allowed {
				totalAllowed++
				fmt.Printf("    Request %d: ✅ ALLOWED", i)
			} else {
				fmt.Printf("    Request %d: ❌ DENIED (%s)", i, response.DenialReason)
			}

			// Show org limit status
			if orgLimit, exists := response.OrgLimits["per_minute"]; exists {
				fmt.Printf(" [Org usage: %d/%d]", orgLimit.CurrentCount, orgLimit.Limit)
			}
			fmt.Println()

			time.Sleep(100 * time.Millisecond)
		}
	}

	fmt.Printf("\n  Organization summary: %d/%d total requests allowed\n", totalAllowed, totalRequests)
} 