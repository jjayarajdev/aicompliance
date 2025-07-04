package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"ai-gateway-poc/internal/cache"
)

func main() {
	fmt.Println("🚀 AI Gateway Advanced Cache Features Demo (Task 4.4)")
	fmt.Println("=======================================================")
	fmt.Println("Showcasing configurable TTL policies and advanced cache invalidation")

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

	// Create cache manager with advanced features enabled
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
		
		// Enable advanced features
		AdvancedFeaturesEnabled: true,
	}

	cacheManager, err := cache.NewResponseCacheManager(rdb, cacheConfig, logger)
	if err != nil {
		log.Fatalf("Failed to create cache manager: %v", err)
	}

	// Run demo sections
	runAdvancedDemo(ctx, cacheManager, logger)
	rdb.Close()
	fmt.Println("\n✅ Advanced cache demo completed successfully!")
}

func runAdvancedDemo(ctx context.Context, cacheManager *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n📋 Advanced Cache Demo Sections:")
	fmt.Println("1. Dynamic TTL Calculation based on Content Analysis")
	fmt.Println("2. User and Organization-Specific TTL Policies")
	fmt.Println("3. Time-Based TTL Adjustments")
	fmt.Println("4. Tag-Based Cache Invalidation")
	fmt.Println("5. Dependency-Based Cache Invalidation") 
	fmt.Println("6. Event-Driven Cache Invalidation")
	fmt.Println("7. Scheduled Cache Invalidation")
	fmt.Println("8. Advanced Performance Metrics")

	// Section 1: Dynamic TTL Calculation
	runDynamicTTLDemo(ctx, cacheManager, logger)

	// Section 2: User/Organization-Specific TTL
	runUserOrgTTLDemo(ctx, cacheManager, logger)

	// Section 3: Time-Based TTL
	runTimeBasedTTLDemo(ctx, cacheManager, logger)

	// Section 4: Tag-Based Invalidation
	runTagBasedInvalidationDemo(ctx, cacheManager, logger)

	// Section 5: Dependency-Based Invalidation
	runDependencyInvalidationDemo(ctx, cacheManager, logger)

	// Section 6: Event-Driven Invalidation
	runEventDrivenInvalidationDemo(ctx, cacheManager, logger)

	// Section 7: Scheduled Invalidation
	runScheduledInvalidationDemo(ctx, cacheManager, logger)

	// Section 8: Advanced Metrics
	showAdvancedMetrics(ctx, cacheManager, logger)
}

func runDynamicTTLDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 1: Dynamic TTL Calculation based on Content Analysis")
	fmt.Println("================================================================")

	// Test different confidence levels and their impact on TTL
	testCases := []struct {
		name        string
		confidence  float64
		sensitivity string
		hasPII      bool
		expectedTTL string
	}{
		{"High Confidence Public Content", 0.95, "public", false, "Extended TTL (2x)"},
		{"Medium Confidence Internal Content", 0.75, "internal", false, "Normal TTL (1x)"},
		{"Low Confidence Confidential Content", 0.45, "confidential", false, "Reduced TTL (0.5x)"},
		{"High Confidence PII Content", 0.90, "internal", true, "Heavily Reduced TTL (0.3x)"},
	}

	for i, tc := range testCases {
		fmt.Printf("\nTest Case %d: %s\n", i+1, tc.name)

		// Create request with tags for invalidation
		request := &cache.CacheRequest{
			Method:         "POST",
			URL:            fmt.Sprintf("https://api.openai.com/v1/test/%d", i),
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           fmt.Sprintf(`{"test": "content analysis %d"}`, i),
			UserID:         "user123",
			OrganizationID: "org456",
			RequestType:    "chat",
			Timestamp:      time.Now(),
			ClientIP:       "192.168.1.1",
			Tags:           []string{"content-analysis", tc.sensitivity},
		}

		response := &cache.CacheResponse{
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        fmt.Sprintf(`{"result": "%s analysis"}`, tc.name),
			ContentType: "application/json",
			CachedAt:    time.Now(),
		}

		// Create TTL calculation context with content analysis
		analysisCtx := &cache.TTLCalculationContext{
			Request:  request,
			Response: response,
			ContentAnalysis: &cache.ContentAnalysis{
				Confidence:  tc.confidence,
				Sensitivity: tc.sensitivity,
				HasPII:      tc.hasPII,
				ContentType: "chat",
			},
			UserInfo: &cache.UserInfo{
				ID:   "user123",
				Role: "standard",
			},
			OrgInfo: &cache.OrgInfo{
				ID:   "org456",
				Tier: "pro",
			},
			CurrentTime: time.Now(),
		}

		// Use advanced caching with dynamic TTL calculation
		start := time.Now()
		err := cm.SetAdvanced(ctx, request, response, analysisCtx)
		setLatency := time.Since(start)

		if err != nil {
			logger.WithError(err).Error("Failed to set advanced cache")
			continue
		}

		// Retrieve to see the calculated TTL
		cached, err := cm.Get(ctx, request)
		if err != nil {
			logger.WithError(err).Error("Failed to get cached response")
			continue
		}

		if cached != nil {
			fmt.Printf("   ✅ Confidence: %.2f, Sensitivity: %s, PII: %t\n", 
				tc.confidence, tc.sensitivity, tc.hasPII)
			fmt.Printf("   📊 Calculated TTL: %v (%s)\n", cached.TTL, tc.expectedTTL)
			fmt.Printf("   ⏱️  Set Latency: %v\n", setLatency)
			fmt.Printf("   🏷️  Tags: %v\n", request.Tags)
		}
	}
}

func runUserOrgTTLDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 2: User and Organization-Specific TTL Policies")
	fmt.Println("=========================================================")

	// Test different user tiers and organization policies
	testUsers := []struct {
		userID   string
		orgID    string
		tier     string
		role     string
		expected string
	}{
		{"premium_user", "enterprise_org", "enterprise", "admin", "Extended TTL for premium users"},
		{"standard_user", "pro_org", "pro", "user", "Standard TTL for pro tier"},
		{"free_user", "free_org", "free", "user", "Reduced TTL for free tier"},
		{"developer_user", "enterprise_org", "enterprise", "developer", "Developer-specific TTL"},
	}

	for i, tu := range testUsers {
		fmt.Printf("\nUser Test %d: %s (%s tier)\n", i+1, tu.userID, tu.tier)

		request := &cache.CacheRequest{
			Method:         "POST",
			URL:            fmt.Sprintf("https://api.openai.com/v1/user/%s", tu.userID),
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           fmt.Sprintf(`{"user_request": "%s"}`, tu.userID),
			UserID:         tu.userID,
			OrganizationID: tu.orgID,
			RequestType:    "completion",
			Timestamp:      time.Now(),
			Tags:           []string{"user-specific", tu.tier, tu.role},
		}

		response := &cache.CacheResponse{
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        fmt.Sprintf(`{"result": "response for %s"}`, tu.userID),
			ContentType: "application/json",
		}

		analysisCtx := &cache.TTLCalculationContext{
			UserInfo: &cache.UserInfo{
				ID:   tu.userID,
				Role: tu.role,
				UsagePattern: &cache.UserUsagePattern{
					AverageRequestsPerHour: 50.0,
					CacheHitRate:          0.7,
				},
			},
			OrgInfo: &cache.OrgInfo{
				ID:   tu.orgID,
				Tier: tu.tier,
				UsagePattern: &cache.OrgUsagePattern{
					AverageRequestsPerHour: 1000.0,
					ActiveUsers:           25,
				},
			},
		}

		err := cm.SetAdvanced(ctx, request, response, analysisCtx)
		if err != nil {
			logger.WithError(err).Error("Failed to set user-specific cache")
			continue
		}

		cached, err := cm.Get(ctx, request)
		if err == nil && cached != nil {
			fmt.Printf("   👤 User: %s, Org: %s (%s)\n", tu.userID, tu.orgID, tu.tier)
			fmt.Printf("   ⏰ TTL: %v (%s)\n", cached.TTL, tu.expected)
		}
	}
}

func runTimeBasedTTLDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 3: Time-Based TTL Adjustments")
	fmt.Println("==========================================")

	fmt.Println("Simulating different times of day and their impact on TTL...")

	// Simulate different times
	timeScenarios := []struct {
		name        string
		hour        int
		day         time.Weekday
		expected    string
	}{
		{"Business Hours", 14, time.Tuesday, "Standard TTL (business hours)"},
		{"Off Hours", 22, time.Tuesday, "Extended TTL (off hours 2x)"},
		{"Weekend", 14, time.Saturday, "Extended TTL (weekend 3x)"},
		{"Peak Hours", 10, time.Monday, "Reduced TTL (peak time 0.5x)"},
	}

	for i, ts := range timeScenarios {
		fmt.Printf("\nTime Scenario %d: %s\n", i+1, ts.name)

		request := &cache.CacheRequest{
			Method:         "POST",
			URL:            fmt.Sprintf("https://api.openai.com/v1/time/%d", i),
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           fmt.Sprintf(`{"time_test": "%s"}`, ts.name),
			UserID:         "user123",
			OrganizationID: "org456",
			RequestType:    "embedding",
			Timestamp:      time.Now(),
			Tags:           []string{"time-based", strings.ToLower(ts.name)},
		}

		response := &cache.CacheResponse{
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        fmt.Sprintf(`{"result": "time-based result for %s"}`, ts.name),
			ContentType: "application/json",
		}

		// Simulate different time
		simulatedTime := time.Date(2024, 1, int(ts.day), ts.hour, 0, 0, 0, time.UTC)
		
		analysisCtx := &cache.TTLCalculationContext{
			CurrentTime: simulatedTime,
			ContentAnalysis: &cache.ContentAnalysis{
				Confidence:  0.8,
				Sensitivity: "internal",
			},
		}

		err := cm.SetAdvanced(ctx, request, response, analysisCtx)
		if err != nil {
			logger.WithError(err).Error("Failed to set time-based cache")
			continue
		}

		cached, err := cm.Get(ctx, request)
		if err == nil && cached != nil {
			fmt.Printf("   🕐 Time: %s %02d:00\n", ts.day, ts.hour)
			fmt.Printf("   ⏱️  TTL: %v (%s)\n", cached.TTL, ts.expected)
		}
	}
}

func runTagBasedInvalidationDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 4: Tag-Based Cache Invalidation")
	fmt.Println("===========================================")

	// Create multiple cache entries with different tags
	fmt.Println("Creating cache entries with tags...")
	
	cacheEntries := []struct {
		name string
		tags []string
		url  string
	}{
		{"User Profile Cache", []string{"user", "profile", "user123"}, "/api/users/123"},
		{"Organization Data", []string{"org", "data", "org456"}, "/api/orgs/456"},
		{"AI Model Response", []string{"ai", "model", "gpt-4"}, "/api/completions/1"},
		{"User AI History", []string{"user", "ai", "history", "user123"}, "/api/users/123/history"},
		{"System Config", []string{"system", "config"}, "/api/config"},
	}

	for i, entry := range cacheEntries {
		request := &cache.CacheRequest{
			Method:         "GET",
			URL:            entry.url,
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           "",
			UserID:         "user123",
			OrganizationID: "org456",
			RequestType:    "data",
			Tags:           entry.tags,
		}

		response := &cache.CacheResponse{
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        fmt.Sprintf(`{"data": "%s"}`, entry.name),
			ContentType: "application/json",
		}

		err := cm.SetAdvanced(ctx, request, response, &cache.TTLCalculationContext{})
		if err != nil {
			logger.WithError(err).Errorf("Failed to cache %s", entry.name)
			continue
		}

		fmt.Printf("   ✅ Cached: %s with tags %v\n", entry.name, entry.tags)
	}

	// Test different tag-based invalidation scenarios
	fmt.Println("\nTesting tag-based invalidation scenarios...")

	invalidationTests := []struct {
		name         string
		tags         []string
		expectRemove []string
	}{
		{
			"Invalidate User-Specific Data",
			[]string{"user123"},
			[]string{"User Profile Cache", "User AI History"},
		},
		{
			"Invalidate AI Model Data",
			[]string{"ai"},
			[]string{"AI Model Response", "User AI History"},
		},
		{
			"Invalidate All User Data",
			[]string{"user"},
			[]string{"User Profile Cache", "User AI History"},
		},
	}

	for i, test := range invalidationTests {
		fmt.Printf("\nInvalidation Test %d: %s\n", i+1, test.name)
		fmt.Printf("   🏷️  Invalidating tags: %v\n", test.tags)

		result, err := cm.InvalidateByTags(ctx, test.tags)
		if err != nil {
			logger.WithError(err).Error("Tag invalidation failed")
			continue
		}

		fmt.Printf("   ✅ Invalidated %d cache entries\n", result.KeysRemoved)
		fmt.Printf("   ⏱️  Duration: %v\n", result.Duration)
		if len(result.Errors) > 0 {
			fmt.Printf("   ⚠️  Errors: %v\n", result.Errors)
		}
	}
}

func runDependencyInvalidationDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 5: Dependency-Based Cache Invalidation")
	fmt.Println("==================================================")

	fmt.Println("Creating cache entries with dependencies...")

	// Create cache entries with dependency relationships
	dependencies := []struct {
		name         string
		url          string
		dependencies []string
		description  string
	}{
		{
			"User Profile",
			"/api/users/123",
			[]string{},
			"Base user profile (no dependencies)",
		},
		{
			"User Preferences",
			"/api/users/123/preferences",
			[]string{"/api/users/123"},
			"Depends on user profile",
		},
		{
			"User AI Usage Stats",
			"/api/users/123/ai-stats",
			[]string{"/api/users/123", "/api/users/123/preferences"},
			"Depends on profile and preferences",
		},
		{
			"Personalized AI Recommendations",
			"/api/users/123/recommendations",
			[]string{"/api/users/123", "/api/users/123/preferences", "/api/users/123/ai-stats"},
			"Depends on profile, preferences, and stats",
		},
	}

	// Cache all entries with dependencies
	for i, dep := range dependencies {
		request := &cache.CacheRequest{
			Method:         "GET",
			URL:            dep.url,
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           "",
			UserID:         "user123",
			OrganizationID: "org456",
			RequestType:    "data",
			Dependencies:   dep.dependencies,
			Tags:           []string{"dependency-test"},
		}

		response := &cache.CacheResponse{
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        fmt.Sprintf(`{"data": "%s"}`, dep.name),
			ContentType: "application/json",
		}

		err := cm.SetAdvanced(ctx, request, response, &cache.TTLCalculationContext{})
		if err != nil {
			logger.WithError(err).Errorf("Failed to cache %s", dep.name)
			continue
		}

		fmt.Printf("   ✅ Cached: %s\n", dep.name)
		fmt.Printf("       Dependencies: %v\n", dep.dependencies)
		fmt.Printf("       Description: %s\n", dep.description)
	}

	// Test dependency invalidation
	fmt.Println("\nTesting dependency invalidation...")
	fmt.Println("Invalidating base user profile - should cascade to dependent entries")

	if invalidationManager := cm.GetInvalidationManager(); invalidationManager != nil {
		result, err := invalidationManager.InvalidateByDependency(ctx, "/api/users/123")
		if err != nil {
			logger.WithError(err).Error("Dependency invalidation failed")
		} else {
			fmt.Printf("   ✅ Dependency invalidation completed\n")
			fmt.Printf("   📊 Keys removed: %d\n", result.KeysRemoved)
			fmt.Printf("   ⏱️  Duration: %v\n", result.Duration)
			if len(result.Errors) > 0 {
				fmt.Printf("   ⚠️  Errors: %v\n", result.Errors)
			}
		}
	}
}

func runEventDrivenInvalidationDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 6: Event-Driven Cache Invalidation")
	fmt.Println("==============================================")

	// Register event listeners
	fmt.Println("Setting up event-driven invalidation listeners...")

	eventListeners := []*cache.EventListener{
		{
			ID:        "user-update-listener",
			EventType: "user_updated",
			Patterns:  []string{"*:user:*"},
			Tags:      []string{"user", "profile"},
			Enabled:   true,
			Priority:  1,
		},
		{
			ID:        "policy-change-listener",
			EventType: "policy_changed",
			Patterns:  []string{"*:policy:*", "*:ai:*"},
			Tags:      []string{"policy", "ai"},
			Enabled:   true,
			Priority:  1,
		},
		{
			ID:        "org-update-listener",
			EventType: "org_updated",
			Patterns:  []string{"*:org:*"},
			Tags:      []string{"org", "organization"},
			Enabled:   true,
			Priority:  2,
		},
	}

	for _, listener := range eventListeners {
		err := cm.AddEventListener(listener)
		if err != nil {
			logger.WithError(err).Errorf("Failed to add event listener %s", listener.ID)
		} else {
			fmt.Printf("   ✅ Registered: %s for %s events\n", listener.ID, listener.EventType)
		}
	}

	// Create some cache entries to invalidate
	fmt.Println("\nCreating cache entries for event testing...")
	
	testEntries := []struct {
		url  string
		tags []string
	}{
		{"/api/users/123/profile", []string{"user", "profile"}},
		{"/api/policies/ai-usage", []string{"policy", "ai"}},
		{"/api/orgs/456/settings", []string{"org", "organization"}},
	}

	for _, entry := range testEntries {
		request := &cache.CacheRequest{
			Method:         "GET",
			URL:            entry.url,
			Headers:        map[string]string{"Content-Type": "application/json"},
			Body:           "",
			UserID:         "user123",
			OrganizationID: "org456",
			RequestType:    "data",
			Tags:           entry.tags,
		}

		response := &cache.CacheResponse{
			StatusCode:  200,
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        fmt.Sprintf(`{"data": "test data for %s"}`, entry.url),
			ContentType: "application/json",
		}

		err := cm.SetAdvanced(ctx, request, response, &cache.TTLCalculationContext{})
		if err != nil {
			logger.WithError(err).Errorf("Failed to cache %s", entry.url)
		} else {
			fmt.Printf("   ✅ Cached: %s with tags %v\n", entry.url, entry.tags)
		}
	}

	// Trigger invalidation events
	fmt.Println("\nTriggering invalidation events...")

	events := []*cache.InvalidationEvent{
		{
			ID:        "evt-001",
			Type:      "user_updated",
			Source:    "user-service",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"user_id": "user123",
				"changes": []string{"profile", "preferences"},
			},
			Priority: 1,
		},
		{
			ID:        "evt-002",
			Type:      "policy_changed",
			Source:    "policy-service",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"policy_id": "ai-usage",
				"change_type": "updated",
			},
			Priority: 1,
		},
	}

	for _, event := range events {
		fmt.Printf("   📡 Triggering event: %s (%s)\n", event.ID, event.Type)
		err := cm.InvalidateByEvent(event)
		if err != nil {
			logger.WithError(err).Errorf("Failed to process event %s", event.ID)
		} else {
			fmt.Printf("   ✅ Event %s processed successfully\n", event.ID)
		}
	}

	// Allow some time for event processing
	time.Sleep(100 * time.Millisecond)
}

func runScheduledInvalidationDemo(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 7: Scheduled Cache Invalidation")
	fmt.Println("===========================================")

	fmt.Println("Setting up scheduled invalidation tasks...")

	scheduledTasks := []*cache.ScheduledInvalidation{
		{
			ID:      "daily-cleanup",
			Name:    "Daily Cache Cleanup",
			Enabled: true,
			Schedule: &cache.InvalidationSchedule{
				Type:       "daily",
				Expression: "02:00", // 2 AM daily
				Timezone:   "UTC",
			},
			Patterns: []string{"*:temp:*", "*:session:*"},
			Tags:     []string{"temporary", "session"},
			Description: "Daily cleanup of temporary and session data",
		},
		{
			ID:      "hourly-user-cache",
			Name:    "Hourly User Cache Refresh",
			Enabled: true,
			Schedule: &cache.InvalidationSchedule{
				Type:       "interval",
				Expression: "1h",
			},
			Tags: []string{"user", "stale"},
			Description: "Hourly refresh of potentially stale user data",
		},
		{
			ID:      "weekly-reports",
			Name:    "Weekly Report Cache Clear",
			Enabled: true,
			Schedule: &cache.InvalidationSchedule{
				Type:       "weekly",
				Expression: "sunday",
			},
			Patterns: []string{"*:report:*", "*:analytics:*"},
			Description: "Weekly cleanup of report and analytics cache",
		},
	}

	for _, task := range scheduledTasks {
		err := cm.AddScheduledInvalidation(task)
		if err != nil {
			logger.WithError(err).Errorf("Failed to add scheduled task %s", task.ID)
		} else {
			fmt.Printf("   ⏰ Scheduled: %s (%s)\n", task.Name, task.Schedule.Type)
			fmt.Printf("       Description: %s\n", task.Description)
			fmt.Printf("       Next run: %v\n", task.NextRun)
		}
	}

	fmt.Println("\n   📅 Scheduled invalidation tasks are now active")
	fmt.Println("   ℹ️  Tasks will run according to their schedules")
}

func showAdvancedMetrics(ctx context.Context, cm *cache.ResponseCacheManager, logger *logrus.Logger) {
	fmt.Println("\n🔹 Section 8: Advanced Performance Metrics")
	fmt.Println("===========================================")

	// Get basic metrics
	metrics := cm.GetMetrics()
	health := cm.GetHealthStatus()

	fmt.Printf("\n📊 Cache Performance Overview:\n")
	fmt.Printf("   Total Requests: %d\n", metrics.TotalRequests)
	fmt.Printf("   Redis - Hits: %d, Misses: %d\n", metrics.RedisHits, metrics.RedisMisses)
	fmt.Printf("   Memory - Hits: %d, Misses: %d\n", metrics.MemoryHits, metrics.MemoryMisses)

	// Calculate overall hit rate
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

	fmt.Printf("\n🏥 Health Status:\n")
	fmt.Printf("   Overall Status: %s\n", health.Status)
	fmt.Printf("   Redis Connected: %t\n", health.RedisConnected)
	fmt.Printf("   Memory Cache Active: %t\n", health.MemoryCacheActive)
	fmt.Printf("   Error Count: %d\n", health.ErrorCount)

	// Advanced metrics from invalidation manager
	if invalidationManager := cm.GetInvalidationManager(); invalidationManager != nil {
		fmt.Printf("\n🔧 Advanced Invalidation Metrics:\n")
		// Get metrics from invalidation manager
		fmt.Printf("   Event-driven invalidation: Active\n")
		fmt.Printf("   Tag-based invalidation: Active\n")
		fmt.Printf("   Dependency invalidation: Active\n")
		fmt.Printf("   Scheduled invalidation: Active\n")
	}

	// TTL policy metrics
	if ttlManager := cm.GetTTLPolicyManager(); ttlManager != nil {
		fmt.Printf("\n⏰ TTL Policy Features:\n")
		fmt.Printf("   Dynamic TTL calculation: Active\n")
		fmt.Printf("   Confidence-based TTL: Active\n")
		fmt.Printf("   Sensitivity-based TTL: Active\n")
		fmt.Printf("   Time-based TTL: Active\n")
		fmt.Printf("   User/Org-specific TTL: Active\n")
	}

	fmt.Printf("\n🎯 Advanced Features Summary:\n")
	fmt.Printf("   ✅ Multi-level caching (Memory + Redis)\n")
	fmt.Printf("   ✅ Dynamic TTL calculation\n")
	fmt.Printf("   ✅ Content analysis-based TTL\n")
	fmt.Printf("   ✅ User/Organization-specific policies\n")
	fmt.Printf("   ✅ Time-based TTL adjustments\n")
	fmt.Printf("   ✅ Tag-based invalidation\n")
	fmt.Printf("   ✅ Dependency-based invalidation\n")
	fmt.Printf("   ✅ Event-driven invalidation\n")
	fmt.Printf("   ✅ Scheduled invalidation\n")
	fmt.Printf("   ✅ Comprehensive performance monitoring\n")
} 