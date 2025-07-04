package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAdvancedTestCacheManager(t *testing.T) (*ResponseCacheManager, *redis.Client) {
	// Start mini Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	
	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	
	// Create cache config with advanced features enabled
	config := &CacheConfig{
		RedisKeyPrefix:       "test:cache:",
		DefaultTTL:           1 * time.Hour,
		MaxRequestSize:       1024 * 1024,
		MaxResponseSize:      10 * 1024 * 1024,
		CompressionThreshold: 1024,
		CompressionEnabled:   true,
		MemoryCacheEnabled:   true,
		MemoryCacheSize:      100,
		MemoryCacheTTL:       5 * time.Minute,
		TTLPolicies: map[string]time.Duration{
			"chat":       15 * time.Minute,
			"completion": 30 * time.Minute,
			"embedding":  2 * time.Hour,
			"default":    1 * time.Hour,
		},
		InvalidationEnabled:  true,
		MetricsEnabled:       true,
		HealthCheckInterval:  30 * time.Second,
		
		// Enable advanced features
		AdvancedFeaturesEnabled: true,
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests
	
	manager, err := NewResponseCacheManager(rdb, config, logger)
	require.NoError(t, err)
	
	// Clean up function
	t.Cleanup(func() {
		rdb.Close()
		mr.Close()
	})
	
	return manager, rdb
}

func createTestAdvancedRequest(url string, requestType string) *CacheRequest {
	return &CacheRequest{
		Method:         "POST",
		URL:            url,
		Headers:        map[string]string{"Content-Type": "application/json"},
		Body:           `{"test": "data"}`,
		UserID:         "test-user",
		OrganizationID: "test-org",
		RequestType:    requestType,
		Timestamp:      time.Now(),
		ClientIP:       "192.168.1.1",
	}
}

func createTestResponse() *CacheResponse {
	return &CacheResponse{
		StatusCode:  200,
		Headers:     map[string]string{"Content-Type": "application/json"},
		Body:        `{"result": "test response"}`,
		ContentType: "application/json",
		CachedAt:    time.Now(),
	}
}

// Test Dynamic TTL Calculation
func TestDynamicTTLCalculation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	testCases := []struct {
		name        string
		confidence  float64
		sensitivity string
		hasPII      bool
		baseTTL     time.Duration
		expectMultiplier float64
	}{
		{"High Confidence", 0.95, "public", false, 1 * time.Hour, 2.0},
		{"Medium Confidence", 0.75, "internal", false, 1 * time.Hour, 1.0},
		{"Low Confidence", 0.45, "confidential", false, 1 * time.Hour, 0.5},
		{"PII Content", 0.9, "internal", true, 1 * time.Hour, 0.3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := createTestAdvancedRequest("/api/test/"+tc.name, "chat")
			response := createTestResponse()

			analysisCtx := &TTLCalculationContext{
				Request:  request,
				Response: response,
				ContentAnalysis: &ContentAnalysis{
					Confidence:  tc.confidence,
					Sensitivity: tc.sensitivity,
					HasPII:      tc.hasPII,
					ContentType: "chat",
				},
				CurrentTime: time.Now(),
			}

			err := manager.SetAdvanced(ctx, request, response, analysisCtx)
			assert.NoError(t, err)

			cached, err := manager.Get(ctx, request)
			assert.NoError(t, err)
			assert.NotNil(t, cached)

			// Verify TTL is within expected range (allowing for calculation variations)
			expectedTTL := time.Duration(float64(tc.baseTTL) * tc.expectMultiplier)
			assert.True(t, cached.TTL >= expectedTTL*90/100 && cached.TTL <= expectedTTL*110/100,
				"TTL %v not within expected range of %v", cached.TTL, expectedTTL)
		})
	}
}

// Test User and Organization-Specific TTL
func TestUserOrgSpecificTTL(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	testCases := []struct {
		name   string
		userID string
		orgID  string
		tier   string
		role   string
	}{
		{"Enterprise User", "premium-user", "enterprise-org", "enterprise", "admin"},
		{"Pro User", "standard-user", "pro-org", "pro", "user"},
		{"Free User", "free-user", "free-org", "free", "user"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := createTestAdvancedRequest("/api/user/"+tc.userID, "completion")
			request.UserID = tc.userID
			request.OrganizationID = tc.orgID
			
			response := createTestResponse()

			analysisCtx := &TTLCalculationContext{
				UserInfo: &UserInfo{
					ID:   tc.userID,
					Role: tc.role,
					UsagePattern: &UserUsagePattern{
						AverageRequestsPerHour: 50.0,
						CacheHitRate:          0.7,
					},
				},
				OrgInfo: &OrgInfo{
					ID:   tc.orgID,
					Tier: tc.tier,
					UsagePattern: &OrgUsagePattern{
						AverageRequestsPerHour: 1000.0,
						ActiveUsers:           25,
					},
				},
				CurrentTime: time.Now(),
			}

			err := manager.SetAdvanced(ctx, request, response, analysisCtx)
			assert.NoError(t, err)

			cached, err := manager.Get(ctx, request)
			assert.NoError(t, err)
			assert.NotNil(t, cached)
			assert.Greater(t, cached.TTL, time.Duration(0))
		})
	}
}

// Test Time-Based TTL Adjustments
func TestTimeBasedTTL(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	testCases := []struct {
		name string
		time time.Time
		expectMultiplier float64
	}{
		{"Business Hours", time.Date(2024, 1, 2, 14, 0, 0, 0, time.UTC), 1.0}, // Tuesday 2PM
		{"Off Hours", time.Date(2024, 1, 2, 22, 0, 0, 0, time.UTC), 2.0},     // Tuesday 10PM
		{"Weekend", time.Date(2024, 1, 6, 14, 0, 0, 0, time.UTC), 3.0},       // Saturday 2PM
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := createTestAdvancedRequest("/api/time/"+tc.name, "embedding")
			response := createTestResponse()

			analysisCtx := &TTLCalculationContext{
				Request:     request,
				Response:    response,
				CurrentTime: tc.time,
				ContentAnalysis: &ContentAnalysis{
					Confidence:  0.8,
					Sensitivity: "internal",
				},
			}

			err := manager.SetAdvanced(ctx, request, response, analysisCtx)
			assert.NoError(t, err)

			cached, err := manager.Get(ctx, request)
			assert.NoError(t, err)
			assert.NotNil(t, cached)
			assert.Greater(t, cached.TTL, time.Duration(0))
		})
	}
}

// Test Tag-Based Invalidation
func TestTagBasedInvalidation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// Create cache entries with different tags
	entries := []struct {
		url  string
		tags []string
	}{
		{"/api/users/123", []string{"user", "profile", "user123"}},
		{"/api/orgs/456", []string{"org", "data", "org456"}},
		{"/api/ai/completions", []string{"ai", "model", "gpt-4"}},
		{"/api/users/123/history", []string{"user", "ai", "history", "user123"}},
		{"/api/config", []string{"system", "config"}},
	}

	// Cache all entries
	for _, entry := range entries {
		request := createTestAdvancedRequest(entry.url, "data")
		request.Tags = entry.tags
		response := createTestResponse()

		err := manager.SetAdvanced(ctx, request, response, &TTLCalculationContext{})
		assert.NoError(t, err)
	}

	// Test tag-based invalidation
	result, err := manager.InvalidateByTags(ctx, []string{"user123"})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 2, int(result.KeysRemoved)) // Should remove 2 entries with user123 tag

	// Verify entries are actually removed
	userRequest := createTestAdvancedRequest("/api/users/123", "data")
	userRequest.Tags = []string{"user", "profile", "user123"}
	cached, err := manager.Get(ctx, userRequest)
	assert.NoError(t, err)
	assert.Nil(t, cached) // Should be nil because it was invalidated
}

// Test Dependency-Based Invalidation
func TestDependencyInvalidation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// Create cache entries with dependencies
	dependencies := []struct {
		url          string
		dependencies []string
	}{
		{"/api/users/123", []string{}},                                          // Base entry
		{"/api/users/123/preferences", []string{"/api/users/123"}},              // Depends on base
		{"/api/users/123/stats", []string{"/api/users/123", "/api/users/123/preferences"}}, // Depends on both
	}

	// Cache all entries with dependencies
	for _, dep := range dependencies {
		request := createTestAdvancedRequest(dep.url, "data")
		request.Dependencies = dep.dependencies
		response := createTestResponse()

		err := manager.SetAdvanced(ctx, request, response, &TTLCalculationContext{})
		assert.NoError(t, err)
	}

	// Test dependency invalidation
	invalidationManager := manager.GetInvalidationManager()
	assert.NotNil(t, invalidationManager)

	result, err := invalidationManager.InvalidateByDependency(ctx, "/api/users/123")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, result.KeysRemoved, int64(0))
}

// Test Event-Driven Invalidation
func TestEventDrivenInvalidation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// Register event listener
	listener := &EventListener{
		ID:        "test-listener",
		EventType: "user_updated",
		Tags:      []string{"user", "profile"},
		Enabled:   true,
		Priority:  1,
	}

	err := manager.AddEventListener(listener)
	assert.NoError(t, err)

	// Create cache entry to be invalidated
	request := createTestAdvancedRequest("/api/users/123/profile", "data")
	request.Tags = []string{"user", "profile"}
	response := createTestResponse()

	err = manager.SetAdvanced(ctx, request, response, &TTLCalculationContext{})
	assert.NoError(t, err)

	// Trigger invalidation event
	event := &InvalidationEvent{
		ID:        "test-event-001",
		Type:      "user_updated",
		Source:    "test",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"user_id": "123",
		},
		Priority: 1,
	}

	err = manager.InvalidateByEvent(event)
	assert.NoError(t, err)

	// Allow time for event processing
	time.Sleep(50 * time.Millisecond)
}

// Test Scheduled Invalidation
func TestScheduledInvalidation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)

	// Create scheduled invalidation task
	schedule := &ScheduledInvalidation{
		ID:      "test-schedule",
		Name:    "Test Cleanup",
		Enabled: true,
		Schedule: &InvalidationSchedule{
			Type:       "interval",
			Expression: "1m",
		},
		Tags:        []string{"temporary"},
		Description: "Test scheduled cleanup",
	}

	err := manager.AddScheduledInvalidation(schedule)
	assert.NoError(t, err)
}

// Test User-Specific Invalidation
func TestUserSpecificInvalidation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// Create user-specific cache entries
	userID := "test-user-123"
	
	for i := 0; i < 3; i++ {
		request := createTestAdvancedRequest("/api/user/data/"+userID, "data")
		request.UserID = userID
		response := createTestResponse()

		err := manager.SetAdvanced(ctx, request, response, &TTLCalculationContext{})
		assert.NoError(t, err)
	}

	// Test user-specific invalidation
	result, err := manager.InvalidateByUser(ctx, userID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

// Test Organization-Specific Invalidation
func TestOrgSpecificInvalidation(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// Create org-specific cache entries
	orgID := "test-org-456"
	
	for i := 0; i < 3; i++ {
		request := createTestAdvancedRequest("/api/org/data/"+orgID, "data")
		request.OrganizationID = orgID
		response := createTestResponse()

		err := manager.SetAdvanced(ctx, request, response, &TTLCalculationContext{})
		assert.NoError(t, err)
	}

	// Test org-specific invalidation
	result, err := manager.InvalidateByOrganization(ctx, orgID)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

// Test Advanced Metrics
func TestAdvancedMetrics(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// Perform some cache operations
	request := createTestAdvancedRequest("/api/metrics/test", "chat")
	response := createTestResponse()

	err := manager.SetAdvanced(ctx, request, response, &TTLCalculationContext{
		ContentAnalysis: &ContentAnalysis{
			Confidence:  0.8,
			Sensitivity: "internal",
		},
	})
	assert.NoError(t, err)

	// Get cached response
	cached, err := manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, cached)

	// Check metrics
	metrics := manager.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Greater(t, metrics.TotalRequests, int64(0))

	// Check TTL manager
	ttlManager := manager.GetTTLPolicyManager()
	assert.NotNil(t, ttlManager)

	// Check invalidation manager
	invalidationManager := manager.GetInvalidationManager()
	assert.NotNil(t, invalidationManager)
}

// Test TTL Policy Manager Features
func TestTTLPolicyManagerFeatures(t *testing.T) {
	config := getDefaultTTLPolicyConfig()
	assert.NotNil(t, config)

	manager := NewTTLPolicyManager(config)
	assert.NotNil(t, manager)

	// Test TTL calculation with various contexts
	ctx := &TTLCalculationContext{
		Request: &CacheRequest{
			RequestType: "chat",
		},
		ContentAnalysis: &ContentAnalysis{
			Confidence:  0.9,
			Sensitivity: "public",
			HasPII:      false,
		},
		CurrentTime: time.Now(),
	}

	ttl, err := manager.CalculateTTL(ctx)
	assert.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0))
}

// Test Invalidation Manager Features
func TestInvalidationManagerFeatures(t *testing.T) {
	// Start mini Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	
	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer rdb.Close()

	config := getDefaultInvalidationConfig()
	assert.NotNil(t, config)

	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel)

	manager := NewInvalidationManager(rdb, config, logger)
	assert.NotNil(t, manager)
	
	defer manager.Shutdown()

	ctx := context.Background()

	// Test pattern invalidation
	result, err := manager.InvalidateByPattern(ctx, []string{"test:*"})
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Test dependency addition
	dependency := &Dependency{
		ID:        "test-dep",
		SourceKey: "source",
		TargetKey: "target",
		Type:      "strong",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err = manager.AddDependency(dependency)
	assert.NoError(t, err)

	// Test tag addition
	err = manager.AddTags("test-key", []string{"tag1", "tag2"})
	assert.NoError(t, err)
}

// Benchmark Advanced TTL Calculation
func BenchmarkAdvancedTTLCalculation(b *testing.B) {
	config := getDefaultTTLPolicyConfig()
	manager := NewTTLPolicyManager(config)

	ctx := &TTLCalculationContext{
		Request: &CacheRequest{
			RequestType: "chat",
		},
		ContentAnalysis: &ContentAnalysis{
			Confidence:  0.85,
			Sensitivity: "internal",
			HasPII:      false,
		},
		UserInfo: &UserInfo{
			ID:   "bench-user",
			Role: "user",
		},
		OrgInfo: &OrgInfo{
			ID:   "bench-org",
			Tier: "pro",
		},
		CurrentTime: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.CalculateTTL(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark Advanced Cache Operations
func BenchmarkAdvancedCacheOperations(b *testing.B) {
	manager, _ := setupAdvancedTestCacheManager(&testing.T{})
	ctx := context.Background()

	request := createTestAdvancedRequest("/api/bench/test", "chat")
	request.Tags = []string{"benchmark", "test"}
	response := createTestResponse()

	analysisCtx := &TTLCalculationContext{
		ContentAnalysis: &ContentAnalysis{
			Confidence:  0.8,
			Sensitivity: "internal",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Set with advanced features
		err := manager.SetAdvanced(ctx, request, response, analysisCtx)
		if err != nil {
			b.Fatal(err)
		}

		// Get from cache
		_, err = manager.Get(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test Configuration Validation
func TestConfigurationValidation(t *testing.T) {
	// Test default TTL policy config
	config := getDefaultTTLPolicyConfig()
	assert.NotNil(t, config)
	assert.True(t, config.DynamicTTLEnabled)
	assert.NotNil(t, config.ConfidenceBasedTTL)
	assert.NotNil(t, config.SensitivityBasedTTL)
	assert.NotNil(t, config.BusinessHours)

	// Test default invalidation config
	invalidationConfig := getDefaultInvalidationConfig()
	assert.NotNil(t, invalidationConfig)
	assert.True(t, invalidationConfig.EventDrivenEnabled)
	assert.True(t, invalidationConfig.TagBasedEnabled)
	assert.True(t, invalidationConfig.DependencyEnabled)
}

// Integration Test for Complete Advanced Features
func TestAdvancedFeaturesIntegration(t *testing.T) {
	manager, _ := setupAdvancedTestCacheManager(t)
	ctx := context.Background()

	// 1. Test advanced TTL calculation
	request := createTestAdvancedRequest("/api/integration/test", "chat")
	request.Tags = []string{"integration", "test", "user123"}
	request.Dependencies = []string{"base-resource"}
	response := createTestResponse()

	analysisCtx := &TTLCalculationContext{
		Request:  request,
		Response: response,
		ContentAnalysis: &ContentAnalysis{
			Confidence:  0.9,
			Sensitivity: "internal",
			HasPII:      false,
		},
		UserInfo: &UserInfo{
			ID:   "test-user",
			Role: "admin",
		},
		OrgInfo: &OrgInfo{
			ID:   "test-org",
			Tier: "enterprise",
		},
		CurrentTime: time.Now(),
	}

	err := manager.SetAdvanced(ctx, request, response, analysisCtx)
	assert.NoError(t, err)

	// 2. Verify cache entry exists
	cached, err := manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, cached)

	// 3. Test tag-based invalidation
	result, err := manager.InvalidateByTags(ctx, []string{"user123"})
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// 4. Verify entry was invalidated
	cached, err = manager.Get(ctx, request)
	assert.NoError(t, err)
	assert.Nil(t, cached)

	// 5. Test metrics collection
	metrics := manager.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Greater(t, metrics.TotalRequests, int64(0))

	// 6. Test health status
	health := manager.GetHealthStatus()
	assert.NotNil(t, health)
	assert.True(t, health.RedisConnected)
} 