package policy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"ai-gateway-poc/internal/analysis"
)

func TestRealTimePolicyEngine_NewEngine(t *testing.T) {
	engine := NewRealTimePolicyEngine(nil)
	
	if engine == nil {
		t.Fatal("Expected non-nil real-time engine")
	}
	
	if engine.config.MaxLatency != 200*time.Millisecond {
		t.Errorf("Expected 200ms max latency, got %v", engine.config.MaxLatency)
	}
	
	if engine.metrics == nil {
		t.Fatal("Expected metrics to be initialized")
	}
	
	if engine.healthMonitor == nil {
		t.Fatal("Expected health monitor to be initialized")
	}
	
	defer engine.Shutdown(context.Background())
}

func TestRealTimePolicyEngine_EvaluateRealTime(t *testing.T) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add sample policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		err := engine.AddPolicy(policy)
		if err != nil {
			t.Fatalf("Failed to add policy: %v", err)
		}
	}
	
	testCases := []struct {
		name           string
		request        *PolicyEvaluationRequest
		expectedAction ActionType
		maxLatency     time.Duration
	}{
		{
			name: "PII Detection - Should be fast",
			request: &PolicyEvaluationRequest{
				ID:           "test-pii-fast",
				Content:      "SSN: 123-45-6789",
				ContentType:  "text",
				Organization: "test-org",
				Analysis: &analysis.AnalysisResult{
					PIIDetection: &analysis.PIIDetectionResult{
						HasPII: true,
						Statistics: analysis.PIIStatistics{
							ConfidenceAvg: 0.95,
						},
					},
					Confidence: 0.95,
				},
			},
			expectedAction: ActionBlock,
			maxLatency:     50 * time.Millisecond,
		},
		{
			name: "Confidential Content - Should be fast",
			request: &PolicyEvaluationRequest{
				ID:           "test-confidential-fast",
				Content:      "Confidential data",
				ContentType:  "text",
				Organization: "test-org",
				Analysis: &analysis.AnalysisResult{
					Classification: &analysis.ClassificationResult{
						Level: analysis.SensitivityConfidential,
					},
					Confidence: 0.9,
				},
			},
			expectedAction: ActionRedact,
			maxLatency:     50 * time.Millisecond,
		},
		{
			name: "Public Content - Should be fastest",
			request: &PolicyEvaluationRequest{
				ID:           "test-public-fast",
				Content:      "Public announcement",
				ContentType:  "text",
				Organization: "test-org",
				Analysis: &analysis.AnalysisResult{
					PIIDetection: &analysis.PIIDetectionResult{
						HasPII: false,
					},
					Classification: &analysis.ClassificationResult{
						Level: analysis.SensitivityPublic,
					},
					Confidence: 0.9,
				},
			},
			expectedAction: ActionAllow,
			maxLatency:     10 * time.Millisecond,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			
			ctx := context.Background()
			result, err := engine.EvaluateRealTime(ctx, tc.request)
			
			latency := time.Since(start)
			
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}
			
			if result.Decision.Action != tc.expectedAction {
				t.Errorf("Expected action %s, got %s", tc.expectedAction, result.Decision.Action)
			}
			
			if latency > tc.maxLatency {
				t.Errorf("Latency %v exceeded maximum %v", latency, tc.maxLatency)
			}
			
			// Verify performance target
			if latency > 200*time.Millisecond {
				t.Errorf("Failed 200ms performance target: %v", latency)
			}
			
			t.Logf("Evaluation completed in %v (target: %v)", latency, tc.maxLatency)
		})
	}
}

func TestRealTimePolicyEngine_Caching(t *testing.T) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add a policy
	policies := CreateSamplePolicies()
	err := engine.AddPolicy(policies[0])
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}
	
	request := &PolicyEvaluationRequest{
		ID:           "cache-test",
		Content:      "SSN: 123-45-6789",
		ContentType:  "text",
		Organization: "test-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{
				HasPII: true,
				Statistics: analysis.PIIStatistics{
					ConfidenceAvg: 0.95,
				},
			},
			Confidence: 0.95,
		},
	}
	
	ctx := context.Background()
	
	// First evaluation - cache miss
	start1 := time.Now()
	result1, err := engine.EvaluateRealTime(ctx, request)
	latency1 := time.Since(start1)
	
	if err != nil {
		t.Fatalf("First evaluation failed: %v", err)
	}
	
	// Second evaluation - cache hit
	start2 := time.Now()
	result2, err := engine.EvaluateRealTime(ctx, request)
	latency2 := time.Since(start2)
	
	if err != nil {
		t.Fatalf("Second evaluation failed: %v", err)
	}
	
	// Verify cache hit is faster
	if latency2 >= latency1 {
		t.Errorf("Cache hit (%v) should be faster than cache miss (%v)", latency2, latency1)
	}
	
	// Verify results are identical
	if result1.Decision.Action != result2.Decision.Action {
		t.Errorf("Cached result differs from original")
	}
	
	// Check metrics
	metrics := engine.GetMetrics()
	if metrics.ResultCacheHits == 0 {
		t.Errorf("Expected cache hits, got %d", metrics.ResultCacheHits)
	}
	
	t.Logf("Cache miss: %v, Cache hit: %v (%.2fx faster)", 
		latency1, latency2, float64(latency1)/float64(latency2))
}

func TestRealTimePolicyEngine_CircuitBreaker(t *testing.T) {
	config := &RealTimeConfig{
		MaxLatency:          200 * time.Millisecond,
		FailureThreshold:    2, // Low threshold for testing
		RecoveryTimeout:     100 * time.Millisecond,
		MetricsEnabled:      true,
		HealthCheckInterval: 100 * time.Millisecond, // Add proper health check interval
		PolicyCacheTTL:      1 * time.Minute,
		ResultCacheTTL:      30 * time.Second,
		ConditionCacheTTL:   10 * time.Second,
		MaxConcurrency:      5,
		WorkerPoolSize:      3,
		MaxCacheSize:        100,
	}
	
	engine := NewRealTimePolicyEngine(config)
	defer engine.Shutdown(context.Background())
	
	// Simulate failures by forcing timeout
	shortTimeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	
	request := &PolicyEvaluationRequest{
		ID:      "circuit-breaker-test",
		Content: "test content",
	}
	
	// Trigger failures to open circuit breaker
	for i := 0; i < 3; i++ {
		_, err := engine.EvaluateRealTime(shortTimeoutCtx, request)
		if err == nil {
			t.Errorf("Expected timeout error on attempt %d", i+1)
		}
	}
	
	// Circuit breaker should be open now
	normalCtx := context.Background()
	_, err := engine.EvaluateRealTime(normalCtx, request)
	if err == nil || err.Error() != "circuit breaker is open" {
		t.Errorf("Expected circuit breaker to be open, got: %v", err)
	}
	
	// Wait for recovery timeout
	time.Sleep(150 * time.Millisecond)
	
	// Circuit should allow requests again
	_, err = engine.EvaluateRealTime(normalCtx, request)
	if err != nil && err.Error() == "circuit breaker is open" {
		t.Errorf("Circuit breaker should have recovered, got: %v", err)
	}
}

func TestRealTimePolicyEngine_HealthMonitoring(t *testing.T) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Initial health should be good
	health := engine.GetHealth()
	if !health.IsHealthy {
		t.Errorf("Expected engine to be healthy initially")
	}
	
	if health.HealthScore != 1.0 {
		t.Errorf("Expected perfect health score initially, got %f", health.HealthScore)
	}
	
	// Wait for a health check cycle
	time.Sleep(100 * time.Millisecond)
	
	// Health should still be good
	health = engine.GetHealth()
	if !health.IsHealthy {
		t.Errorf("Expected engine to remain healthy")
	}
}

func TestRealTimePolicyEngine_Metrics(t *testing.T) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		engine.AddPolicy(policy)
	}
	
	request := &PolicyEvaluationRequest{
		ID:           "metrics-test",
		Content:      "test content",
		ContentType:  "text",
		Organization: "test-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{HasPII: false},
			Confidence:   0.9,
		},
	}
	
	ctx := context.Background()
	
	// Perform multiple evaluations
	for i := 0; i < 10; i++ {
		_, err := engine.EvaluateRealTime(ctx, request)
		if err != nil {
			t.Fatalf("Evaluation %d failed: %v", i+1, err)
		}
	}
	
	// Check metrics
	metrics := engine.GetMetrics()
	
	if metrics.TotalRequests < 10 {
		t.Errorf("Expected at least 10 requests, got %d", metrics.TotalRequests)
	}
	
	if metrics.AverageLatency <= 0 {
		t.Errorf("Expected positive average latency, got %v", metrics.AverageLatency)
	}
	
	if metrics.AverageLatency > 200*time.Millisecond {
		t.Errorf("Average latency %v exceeds 200ms target", metrics.AverageLatency)
	}
	
	t.Logf("Metrics: %d requests, avg latency: %v", metrics.TotalRequests, metrics.AverageLatency)
}

// Benchmark tests for performance validation
func BenchmarkRealTimePolicyEngine_SimpleEvaluation(b *testing.B) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add a simple policy
	policies := CreateSamplePolicies()
	engine.AddPolicy(policies[0])
	
	request := &PolicyEvaluationRequest{
		ID:           "benchmark-simple",
		Content:      "test content",
		ContentType:  "text",
		Organization: "test-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{HasPII: false},
			Confidence:   0.9,
		},
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateRealTime(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRealTimePolicyEngine_ComplexEvaluation(b *testing.B) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add multiple policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		engine.AddPolicy(policy)
	}
	
	request := &PolicyEvaluationRequest{
		ID:           "benchmark-complex",
		Content:      "Complex content with SSN 123-45-6789 and confidential data",
		ContentType:  "text",
		Organization: "test-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{
				HasPII: true,
				Statistics: analysis.PIIStatistics{
					ConfidenceAvg: 0.95,
				},
			},
			Classification: &analysis.ClassificationResult{
				Level: analysis.SensitivityConfidential,
			},
			Confidence: 0.95,
		},
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateRealTime(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRealTimePolicyEngine_CachedEvaluation(b *testing.B) {
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		engine.AddPolicy(policy)
	}
	
	request := &PolicyEvaluationRequest{
		ID:           "benchmark-cached",
		Content:      "Cached content test",
		ContentType:  "text",
		Organization: "test-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{HasPII: false},
			Confidence:   0.9,
		},
	}
	
	ctx := context.Background()
	
	// Warm up cache
	engine.EvaluateRealTime(ctx, request)
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateRealTime(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Performance stress test
func TestRealTimePolicyEngine_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	
	engine := NewRealTimePolicyEngine(nil)
	defer engine.Shutdown(context.Background())
	
	// Add policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		engine.AddPolicy(policy)
	}
	
	const numRequests = 1000
	const maxLatency = 200 * time.Millisecond
	
	requests := make([]*PolicyEvaluationRequest, numRequests)
	for i := 0; i < numRequests; i++ {
		requests[i] = &PolicyEvaluationRequest{
			ID:           fmt.Sprintf("stress-test-%d", i),
			Content:      fmt.Sprintf("Stress test content %d", i),
			ContentType:  "text",
			Organization: "test-org",
			Analysis: &analysis.AnalysisResult{
				PIIDetection: &analysis.PIIDetectionResult{HasPII: i%2 == 0},
				Confidence:   0.9,
			},
		}
	}
	
	ctx := context.Background()
	start := time.Now()
	
	var slowRequests int
	for i, request := range requests {
		requestStart := time.Now()
		_, err := engine.EvaluateRealTime(ctx, request)
		requestLatency := time.Since(requestStart)
		
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
		
		if requestLatency > maxLatency {
			slowRequests++
		}
	}
	
	totalTime := time.Since(start)
	avgLatency := totalTime / numRequests
	throughput := float64(numRequests) / totalTime.Seconds()
	
	t.Logf("Stress test results:")
	t.Logf("  Total requests: %d", numRequests)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Average latency: %v", avgLatency)
	t.Logf("  Throughput: %.2f req/sec", throughput)
	t.Logf("  Slow requests (>200ms): %d (%.2f%%)", slowRequests, float64(slowRequests)/float64(numRequests)*100)
	
	// Performance assertions
	if avgLatency > maxLatency {
		t.Errorf("Average latency %v exceeds maximum %v", avgLatency, maxLatency)
	}
	
	if float64(slowRequests)/float64(numRequests) > 0.05 { // Allow 5% slow requests
		t.Errorf("Too many slow requests: %d/%d (%.2f%%)", slowRequests, numRequests, float64(slowRequests)/float64(numRequests)*100)
	}
	
	// Check final metrics
	metrics := engine.GetMetrics()
	if metrics.TotalRequests < int64(numRequests) {
		t.Errorf("Expected %d requests in metrics, got %d", numRequests, metrics.TotalRequests)
	}
} 