package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"ai-gateway-poc/internal/analysis"
	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("🚀 AI Gateway Task 3.2: Real-Time Policy Evaluation Engine Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	fmt.Println("📋 REAL-TIME ENGINE FEATURES")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println("✅ <200ms latency target performance")
	fmt.Println("✅ Multi-layer caching (policy, result, condition)")
	fmt.Println("✅ Parallel policy evaluation")
	fmt.Println("✅ Circuit breaker for resilience")
	fmt.Println("✅ Comprehensive metrics and health monitoring")
	fmt.Println("✅ Real-time performance tracking")
	fmt.Println()

	// Initialize real-time engine
	config := &policy.RealTimeConfig{
		MaxLatency:          200 * time.Millisecond,
		MaxConcurrency:      10,
		WorkerPoolSize:      5,
		PolicyCacheTTL:      5 * time.Minute,
		ResultCacheTTL:      1 * time.Minute,
		ConditionCacheTTL:   30 * time.Second,
		MaxCacheSize:        1000,
		FailureThreshold:    5,
		RecoveryTimeout:     30 * time.Second,
		MetricsEnabled:      true,
		HealthCheckInterval: 10 * time.Second,
	}

	engine := policy.NewRealTimePolicyEngine(config)
	defer engine.Shutdown(context.Background())

	// Demo 1: Engine Initialization and Setup
	fmt.Println("🏗️ DEMO 1: REAL-TIME ENGINE INITIALIZATION")
	fmt.Println(strings.Repeat("-", 40))

	// Add sample policies
	policies := policy.CreateSamplePolicies()
	for _, pol := range policies {
		err := engine.AddPolicy(pol)
		if err != nil {
			fmt.Printf("❌ Failed to add policy: %v\n", err)
		} else {
			fmt.Printf("✅ Added policy: %s\n", pol.Name)
		}
	}

	// Show initial health
	health := engine.GetHealth()
	fmt.Printf("🏥 Engine Health: %s (Score: %.2f)\n", 
		healthStatus(health.IsHealthy), health.HealthScore)
	fmt.Printf("⏰ Uptime: %v\n", time.Since(health.UptimeStart))
	fmt.Println()

	// Demo 2: Performance Benchmarking
	fmt.Println("⚡ DEMO 2: PERFORMANCE BENCHMARKING")
	fmt.Println(strings.Repeat("-", 40))

	testRequests := createTestRequests()
	ctx := context.Background()

	fmt.Printf("🎯 Target Latency: <200ms\n")
	fmt.Printf("📊 Running %d test evaluations...\n", len(testRequests))
	fmt.Println()

	var totalLatency time.Duration
	var maxLatency time.Duration
	var minLatency time.Duration = time.Hour // Initialize to large value
	var under200ms int
	var under50ms int
	var under10ms int

	for i, request := range testRequests {
		start := time.Now()
		result, err := engine.EvaluateRealTime(ctx, request)
		latency := time.Since(start)

		totalLatency += latency
		if latency > maxLatency {
			maxLatency = latency
		}
		if latency < minLatency {
			minLatency = latency
		}

		if latency < 200*time.Millisecond {
			under200ms++
		}
		if latency < 50*time.Millisecond {
			under50ms++
		}
		if latency < 10*time.Millisecond {
			under10ms++
		}

		status := "✅"
		if err != nil {
			status = "❌"
		} else if latency > 200*time.Millisecond {
			status = "⚠️"
		}

		fmt.Printf("  %s Request %d: %v (%s) -> %s\n", 
			status, i+1, latency, request.ID, 
			getActionEmoji(result.Decision.Action))
	}

	avgLatency := totalLatency / time.Duration(len(testRequests))
	
	fmt.Println()
	fmt.Println("📈 PERFORMANCE RESULTS")
	fmt.Println(strings.Repeat("-", 30))
	fmt.Printf("Average Latency: %v\n", avgLatency)
	fmt.Printf("Min Latency: %v\n", minLatency)
	fmt.Printf("Max Latency: %v\n", maxLatency)
	fmt.Printf("Under 10ms: %d/%d (%.1f%%)\n", under10ms, len(testRequests), float64(under10ms)/float64(len(testRequests))*100)
	fmt.Printf("Under 50ms: %d/%d (%.1f%%)\n", under50ms, len(testRequests), float64(under50ms)/float64(len(testRequests))*100)
	fmt.Printf("Under 200ms: %d/%d (%.1f%%)\n", under200ms, len(testRequests), float64(under200ms)/float64(len(testRequests))*100)

	if avgLatency < 200*time.Millisecond {
		fmt.Printf("🎉 TARGET ACHIEVED: Average latency under 200ms!\n")
	} else {
		fmt.Printf("❌ TARGET MISSED: Average latency exceeds 200ms\n")
	}
	fmt.Println()

	// Demo 3: Cache Performance
	fmt.Println("💾 DEMO 3: CACHE PERFORMANCE DEMONSTRATION")
	fmt.Println(strings.Repeat("-", 40))

	// Test cache performance with identical requests
	cacheTestRequest := &policy.PolicyEvaluationRequest{
		ID:           "cache-performance-test",
		Content:      "Cache test: SSN 123-45-6789",
		ContentType:  "text",
		Organization: "cache-test-org",
		User:         "cache-user",
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

	// First request (cache miss)
	fmt.Printf("🔄 First evaluation (cache miss)...\n")
	start1 := time.Now()
	result1, err1 := engine.EvaluateRealTime(ctx, cacheTestRequest)
	latency1 := time.Since(start1)

	if err1 != nil {
		fmt.Printf("❌ Cache miss failed: %v\n", err1)
	} else {
		fmt.Printf("  ✅ Cache miss: %v -> %s\n", latency1, result1.Decision.Action)
	}

	// Second request (cache hit)
	fmt.Printf("🔄 Second evaluation (cache hit)...\n")
	start2 := time.Now()
	result2, err2 := engine.EvaluateRealTime(ctx, cacheTestRequest)
	latency2 := time.Since(start2)

	if err2 != nil {
		fmt.Printf("❌ Cache hit failed: %v\n", err2)
	} else {
		fmt.Printf("  ✅ Cache hit: %v -> %s\n", latency2, result2.Decision.Action)
		if latency1 > latency2 {
			fmt.Printf("  🚀 Cache speedup: %.2fx faster\n", float64(latency1)/float64(latency2))
		}
	}
	fmt.Println()

	// Demo 4: Concurrent Load Testing
	fmt.Println("🔥 DEMO 4: CONCURRENT LOAD TESTING")
	fmt.Println(strings.Repeat("-", 40))

	const numWorkers = 10
	const requestsPerWorker = 50
	const totalRequests = numWorkers * requestsPerWorker

	fmt.Printf("🚀 Starting %d concurrent workers\n", numWorkers)
	fmt.Printf("📊 %d requests per worker (%d total)\n", requestsPerWorker, totalRequests)

	var wg sync.WaitGroup
	results := make(chan time.Duration, totalRequests)
	loadTestStart := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < requestsPerWorker; j++ {
				request := &policy.PolicyEvaluationRequest{
					ID:           fmt.Sprintf("load-test-w%d-r%d", workerID, j),
					Content:      fmt.Sprintf("Load test content from worker %d request %d", workerID, j),
					ContentType:  "text",
					Organization: "load-test-org",
					Analysis: &analysis.AnalysisResult{
						PIIDetection: &analysis.PIIDetectionResult{
							HasPII: j%3 == 0, // Vary PII detection
						},
						Confidence: 0.8 + float64(j%20)/100, // Vary confidence
					},
				}

				requestStart := time.Now()
				_, err := engine.EvaluateRealTime(ctx, request)
				requestLatency := time.Since(requestStart)

				if err != nil {
					fmt.Printf("❌ Worker %d request %d failed: %v\n", workerID, j, err)
				}

				results <- requestLatency
			}
		}(i)
	}

	wg.Wait()
	close(results)
	loadTestDuration := time.Since(loadTestStart)

	// Analyze load test results
	var loadLatencies []time.Duration
	var loadTotalLatency time.Duration
	var loadMaxLatency time.Duration
	var loadUnder200ms int

	for latency := range results {
		loadLatencies = append(loadLatencies, latency)
		loadTotalLatency += latency
		if latency > loadMaxLatency {
			loadMaxLatency = latency
		}
		if latency < 200*time.Millisecond {
			loadUnder200ms++
		}
	}

	loadAvgLatency := loadTotalLatency / time.Duration(len(loadLatencies))
	throughput := float64(totalRequests) / loadTestDuration.Seconds()

	fmt.Printf("⚡ Load Test Results:\n")
	fmt.Printf("  Total Duration: %v\n", loadTestDuration)
	fmt.Printf("  Average Latency: %v\n", loadAvgLatency)
	fmt.Printf("  Max Latency: %v\n", loadMaxLatency)
	fmt.Printf("  Throughput: %.2f req/sec\n", throughput)
	fmt.Printf("  Under 200ms: %d/%d (%.1f%%)\n", loadUnder200ms, totalRequests, float64(loadUnder200ms)/float64(totalRequests)*100)
	fmt.Println()

	// Demo 5: Engine Metrics and Health
	fmt.Println("📊 DEMO 5: METRICS AND HEALTH MONITORING")
	fmt.Println(strings.Repeat("-", 40))

	metrics := engine.GetMetrics()
	health = engine.GetHealth()

	fmt.Printf("📈 Performance Metrics:\n")
	fmt.Printf("  Total Requests: %d\n", metrics.TotalRequests)
	fmt.Printf("  Average Latency: %v\n", metrics.AverageLatency)
	fmt.Printf("  Max Latency: %v\n", metrics.MaxLatency)
	fmt.Printf("  P95 Latency: %v\n", metrics.P95Latency)
	fmt.Printf("  P99 Latency: %v\n", metrics.P99Latency)
	fmt.Println()

	fmt.Printf("💾 Cache Performance:\n")
	fmt.Printf("  Result Cache Hits: %d\n", metrics.ResultCacheHits)
	fmt.Printf("  Result Cache Misses: %d\n", metrics.ResultCacheMisses)
	if metrics.ResultCacheHits+metrics.ResultCacheMisses > 0 {
		hitRate := float64(metrics.ResultCacheHits) / float64(metrics.ResultCacheHits+metrics.ResultCacheMisses) * 100
		fmt.Printf("  Cache Hit Rate: %.1f%%\n", hitRate)
	}
	fmt.Println()

	fmt.Printf("🏥 Engine Health:\n")
	fmt.Printf("  Status: %s\n", healthStatus(health.IsHealthy))
	fmt.Printf("  Health Score: %.2f/1.0\n", health.HealthScore)
	fmt.Printf("  Last Check: %v ago\n", time.Since(health.LastHealthCheck))
	fmt.Printf("  Uptime: %v\n", time.Since(health.UptimeStart))
	if len(health.Issues) > 0 {
		fmt.Printf("  Issues: %s\n", strings.Join(health.Issues, ", "))
	} else {
		fmt.Printf("  Issues: None ✅\n")
	}
	fmt.Println()

	fmt.Printf("🔧 System Resources:\n")
	fmt.Printf("  Goroutines: %d\n", metrics.GoroutineCount)
	fmt.Printf("  Errors: %d\n", metrics.EvaluationErrors)
	fmt.Printf("  Timeouts: %d\n", metrics.TimeoutErrors)
	fmt.Println()

	// Demo 6: Latency Distribution
	fmt.Println("📊 DEMO 6: LATENCY DISTRIBUTION ANALYSIS")
	fmt.Println(strings.Repeat("-", 40))

	fmt.Printf("Latency Histogram:\n")
	for _, bucket := range metrics.LatencyHistogram {
		if bucket.Count > 0 {
			fmt.Printf("  ≤%v: %d requests\n", bucket.UpperBound, bucket.Count)
		}
	}
	fmt.Println()

	// Final Summary
	fmt.Println("🎉 TASK 3.2 IMPLEMENTATION COMPLETE!")
	fmt.Println(strings.Repeat("-", 40))
	
	targetMet := avgLatency < 200*time.Millisecond
	fmt.Printf("🎯 Performance Target (<200ms): %s\n", passFailStatus(targetMet))
	fmt.Printf("📊 Average Latency: %v\n", avgLatency)
	fmt.Printf("🚀 Peak Throughput: %.2f req/sec\n", throughput)
	fmt.Printf("💾 Cache Hit Rate: %.1f%%\n", float64(metrics.ResultCacheHits)/float64(metrics.ResultCacheHits+metrics.ResultCacheMisses)*100)
	fmt.Printf("🏥 Engine Health: %s\n", healthStatus(health.IsHealthy))
	fmt.Println()
	
	if targetMet {
		fmt.Println("✅ Real-time policy evaluation engine successfully meets <200ms target!")
		fmt.Println("🚀 Ready for Task 3.3: Policy conflict resolution!")
	} else {
		fmt.Println("⚠️  Performance target not consistently met - optimization needed")
	}
}

func createTestRequests() []*policy.PolicyEvaluationRequest {
	return []*policy.PolicyEvaluationRequest{
		{
			ID:           "high-pii-confidence",
			Content:      "SSN: 123-45-6789, Credit Card: 4532-1234-5678-9012",
			ContentType:  "text",
			Organization: "test-org",
			User:         "test-user",
			Analysis: &analysis.AnalysisResult{
				PIIDetection: &analysis.PIIDetectionResult{
					HasPII: true,
					Statistics: analysis.PIIStatistics{
						ConfidenceAvg: 0.98,
					},
				},
				Confidence: 0.98,
			},
		},
		{
			ID:           "confidential-content",
			Content:      "CONFIDENTIAL: Strategic business plan for Q4",
			ContentType:  "text",
			Organization: "test-org",
			User:         "manager",
			Analysis: &analysis.AnalysisResult{
				Classification: &analysis.ClassificationResult{
					Level: analysis.SensitivityConfidential,
				},
				Confidence: 0.92,
			},
		},
		{
			ID:           "public-content",
			Content:      "Welcome to our public API documentation",
			ContentType:  "text",
			Organization: "test-org",
			User:         "developer",
			Analysis: &analysis.AnalysisResult{
				PIIDetection: &analysis.PIIDetectionResult{HasPII: false},
				Classification: &analysis.ClassificationResult{
					Level: analysis.SensitivityPublic,
				},
				Confidence: 0.95,
			},
		},
		{
			ID:           "mixed-content",
			Content:      "Internal memo with email contact@company.com",
			ContentType:  "text",
			Organization: "test-org",
			User:         "employee",
			Analysis: &analysis.AnalysisResult{
				PIIDetection: &analysis.PIIDetectionResult{
					HasPII: true,
					Statistics: analysis.PIIStatistics{
						ConfidenceAvg: 0.75,
					},
				},
				Classification: &analysis.ClassificationResult{
					Level: analysis.SensitivityInternal,
				},
				Confidence: 0.85,
			},
		},
		{
			ID:           "no-analysis",
			Content:      "Simple text without analysis",
			ContentType:  "text",
			Organization: "test-org",
			User:         "guest",
			Analysis: &analysis.AnalysisResult{
				PIIDetection: &analysis.PIIDetectionResult{HasPII: false},
				Confidence:   0.5,
			},
		},
	}
}

func healthStatus(isHealthy bool) string {
	if isHealthy {
		return "🟢 Healthy"
	}
	return "🔴 Unhealthy"
}

func passFailStatus(passed bool) string {
	if passed {
		return "✅ PASSED"
	}
	return "❌ FAILED"
}

func getActionEmoji(action policy.ActionType) string {
	switch action {
	case policy.ActionAllow:
		return "✅ Allow"
	case policy.ActionBlock:
		return "🚫 Block"
	case policy.ActionRedact:
		return "✂️ Redact"
	case policy.ActionWarn:
		return "⚠️ Warn"
	case policy.ActionMask:
		return "🎭 Mask"
	default:
		return "❓ Unknown"
	}
} 