package policy

import (
	"crypto/md5"
	"fmt"
	"runtime"
	"time"
)

// PolicyCache methods
func (pc *PolicyCache) get(id string) *CachedPolicy {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	
	cached, exists := pc.cache[id]
	if !exists {
		return nil
	}
	
	// Check TTL
	if time.Since(cached.CachedAt) > pc.ttl {
		delete(pc.cache, id)
		return nil
	}
	
	// Update hit statistics
	cached.HitCount++
	cached.LastHit = time.Now()
	
	return cached
}

func (pc *PolicyCache) set(id string, policy *Policy) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	pc.cache[id] = &CachedPolicy{
		Policy:   policy,
		CachedAt: time.Now(),
		HitCount: 0,
		LastHit:  time.Now(),
	}
}

func (pc *PolicyCache) invalidate(id string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	delete(pc.cache, id)
}

func (pc *PolicyCache) clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	
	pc.cache = make(map[string]*CachedPolicy)
}

func (pc *PolicyCache) size() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	
	return len(pc.cache)
}

// EvaluationCache methods
func (ec *EvaluationCache) get(request *PolicyEvaluationRequest) *CachedEvaluation {
	hash := generateRequestHash(request)
	
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	
	cached, exists := ec.cache[hash]
	if !exists {
		return nil
	}
	
	// Check TTL
	if time.Since(cached.CachedAt) > ec.ttl {
		delete(ec.cache, hash)
		return nil
	}
	
	// Update hit statistics
	cached.HitCount++
	
	return cached
}

func (ec *EvaluationCache) set(request *PolicyEvaluationRequest, result *PolicyEvaluationResult) {
	hash := generateRequestHash(request)
	
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	ec.cache[hash] = &CachedEvaluation{
		Result:   result,
		Hash:     hash,
		CachedAt: time.Now(),
		HitCount: 0,
	}
}

func (ec *EvaluationCache) clear() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	
	ec.cache = make(map[string]*CachedEvaluation)
}

func (ec *EvaluationCache) size() int {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	
	return len(ec.cache)
}

// ConditionCache methods
func (cc *ConditionCache) get(key string) *CachedCondition {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	
	cached, exists := cc.cache[key]
	if !exists {
		return nil
	}
	
	// Check TTL
	if time.Since(cached.CachedAt) > cc.ttl {
		delete(cc.cache, key)
		return nil
	}
	
	return cached
}

func (cc *ConditionCache) set(key string, result bool) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	cc.cache[key] = &CachedCondition{
		Result:   result,
		Hash:     key,
		CachedAt: time.Now(),
	}
}

func (cc *ConditionCache) clear() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	
	cc.cache = make(map[string]*CachedCondition)
}

// Helper functions for cache key generation
func generateRequestHash(request *PolicyEvaluationRequest) string {
	// Create a deterministic hash of the request
	hasher := md5.New()
	
	// Include key fields that affect evaluation
	hasher.Write([]byte(request.Content))
	hasher.Write([]byte(request.ContentType))
	hasher.Write([]byte(request.Organization))
	hasher.Write([]byte(request.User))
	
	// Include analysis results if present
	if request.Analysis != nil {
		if request.Analysis.PIIDetection != nil {
			hasher.Write([]byte(fmt.Sprintf("%t", request.Analysis.PIIDetection.HasPII)))
		}
		if request.Analysis.Classification != nil {
			hasher.Write([]byte(string(request.Analysis.Classification.Level)))
		}
		hasher.Write([]byte(fmt.Sprintf("%.2f", request.Analysis.Confidence)))
	}
	
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func (rte *RealTimePolicyEngine) generateConditionCacheKey(condition *PolicyCondition, request *PolicyEvaluationRequest) string {
	hasher := md5.New()
	
	// Include condition details
	hasher.Write([]byte(string(condition.Type)))
	if condition.Value != nil {
		hasher.Write([]byte(fmt.Sprintf("%v", condition.Value)))
	}
	if condition.Field != "" {
		hasher.Write([]byte(condition.Field))
	}
	
	// Include relevant request data
	if request.Analysis != nil {
		if condition.Type == ConditionPIIDetected && request.Analysis.PIIDetection != nil {
			hasher.Write([]byte(fmt.Sprintf("%t", request.Analysis.PIIDetection.HasPII)))
		}
		if condition.Type == ConditionSensitivityLevel && request.Analysis.Classification != nil {
			hasher.Write([]byte(string(request.Analysis.Classification.Level)))
		}
		if condition.Type == ConditionConfidenceAbove {
			hasher.Write([]byte(fmt.Sprintf("%.2f", request.Analysis.Confidence)))
		}
	}
	
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// EngineMetrics implementations
func newEngineMetrics() *EngineMetrics {
	return &EngineMetrics{
		LatencyHistogram: initializeLatencyHistogram(),
	}
}

func initializeLatencyHistogram() []LatencyBucket {
	return []LatencyBucket{
		{UpperBound: 1 * time.Millisecond, Count: 0},
		{UpperBound: 5 * time.Millisecond, Count: 0},
		{UpperBound: 10 * time.Millisecond, Count: 0},
		{UpperBound: 25 * time.Millisecond, Count: 0},
		{UpperBound: 50 * time.Millisecond, Count: 0},
		{UpperBound: 100 * time.Millisecond, Count: 0},
		{UpperBound: 200 * time.Millisecond, Count: 0},
		{UpperBound: 500 * time.Millisecond, Count: 0},
		{UpperBound: 1 * time.Second, Count: 0},
	}
}

func (em *EngineMetrics) recordLatency(latency time.Duration) {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	em.TotalRequests++
	
	// Update average latency (rolling average)
	if em.TotalRequests == 1 {
		em.AverageLatency = latency
	} else {
		// Exponential moving average
		alpha := 0.1
		em.AverageLatency = time.Duration(float64(em.AverageLatency)*(1-alpha) + float64(latency)*alpha)
	}
	
	// Update max latency
	if latency > em.MaxLatency {
		em.MaxLatency = latency
	}
	
	// Update histogram
	for i := range em.LatencyHistogram {
		if latency <= em.LatencyHistogram[i].UpperBound {
			em.LatencyHistogram[i].Count++
			break
		}
	}
	
	// Update percentiles (simplified - in production use a proper quantile estimator)
	em.updatePercentiles(latency)
}

func (em *EngineMetrics) updatePercentiles(latency time.Duration) {
	// Simplified percentile calculation
	// In production, use a proper streaming quantile algorithm
	if em.TotalRequests%100 == 0 {
		// Recalculate every 100 requests
		em.P95Latency = time.Duration(float64(em.MaxLatency) * 0.95)
		em.P99Latency = time.Duration(float64(em.MaxLatency) * 0.99)
	}
}

func (em *EngineMetrics) recordCacheHit(cacheType string) {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	switch cacheType {
	case "policy":
		em.PolicyCacheHits++
	case "result":
		em.ResultCacheHits++
	}
}

func (em *EngineMetrics) recordCacheMiss(cacheType string) {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	switch cacheType {
	case "policy":
		em.PolicyCacheMisses++
	case "result":
		em.ResultCacheMisses++
	}
}

func (em *EngineMetrics) recordTimeout() {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	em.TimeoutErrors++
}

func (em *EngineMetrics) recordError(err error) {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	em.EvaluationErrors++
}

func (em *EngineMetrics) recordCircuitBreakerTrip() {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	em.CircuitBreakerTrips++
}

func (em *EngineMetrics) snapshot() *EngineMetrics {
	em.mu.RLock()
	defer em.mu.RUnlock()
	
	// Create a deep copy
	snapshot := &EngineMetrics{
		TotalRequests:       em.TotalRequests,
		AverageLatency:      em.AverageLatency,
		P95Latency:          em.P95Latency,
		P99Latency:          em.P99Latency,
		MaxLatency:          em.MaxLatency,
		PolicyCacheHits:     em.PolicyCacheHits,
		PolicyCacheMisses:   em.PolicyCacheMisses,
		ResultCacheHits:     em.ResultCacheHits,
		ResultCacheMisses:   em.ResultCacheMisses,
		TimeoutErrors:       em.TimeoutErrors,
		EvaluationErrors:    em.EvaluationErrors,
		CircuitBreakerTrips: em.CircuitBreakerTrips,
		RequestsPerSecond:   em.RequestsPerSecond,
		PeakRPS:            em.PeakRPS,
		GoroutineCount:     runtime.NumGoroutine(),
	}
	
	// Copy histogram
	snapshot.LatencyHistogram = make([]LatencyBucket, len(em.LatencyHistogram))
	copy(snapshot.LatencyHistogram, em.LatencyHistogram)
	
	return snapshot
}

// HealthMonitor implementations
func newHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		IsHealthy:       true,
		UptimeStart:     time.Now(),
		HealthScore:     1.0,
		Issues:          []string{},
		LastHealthCheck: time.Now(),
	}
}

func (hm *HealthMonitor) updateHealth(metrics *EngineMetrics) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.LastHealthCheck = time.Now()
	hm.Issues = []string{}
	
	score := 1.0
	
	// Check latency
	if metrics.AverageLatency > 150*time.Millisecond {
		score -= 0.2
		hm.Issues = append(hm.Issues, "High average latency")
	}
	
	// Check error rates
	if metrics.TotalRequests > 0 {
		errorRate := float64(metrics.EvaluationErrors) / float64(metrics.TotalRequests)
		if errorRate > 0.05 { // 5% error rate
			score -= 0.3
			hm.Issues = append(hm.Issues, "High error rate")
		}
	}
	
	// Check circuit breaker
	if metrics.CircuitBreakerTrips > 0 {
		score -= 0.1
		hm.Issues = append(hm.Issues, "Circuit breaker trips detected")
	}
	
	// Check memory usage (simplified)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	if memStats.Alloc > 100*1024*1024 { // 100MB
		score -= 0.1
		hm.Issues = append(hm.Issues, "High memory usage")
	}
	
	hm.HealthScore = score
	hm.IsHealthy = score > 0.7
}

func (hm *HealthMonitor) snapshot() *HealthMonitor {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	// Create a copy
	issues := make([]string, len(hm.Issues))
	copy(issues, hm.Issues)
	
	return &HealthMonitor{
		IsHealthy:       hm.IsHealthy,
		LastHealthCheck: hm.LastHealthCheck,
		HealthScore:     hm.HealthScore,
		Issues:          issues,
		UptimeStart:     hm.UptimeStart,
	}
}

// CircuitBreaker implementations
func newCircuitBreaker(config *RealTimeConfig) *CircuitBreaker {
	return &CircuitBreaker{
		state:  CircuitClosed,
		config: config,
	}
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		return time.Now().After(cb.nextRetry)
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.failureCount = 0
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
	}
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	cb.failureCount++
	cb.lastFailure = time.Now()
	
	if cb.failureCount >= int64(cb.config.FailureThreshold) {
		cb.state = CircuitOpen
		cb.nextRetry = time.Now().Add(cb.config.RecoveryTimeout)
	}
}

// WorkerPool implementations
func newWorkerPool(size int) *WorkerPool {
	return &WorkerPool{
		workers:    size,
		jobQueue:   make(chan *EvaluationJob, size*2),
		resultChan: make(chan *EvaluationJobResult, size*2),
		quit:       make(chan struct{}),
	}
}

// Invalidation methods
func (rte *RealTimePolicyEngine) invalidateCaches() {
	rte.policyCache.clear()
	rte.resultCache.clear()
	rte.conditionCache.clear()
}

// Background tasks
func (rte *RealTimePolicyEngine) startBackgroundTasks() {
	// Start health monitoring
	if rte.config.MetricsEnabled {
		rte.wg.Add(1)
		go rte.healthMonitoringLoop()
	}
	
	// Start cache cleanup
	rte.wg.Add(1)
	go rte.cacheCleanupLoop()
}

func (rte *RealTimePolicyEngine) healthMonitoringLoop() {
	defer rte.wg.Done()
	
	ticker := time.NewTicker(rte.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			metrics := rte.metrics.snapshot()
			rte.healthMonitor.updateHealth(metrics)
		case <-rte.shutdownChan:
			return
		}
	}
}

func (rte *RealTimePolicyEngine) cacheCleanupLoop() {
	defer rte.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute) // Cleanup every minute
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Cleanup would go here - for now just log cache sizes
			// In production, implement proper LRU eviction
		case <-rte.shutdownChan:
			return
		}
	}
} 