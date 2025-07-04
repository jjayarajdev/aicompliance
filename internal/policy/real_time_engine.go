package policy

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RealTimePolicyEngine provides high-performance policy evaluation with <200ms latency
type RealTimePolicyEngine struct {
	// Core engine
	engine *PolicyEngine
	
	// Performance optimizations
	policyCache    *PolicyCache
	resultCache    *EvaluationCache
	conditionCache *ConditionCache
	
	// Metrics and monitoring
	metrics        *EngineMetrics
	healthMonitor  *HealthMonitor
	
	// Configuration
	config         *RealTimeConfig
	
	// Worker pools for parallel processing
	workerPool     *WorkerPool
	
	// Circuit breaker for resilience
	circuitBreaker *CircuitBreaker
	
	// Shutdown handling
	shutdownChan   chan struct{}
	wg            sync.WaitGroup
	mu            sync.RWMutex
}

// RealTimeConfig configures the real-time engine
type RealTimeConfig struct {
	// Performance targets
	MaxLatency          time.Duration `json:"max_latency"`           // Target <200ms
	MaxConcurrency      int           `json:"max_concurrency"`       // Parallel evaluations
	WorkerPoolSize      int           `json:"worker_pool_size"`      // Worker goroutines
	
	// Caching
	PolicyCacheTTL      time.Duration `json:"policy_cache_ttl"`      // Policy cache TTL
	ResultCacheTTL      time.Duration `json:"result_cache_ttl"`      // Result cache TTL
	ConditionCacheTTL   time.Duration `json:"condition_cache_ttl"`   // Condition cache TTL
	MaxCacheSize        int           `json:"max_cache_size"`        // Max cache entries
	
	// Circuit breaker
	FailureThreshold    int           `json:"failure_threshold"`     // Failures before open
	RecoveryTimeout     time.Duration `json:"recovery_timeout"`      // Recovery attempt interval
	
	// Monitoring
	MetricsEnabled      bool          `json:"metrics_enabled"`       // Enable metrics collection
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Health check frequency
}

// PolicyCache provides fast policy lookup with TTL
type PolicyCache struct {
	cache map[string]*CachedPolicy
	mu    sync.RWMutex
	ttl   time.Duration
}

// CachedPolicy represents a cached policy with metadata
type CachedPolicy struct {
	Policy    *Policy
	CachedAt  time.Time
	HitCount  int64
	LastHit   time.Time
}

// EvaluationCache caches evaluation results for identical requests
type EvaluationCache struct {
	cache map[string]*CachedEvaluation
	mu    sync.RWMutex
	ttl   time.Duration
}

// CachedEvaluation represents a cached evaluation result
type CachedEvaluation struct {
	Result   *PolicyEvaluationResult
	Hash     string
	CachedAt time.Time
	HitCount int64
}

// ConditionCache caches condition evaluation results
type ConditionCache struct {
	cache map[string]*CachedCondition
	mu    sync.RWMutex
	ttl   time.Duration
}

// CachedCondition represents a cached condition result
type CachedCondition struct {
	Result   bool
	Hash     string
	CachedAt time.Time
}

// WorkerPool manages parallel evaluation workers
type WorkerPool struct {
	workers    int
	jobQueue   chan *EvaluationJob
	resultChan chan *EvaluationJobResult
	quit       chan struct{}
	wg         sync.WaitGroup
}

// EvaluationJob represents a policy evaluation job
type EvaluationJob struct {
	ID      string
	Request *PolicyEvaluationRequest
	Timeout time.Duration
}

// EvaluationJobResult represents the result of an evaluation job
type EvaluationJobResult struct {
	JobID  string
	Result *PolicyEvaluationResult
	Error  error
	Latency time.Duration
}

// EngineMetrics tracks performance metrics
type EngineMetrics struct {
	// Latency metrics
	TotalRequests     int64         `json:"total_requests"`
	AverageLatency    time.Duration `json:"average_latency"`
	P95Latency        time.Duration `json:"p95_latency"`
	P99Latency        time.Duration `json:"p99_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	
	// Cache metrics
	PolicyCacheHits   int64         `json:"policy_cache_hits"`
	PolicyCacheMisses int64         `json:"policy_cache_misses"`
	ResultCacheHits   int64         `json:"result_cache_hits"`
	ResultCacheMisses int64         `json:"result_cache_misses"`
	
	// Error metrics
	TimeoutErrors     int64         `json:"timeout_errors"`
	EvaluationErrors  int64         `json:"evaluation_errors"`
	CircuitBreakerTrips int64       `json:"circuit_breaker_trips"`
	
	// Throughput metrics
	RequestsPerSecond float64       `json:"requests_per_second"`
	PeakRPS          float64       `json:"peak_rps"`
	
	// Resource usage
	GoroutineCount   int           `json:"goroutine_count"`
	MemoryUsage      int64         `json:"memory_usage"`
	
	// Latency histogram for detailed analysis
	LatencyHistogram []LatencyBucket `json:"latency_histogram"`
	
	mu sync.RWMutex
}

// LatencyBucket represents a latency histogram bucket
type LatencyBucket struct {
	UpperBound time.Duration `json:"upper_bound"`
	Count      int64         `json:"count"`
}

// HealthMonitor tracks engine health
type HealthMonitor struct {
	IsHealthy        bool          `json:"is_healthy"`
	LastHealthCheck  time.Time     `json:"last_health_check"`
	HealthScore      float64       `json:"health_score"`      // 0.0 to 1.0
	Issues           []string      `json:"issues"`
	UptimeStart      time.Time     `json:"uptime_start"`
	
	mu sync.RWMutex
}

// CircuitBreaker provides resilience against cascading failures
type CircuitBreaker struct {
	state          CircuitState
	failureCount   int64
	lastFailure    time.Time
	nextRetry      time.Time
	config         *RealTimeConfig
	mu            sync.RWMutex
}

// CircuitState represents circuit breaker states
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// NewRealTimePolicyEngine creates a new high-performance policy engine
func NewRealTimePolicyEngine(config *RealTimeConfig) *RealTimePolicyEngine {
	if config == nil {
		config = getDefaultRealTimeConfig()
	}
	
	engine := &RealTimePolicyEngine{
		engine:         NewPolicyEngine(),
		config:         config,
		shutdownChan:   make(chan struct{}),
		metrics:        newEngineMetrics(),
		healthMonitor:  newHealthMonitor(),
		circuitBreaker: newCircuitBreaker(config),
	}
	
	// Initialize caches
	engine.policyCache = newPolicyCache(config.PolicyCacheTTL)
	engine.resultCache = newEvaluationCache(config.ResultCacheTTL)
	engine.conditionCache = newConditionCache(config.ConditionCacheTTL)
	
	// Initialize worker pool
	engine.workerPool = newWorkerPool(config.WorkerPoolSize)
	
	// Start background tasks
	engine.startBackgroundTasks()
	
	return engine
}

// EvaluateRealTime performs high-performance policy evaluation
func (rte *RealTimePolicyEngine) EvaluateRealTime(ctx context.Context, request *PolicyEvaluationRequest) (*PolicyEvaluationResult, error) {
	start := time.Now()
	
	// Check circuit breaker
	if !rte.circuitBreaker.canExecute() {
		rte.metrics.recordCircuitBreakerTrip()
		return nil, fmt.Errorf("circuit breaker is open")
	}
	
	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, rte.config.MaxLatency)
	defer cancel()
	
	// Check result cache first
	if cached := rte.resultCache.get(request); cached != nil {
		rte.metrics.recordCacheHit("result")
		rte.metrics.recordLatency(time.Since(start))
		return cached.Result, nil
	}
	rte.metrics.recordCacheMiss("result")
	
	// Perform evaluation
	result, err := rte.evaluateWithTimeout(ctx, request)
	
	latency := time.Since(start)
	rte.metrics.recordLatency(latency)
	
	if err != nil {
		rte.circuitBreaker.recordFailure()
		rte.metrics.recordError(err)
		return nil, err
	}
	
	// Cache successful results
	rte.resultCache.set(request, result)
	rte.circuitBreaker.recordSuccess()
	
	return result, nil
}

// evaluateWithTimeout performs evaluation with timeout protection
func (rte *RealTimePolicyEngine) evaluateWithTimeout(ctx context.Context, request *PolicyEvaluationRequest) (*PolicyEvaluationResult, error) {
	resultChan := make(chan *PolicyEvaluationResult, 1)
	errorChan := make(chan error, 1)
	
	go func() {
		result, err := rte.performEvaluation(ctx, request)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		rte.metrics.recordTimeout()
		return nil, fmt.Errorf("evaluation timeout: %v", ctx.Err())
	}
}

// performEvaluation executes the core evaluation logic
func (rte *RealTimePolicyEngine) performEvaluation(ctx context.Context, request *PolicyEvaluationRequest) (*PolicyEvaluationResult, error) {
	start := time.Now()
	
	result := &PolicyEvaluationResult{
		RequestID:       request.ID,
		MatchedPolicies: []PolicyMatch{},
		Actions:         []ExecutedAction{},
		Conflicts:       []PolicyConflict{},
		Recommendations: []string{},
		Timestamp:       start,
		Metadata:        make(map[string]interface{}),
	}
	
	// Get applicable policies (with caching)
	policies, err := rte.getApplicablePolicies(ctx, request)
	if err != nil {
		return nil, err
	}
	
	// Evaluate policies in parallel for better performance
	if len(policies) > 1 && rte.config.MaxConcurrency > 1 {
		return rte.evaluatePoliciesParallel(ctx, request, policies, result)
	}
	
	// Sequential evaluation for single policy or small sets
	return rte.evaluatePoliciesSequential(ctx, request, policies, result)
}

// evaluatePoliciesParallel evaluates multiple policies in parallel
func (rte *RealTimePolicyEngine) evaluatePoliciesParallel(ctx context.Context, request *PolicyEvaluationRequest, policies []*Policy, result *PolicyEvaluationResult) (*PolicyEvaluationResult, error) {
	type policyResult struct {
		match *PolicyMatch
		err   error
	}
	
	resultChan := make(chan policyResult, len(policies))
	semaphore := make(chan struct{}, rte.config.MaxConcurrency)
	
	var wg sync.WaitGroup
	
	for _, policy := range policies {
		wg.Add(1)
		go func(p *Policy) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			match := rte.evaluatePolicyOptimized(p, request)
			resultChan <- policyResult{match: match, err: nil}
		}(policy)
	}
	
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	// Collect results
	for policyRes := range resultChan {
		if policyRes.err != nil {
			return nil, policyRes.err
		}
		if policyRes.match != nil {
			result.MatchedPolicies = append(result.MatchedPolicies, *policyRes.match)
		}
	}
	
	// Resolve conflicts and finalize decision
	rte.finalizeEvaluationResult(result)
	
	return result, nil
}

// evaluatePoliciesSequential evaluates policies sequentially
func (rte *RealTimePolicyEngine) evaluatePoliciesSequential(ctx context.Context, request *PolicyEvaluationRequest, policies []*Policy, result *PolicyEvaluationResult) (*PolicyEvaluationResult, error) {
	for _, policy := range policies {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		
		match := rte.evaluatePolicyOptimized(policy, request)
		if match != nil {
			result.MatchedPolicies = append(result.MatchedPolicies, *match)
		}
	}
	
	rte.finalizeEvaluationResult(result)
	return result, nil
}

// evaluatePolicyOptimized performs optimized policy evaluation with caching
func (rte *RealTimePolicyEngine) evaluatePolicyOptimized(policy *Policy, request *PolicyEvaluationRequest) *PolicyMatch {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}
		
		// Use cached condition evaluation
		conditionResult := rte.evaluateConditionCached(rule.Condition, request)
		
		if conditionResult {
			return &PolicyMatch{
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Priority:   rule.Priority,
				Confidence: 1.0,
				Action:     rule.Action,
			}
		}
	}
	
	return nil
}

// evaluateConditionCached evaluates conditions with caching
func (rte *RealTimePolicyEngine) evaluateConditionCached(condition *PolicyCondition, request *PolicyEvaluationRequest) bool {
	if condition == nil {
		return true
	}
	
	// Generate cache key
	cacheKey := rte.generateConditionCacheKey(condition, request)
	
	// Check cache
	if cached := rte.conditionCache.get(cacheKey); cached != nil {
		return cached.Result
	}
	
	// Evaluate condition
	result := rte.engine.evaluateCondition(condition, request)
	
	// Cache result
	rte.conditionCache.set(cacheKey, result)
	
	return result
}

// getApplicablePolicies retrieves applicable policies with caching
func (rte *RealTimePolicyEngine) getApplicablePolicies(ctx context.Context, request *PolicyEvaluationRequest) ([]*Policy, error) {
	var applicable []*Policy
	
	// Get all policies (cached)
	policies := rte.getAllPoliciesCached()
	
	for _, policy := range policies {
		if policy.Status == PolicyStatusActive && rte.engine.isPolicyApplicable(policy, request) {
			applicable = append(applicable, policy)
		}
	}
	
	return applicable, nil
}

// getAllPoliciesCached returns all policies with caching
func (rte *RealTimePolicyEngine) getAllPoliciesCached() []*Policy {
	// For now, delegate to engine - in production this would use distributed cache
	return rte.engine.ListPolicies()
}

// finalizeEvaluationResult completes the evaluation with conflict resolution
func (rte *RealTimePolicyEngine) finalizeEvaluationResult(result *PolicyEvaluationResult) {
	// Resolve conflicts
	result.Decision = rte.engine.resolveConflicts(result.MatchedPolicies, result)
	
	// Calculate confidence
	result.Confidence = rte.engine.calculateOverallConfidence(result.MatchedPolicies)
	
	// Calculate processing time
	result.ProcessingTime = time.Since(result.Timestamp)
}

// AddPolicy adds a policy and invalidates relevant caches
func (rte *RealTimePolicyEngine) AddPolicy(policy *Policy) error {
	err := rte.engine.AddPolicy(policy)
	if err != nil {
		return err
	}
	
	// Invalidate caches
	rte.invalidateCaches()
	
	return nil
}

// GetMetrics returns current performance metrics
func (rte *RealTimePolicyEngine) GetMetrics() *EngineMetrics {
	return rte.metrics.snapshot()
}

// GetHealth returns current health status
func (rte *RealTimePolicyEngine) GetHealth() *HealthMonitor {
	return rte.healthMonitor.snapshot()
}

// Shutdown gracefully shuts down the engine
func (rte *RealTimePolicyEngine) Shutdown(ctx context.Context) error {
	close(rte.shutdownChan)
	
	done := make(chan struct{})
	go func() {
		rte.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Helper functions and implementations continue in the next part...

// Cache implementations
func newPolicyCache(ttl time.Duration) *PolicyCache {
	return &PolicyCache{
		cache: make(map[string]*CachedPolicy),
		ttl:   ttl,
	}
}

func newEvaluationCache(ttl time.Duration) *EvaluationCache {
	return &EvaluationCache{
		cache: make(map[string]*CachedEvaluation),
		ttl:   ttl,
	}
}

func newConditionCache(ttl time.Duration) *ConditionCache {
	return &ConditionCache{
		cache: make(map[string]*CachedCondition),
		ttl:   ttl,
	}
}

// Default configuration
func getDefaultRealTimeConfig() *RealTimeConfig {
	return &RealTimeConfig{
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
} 