package policy

import (
	"fmt"
	"sync"
	"time"
)

// TenantIsolationManagerImpl implements comprehensive tenant isolation
type TenantIsolationManagerImpl struct {
	namespaces       map[string]string                    // tenantID -> namespace
	caches          map[string]TenantCacheInterface      // tenantID -> cache
	metrics         map[string]TenantMetricsInterface    // tenantID -> metrics
	loggers         map[string]TenantLoggerInterface     // tenantID -> logger
	policyEngines   map[string]TenantPolicyEngineInterface // tenantID -> engine
	config          *TenantManagerConfig
	mu              sync.RWMutex
}

// NewTenantIsolationManagerImpl creates a new tenant isolation manager
func NewTenantIsolationManagerImpl(config *TenantManagerConfig) TenantIsolationManager {
	return &TenantIsolationManagerImpl{
		namespaces:    make(map[string]string),
		caches:       make(map[string]TenantCacheInterface),
		metrics:      make(map[string]TenantMetricsInterface),
		loggers:      make(map[string]TenantLoggerInterface),
		policyEngines: make(map[string]TenantPolicyEngineInterface),
		config:       config,
	}
}

// ===== NAMESPACE MANAGEMENT =====

// CreateNamespace creates a unique namespace for a tenant
func (tim *TenantIsolationManagerImpl) CreateNamespace(tenantID string) (string, error) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if _, exists := tim.namespaces[tenantID]; exists {
		return "", fmt.Errorf("namespace already exists for tenant: %s", tenantID)
	}
	
	namespace := fmt.Sprintf("tenant_%s", tenantID)
	tim.namespaces[tenantID] = namespace
	
	return namespace, nil
}

// DeleteNamespace removes a tenant's namespace
func (tim *TenantIsolationManagerImpl) DeleteNamespace(tenantID string) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	delete(tim.namespaces, tenantID)
	return nil
}

// GetNamespace retrieves a tenant's namespace
func (tim *TenantIsolationManagerImpl) GetNamespace(tenantID string) (string, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		return "", fmt.Errorf("namespace not found for tenant: %s", tenantID)
	}
	
	return namespace, nil
}

// ValidateNamespace validates if a tenant has access to a namespace
func (tim *TenantIsolationManagerImpl) ValidateNamespace(tenantID, namespace string) (bool, error) {
	tenantNamespace, err := tim.GetNamespace(tenantID)
	if err != nil {
		return false, err
	}
	
	return tenantNamespace == namespace, nil
}

// ===== CACHE ISOLATION =====

// CreateTenantCache creates an isolated cache for a tenant
func (tim *TenantIsolationManagerImpl) CreateTenantCache(tenantID string) (TenantCacheInterface, error) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if _, exists := tim.caches[tenantID]; exists {
		return nil, fmt.Errorf("cache already exists for tenant: %s", tenantID)
	}
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		namespace = fmt.Sprintf("tenant_%s", tenantID)
		tim.namespaces[tenantID] = namespace
	}
	
	cache := NewTenantCacheImpl(tenantID, namespace)
	tim.caches[tenantID] = cache
	
	return cache, nil
}

// GetTenantCache retrieves a tenant's cache
func (tim *TenantIsolationManagerImpl) GetTenantCache(tenantID string) (TenantCacheInterface, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	cache, exists := tim.caches[tenantID]
	if !exists {
		return nil, fmt.Errorf("cache not found for tenant: %s", tenantID)
	}
	
	return cache, nil
}

// DeleteTenantCache removes a tenant's cache
func (tim *TenantIsolationManagerImpl) DeleteTenantCache(tenantID string) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if cache, exists := tim.caches[tenantID]; exists {
		cache.ClearTenantData()
	}
	
	delete(tim.caches, tenantID)
	return nil
}

// ===== METRICS ISOLATION =====

// CreateTenantMetrics creates isolated metrics for a tenant
func (tim *TenantIsolationManagerImpl) CreateTenantMetrics(tenantID string) (TenantMetricsInterface, error) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if _, exists := tim.metrics[tenantID]; exists {
		return nil, fmt.Errorf("metrics already exists for tenant: %s", tenantID)
	}
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		namespace = fmt.Sprintf("tenant_%s", tenantID)
		tim.namespaces[tenantID] = namespace
	}
	
	metrics := NewTenantMetricsImpl(tenantID, namespace)
	tim.metrics[tenantID] = metrics
	
	return metrics, nil
}

// GetTenantMetrics retrieves a tenant's metrics
func (tim *TenantIsolationManagerImpl) GetTenantMetrics(tenantID string) (TenantMetricsInterface, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	metrics, exists := tim.metrics[tenantID]
	if !exists {
		return nil, fmt.Errorf("metrics not found for tenant: %s", tenantID)
	}
	
	return metrics, nil
}

// DeleteTenantMetrics removes a tenant's metrics
func (tim *TenantIsolationManagerImpl) DeleteTenantMetrics(tenantID string) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if metrics, exists := tim.metrics[tenantID]; exists {
		metrics.ResetMetrics()
	}
	
	delete(tim.metrics, tenantID)
	return nil
}

// ===== LOGGING ISOLATION =====

// CreateTenantLogger creates isolated logging for a tenant
func (tim *TenantIsolationManagerImpl) CreateTenantLogger(tenantID string) (TenantLoggerInterface, error) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if _, exists := tim.loggers[tenantID]; exists {
		return nil, fmt.Errorf("logger already exists for tenant: %s", tenantID)
	}
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		namespace = fmt.Sprintf("tenant_%s", tenantID)
		tim.namespaces[tenantID] = namespace
	}
	
	logger := NewTenantLoggerImpl(tenantID, namespace)
	tim.loggers[tenantID] = logger
	
	return logger, nil
}

// GetTenantLogger retrieves a tenant's logger
func (tim *TenantIsolationManagerImpl) GetTenantLogger(tenantID string) (TenantLoggerInterface, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	logger, exists := tim.loggers[tenantID]
	if !exists {
		return nil, fmt.Errorf("logger not found for tenant: %s", tenantID)
	}
	
	return logger, nil
}

// DeleteTenantLogger removes a tenant's logger
func (tim *TenantIsolationManagerImpl) DeleteTenantLogger(tenantID string) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	delete(tim.loggers, tenantID)
	return nil
}

// ===== POLICY ENGINE ISOLATION =====

// CreateTenantPolicyEngine creates an isolated policy engine for a tenant
func (tim *TenantIsolationManagerImpl) CreateTenantPolicyEngine(tenantID string, config *TenantConfiguration) (TenantPolicyEngineInterface, error) {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	if _, exists := tim.policyEngines[tenantID]; exists {
		return nil, fmt.Errorf("policy engine already exists for tenant: %s", tenantID)
	}
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		namespace = fmt.Sprintf("tenant_%s", tenantID)
		tim.namespaces[tenantID] = namespace
	}
	
	engine := NewTenantPolicyEngineImpl(tenantID, namespace, config)
	tim.policyEngines[tenantID] = engine
	
	return engine, nil
}

// GetTenantPolicyEngine retrieves a tenant's policy engine
func (tim *TenantIsolationManagerImpl) GetTenantPolicyEngine(tenantID string) (TenantPolicyEngineInterface, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	engine, exists := tim.policyEngines[tenantID]
	if !exists {
		return nil, fmt.Errorf("policy engine not found for tenant: %s", tenantID)
	}
	
	return engine, nil
}

// DeleteTenantPolicyEngine removes a tenant's policy engine
func (tim *TenantIsolationManagerImpl) DeleteTenantPolicyEngine(tenantID string) error {
	tim.mu.Lock()
	defer tim.mu.Unlock()
	
	delete(tim.policyEngines, tenantID)
	return nil
}

// ===== HEALTH AND MONITORING =====

// CheckTenantIsolation checks the isolation health for a tenant
func (tim *TenantIsolationManagerImpl) CheckTenantIsolation(tenantID string) (*IsolationHealthCheck, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	health := &IsolationHealthCheck{
		TenantID:       tenantID,
		Namespace:      namespace,
		IsolationLevel: IsolationLevelStandard,
		OverallHealth:  HealthStatusHealthy,
		Components:     make(map[string]ComponentHealth),
		Issues:         []IsolationIssue{},
		LastChecked:    time.Now(),
	}
	
	// Check cache isolation
	if cache, exists := tim.caches[tenantID]; exists {
		health.Components["cache"] = ComponentHealth{
			Name:         "cache",
			Status:       HealthStatusHealthy,
			ResponseTime: time.Millisecond,
		}
		
		// Check cache quotas
		stats := cache.GetCacheStats()
		if stats.MemoryUsed > stats.MemoryLimit*8/10 { // 80% threshold
			health.Issues = append(health.Issues, IsolationIssue{
				Component:   "cache",
				Type:        "resource_bleed",
				Severity:    "medium",
				Description: "Cache memory usage is high",
				DetectedAt:  time.Now(),
				Impact:      "Performance degradation possible",
				Remediation: "Consider increasing memory limits or implementing cache eviction",
			})
		}
	}
	
	// Check metrics isolation
	if metrics, exists := tim.metrics[tenantID]; exists {
		health.Components["metrics"] = ComponentHealth{
			Name:         "metrics",
			Status:       HealthStatusHealthy,
			ResponseTime: time.Millisecond,
		}
		
		// Check metrics quotas
		stats := metrics.GetTenantStats()
		if stats.MetricsDropped > 0 {
			health.Issues = append(health.Issues, IsolationIssue{
				Component:   "metrics",
				Type:        "resource_bleed",
				Severity:    "medium",
				Description: "Metrics are being dropped",
				DetectedAt:  time.Now(),
				Impact:      "Monitoring data loss",
				Remediation: "Review metrics retention and storage limits",
			})
		}
	}
	
	// Check logger isolation
	if logger, exists := tim.loggers[tenantID]; exists {
		health.Components["logging"] = ComponentHealth{
			Name:         "logging",
			Status:       HealthStatusHealthy,
			ResponseTime: time.Millisecond,
		}
		
		// Check log quotas
		stats := logger.GetLogStats()
		if stats.LogsDropped > 0 {
			health.Issues = append(health.Issues, IsolationIssue{
				Component:   "logging",
				Type:        "resource_bleed",
				Severity:    "medium",
				Description: "Logs are being dropped",
				DetectedAt:  time.Now(),
				Impact:      "Audit trail loss",
				Remediation: "Review log retention and storage limits",
			})
		}
	}
	
	// Check policy engine isolation
	if engine, exists := tim.policyEngines[tenantID]; exists {
		engineHealth := engine.GetHealthStatus()
		health.Components["policy_engine"] = ComponentHealth{
			Name:         "policy_engine",
			Status:       engineHealth.PolicyEngineStatus,
			ResponseTime: engineHealth.HealthCheckDuration,
		}
		
		// Add any engine issues
		for _, issue := range engineHealth.Issues {
			health.Issues = append(health.Issues, IsolationIssue{
				Component:   "policy_engine",
				Type:        "access_violation",
				Severity:    issue.Severity,
				Description: issue.Message,
				DetectedAt:  issue.FirstDetected,
				Impact:      "Policy evaluation issues",
				Remediation: "Review policy engine configuration",
			})
		}
	}
	
	// Determine overall health
	health.OverallHealth = tim.calculateOverallIsolationHealth(health.Components, health.Issues)
	
	return health, nil
}

// EnforceIsolation enforces isolation for a tenant
func (tim *TenantIsolationManagerImpl) EnforceIsolation(tenantID string) error {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	var errors []error
	
	// Enforce cache isolation
	if cache, exists := tim.caches[tenantID]; exists {
		if err := cache.EnforceQuotas(); err != nil {
			errors = append(errors, fmt.Errorf("cache isolation: %w", err))
		}
	}
	
	// Enforce metrics isolation
	if metrics, exists := tim.metrics[tenantID]; exists {
		// Check and enforce metric quotas
		usage := metrics.GetTenantResourceUsage()
		for resource, amount := range usage {
			if allowed, err := metrics.CheckQuota(resource, amount); err != nil {
				errors = append(errors, fmt.Errorf("metrics quota check: %w", err))
			} else if !allowed {
				errors = append(errors, fmt.Errorf("metrics quota exceeded for resource: %s", resource))
			}
		}
	}
	
	// Enforce policy engine isolation
	if engine, exists := tim.policyEngines[tenantID]; exists {
		if err := engine.EnforceResourceLimits(); err != nil {
			errors = append(errors, fmt.Errorf("policy engine isolation: %w", err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("isolation enforcement failed: %v", errors)
	}
	
	return nil
}

// GetIsolationMetrics retrieves isolation metrics for a tenant
func (tim *TenantIsolationManagerImpl) GetIsolationMetrics(tenantID string) (*IsolationMetrics, error) {
	tim.mu.RLock()
	defer tim.mu.RUnlock()
	
	namespace, exists := tim.namespaces[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	metrics := &IsolationMetrics{
		TenantID:              tenantID,
		Namespace:             namespace,
		DataLeaks:             0,
		AccessViolations:      0,
		ResourceBleeds:        0,
		CrossTenantRequests:   0,
		IsolationViolations:   0,
		ViolationsByType:      make(map[string]int64),
		MitigationActions:     0,
	}
	
	// In a real implementation, these would be collected from various sources
	
	return metrics, nil
}

// ===== HELPER METHODS =====

// calculateOverallIsolationHealth determines overall health based on components and issues
func (tim *TenantIsolationManagerImpl) calculateOverallIsolationHealth(components map[string]ComponentHealth, issues []IsolationIssue) HealthStatus {
	// Count unhealthy components
	unhealthyCount := 0
	for _, component := range components {
		if component.Status != HealthStatusHealthy {
			unhealthyCount++
		}
	}
	
	// Check issue severity
	criticalIssues := 0
	highIssues := 0
	for _, issue := range issues {
		switch issue.Severity {
		case "critical":
			criticalIssues++
		case "high":
			highIssues++
		}
	}
	
	// Determine overall status
	if criticalIssues > 0 || unhealthyCount > len(components)/2 {
		return HealthStatusCritical
	}
	
	if highIssues > 0 || unhealthyCount > 0 {
		return HealthStatusDegraded
	}
	
	if len(issues) > 0 {
		return HealthStatusDegraded
	}
	
	return HealthStatusHealthy
}

// ===== TENANT CACHE IMPLEMENTATION =====

// TenantCacheImpl implements TenantCacheInterface
type TenantCacheImpl struct {
	tenantID   string
	namespace  string
	cache      map[string]interface{}
	stats      *TenantCacheStats
	mu         sync.RWMutex
}

// NewTenantCacheImpl creates a new tenant cache implementation
func NewTenantCacheImpl(tenantID, namespace string) TenantCacheInterface {
	return &TenantCacheImpl{
		tenantID:  tenantID,
		namespace: namespace,
		cache:     make(map[string]interface{}),
		stats: &TenantCacheStats{
			TenantID:    tenantID,
			Namespace:   namespace,
			MemoryUsed:  0,
			MemoryLimit: 100 * 1024 * 1024, // 100MB default
			EntryCount:  0,
			EntryLimit:  10000, // 10k entries default
			HitCount:    0,
			MissCount:   0,
		},
	}
}

// GetPolicy implements PolicyCacheInterface
func (tc *TenantCacheImpl) GetPolicy(id string) (*Policy, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	
	key := fmt.Sprintf("policy:%s", id)
	if policy, exists := tc.cache[key]; exists {
		tc.stats.HitCount++
		return policy.(*Policy), nil
	}
	
	tc.stats.MissCount++
	return nil, fmt.Errorf("policy not found in cache: %s", id)
}

// SetPolicy implements PolicyCacheInterface
func (tc *TenantCacheImpl) SetPolicy(policy *Policy) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	key := fmt.Sprintf("policy:%s", policy.ID)
	tc.cache[key] = policy
	tc.stats.EntryCount++
	
	return nil
}

// InvalidatePolicy implements PolicyCacheInterface
func (tc *TenantCacheImpl) InvalidatePolicy(id string) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	key := fmt.Sprintf("policy:%s", id)
	if _, exists := tc.cache[key]; exists {
		delete(tc.cache, key)
		tc.stats.EntryCount--
	}
	
	return nil
}

// GetEvaluationResult implements PolicyCacheInterface
func (tc *TenantCacheImpl) GetEvaluationResult(requestHash string) (*PolicyEvaluationResult, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	
	key := fmt.Sprintf("eval:%s", requestHash)
	if result, exists := tc.cache[key]; exists {
		tc.stats.HitCount++
		return result.(*PolicyEvaluationResult), nil
	}
	
	tc.stats.MissCount++
	return nil, fmt.Errorf("evaluation result not found in cache: %s", requestHash)
}

// SetEvaluationResult implements PolicyCacheInterface
func (tc *TenantCacheImpl) SetEvaluationResult(requestHash string, result *PolicyEvaluationResult, ttl time.Duration) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	key := fmt.Sprintf("eval:%s", requestHash)
	tc.cache[key] = result
	tc.stats.EntryCount++
	
	// In a real implementation, TTL would be handled properly
	return nil
}

// GetTenantID implements TenantCacheInterface
func (tc *TenantCacheImpl) GetTenantID() string {
	return tc.tenantID
}

// GetNamespace implements TenantCacheInterface
func (tc *TenantCacheImpl) GetNamespace() string {
	return tc.namespace
}

// GetMemoryUsage implements TenantCacheInterface
func (tc *TenantCacheImpl) GetMemoryUsage() int64 {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.stats.MemoryUsed
}

// GetEntryCount implements TenantCacheInterface
func (tc *TenantCacheImpl) GetEntryCount() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.stats.EntryCount
}

// ClearTenantData implements TenantCacheInterface
func (tc *TenantCacheImpl) ClearTenantData() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	tc.cache = make(map[string]interface{})
	tc.stats.EntryCount = 0
	tc.stats.MemoryUsed = 0
	
	return nil
}

// GetCacheStats implements TenantCacheInterface
func (tc *TenantCacheImpl) GetCacheStats() *TenantCacheStats {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	
	// Update hit ratio
	total := tc.stats.HitCount + tc.stats.MissCount
	if total > 0 {
		tc.stats.HitRatio = float64(tc.stats.HitCount) / float64(total)
	}
	
	return tc.stats
}

// SetMaxMemory implements TenantCacheInterface
func (tc *TenantCacheImpl) SetMaxMemory(bytes int64) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	tc.stats.MemoryLimit = bytes
	return nil
}

// SetMaxEntries implements TenantCacheInterface
func (tc *TenantCacheImpl) SetMaxEntries(count int) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	tc.stats.EntryLimit = count
	return nil
}

// EnforceQuotas implements TenantCacheInterface
func (tc *TenantCacheImpl) EnforceQuotas() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	// Enforce entry limit
	if tc.stats.EntryCount > tc.stats.EntryLimit {
		// Simple LRU eviction - in real implementation this would be more sophisticated
		excess := tc.stats.EntryCount - tc.stats.EntryLimit
		for key := range tc.cache {
			if excess <= 0 {
				break
			}
			delete(tc.cache, key)
			tc.stats.EntryCount--
			tc.stats.EvictionCount++
			excess--
		}
		tc.stats.LastEviction = func() *time.Time { t := time.Now(); return &t }()
	}
	
	return nil
} 