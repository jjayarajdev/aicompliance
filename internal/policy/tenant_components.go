package policy

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ===== TENANT METRICS IMPLEMENTATION =====

// TenantMetricsImpl implements TenantMetricsInterface
type TenantMetricsImpl struct {
	tenantID  string
	namespace string
	stats     *TenantMetricsStats
	quotas    map[string]*QuotaUsage
	mu        sync.RWMutex
}

// NewTenantMetricsImpl creates a new tenant metrics implementation
func NewTenantMetricsImpl(tenantID, namespace string) TenantMetricsInterface {
	return &TenantMetricsImpl{
		tenantID:  tenantID,
		namespace: namespace,
		stats: &TenantMetricsStats{
			TenantID:        tenantID,
			Namespace:       namespace,
			LastCollection:  time.Now(),
		},
		quotas: make(map[string]*QuotaUsage),
	}
}

// RecordEvaluation implements PolicyMetrics
func (tm *TenantMetricsImpl) RecordEvaluation(policyID string, duration time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.stats.MetricsCollected++
}

// RecordAction implements PolicyMetrics
func (tm *TenantMetricsImpl) RecordAction(actionType ActionType, status ActionStatus) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.stats.MetricsCollected++
}

// RecordConflict implements PolicyMetrics
func (tm *TenantMetricsImpl) RecordConflict(conflictType ConflictType) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.stats.MetricsCollected++
}

// GetPolicyStats implements PolicyMetrics
func (tm *TenantMetricsImpl) GetPolicyStats(policyID string) PolicyStats {
	return PolicyStats{
		PolicyID:       policyID,
		ExecutionCount: 0,
		MatchCount:     0,
		LastExecuted:   &time.Time{},
	}
}

// GetTenantID implements TenantMetricsInterface
func (tm *TenantMetricsImpl) GetTenantID() string {
	return tm.tenantID
}

// GetNamespace implements TenantMetricsInterface
func (tm *TenantMetricsImpl) GetNamespace() string {
	return tm.namespace
}

// RecordTenantUsage implements TenantMetricsInterface
func (tm *TenantMetricsImpl) RecordTenantUsage(resource string, amount int64) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if quota, exists := tm.quotas[resource]; exists {
		quota.Used += amount
		quota.LastUpdated = time.Now()
		quota.UsagePercent = float64(quota.Used) / float64(quota.Limit) * 100
	} else {
		tm.quotas[resource] = &QuotaUsage{
			Resource:     resource,
			Used:         amount,
			Limit:        1000000, // Default limit
			Unit:         "count",
			LastUpdated:  time.Now(),
			UsagePercent: 0,
		}
	}
	
	return nil
}

// GetTenantResourceUsage implements TenantMetricsInterface
func (tm *TenantMetricsImpl) GetTenantResourceUsage() map[string]int64 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	usage := make(map[string]int64)
	for resource, quota := range tm.quotas {
		usage[resource] = quota.Used
	}
	
	return usage
}

// GetTenantStats implements TenantMetricsInterface
func (tm *TenantMetricsImpl) GetTenantStats() *TenantMetricsStats {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.stats
}

// CheckQuota implements TenantMetricsInterface
func (tm *TenantMetricsImpl) CheckQuota(resource string, amount int64) (bool, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	if quota, exists := tm.quotas[resource]; exists {
		return quota.Used+amount <= quota.Limit, nil
	}
	
	return true, nil // No quota set, allow
}

// GetQuotaUsage implements TenantMetricsInterface
func (tm *TenantMetricsImpl) GetQuotaUsage() map[string]*QuotaUsage {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	usage := make(map[string]*QuotaUsage)
	for resource, quota := range tm.quotas {
		usage[resource] = quota
	}
	
	return usage
}

// ResetMetrics implements TenantMetricsInterface
func (tm *TenantMetricsImpl) ResetMetrics() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tm.stats = &TenantMetricsStats{
		TenantID:        tm.tenantID,
		Namespace:       tm.namespace,
		LastCollection:  time.Now(),
	}
	tm.quotas = make(map[string]*QuotaUsage)
	
	return nil
}

// ===== TENANT LOGGER IMPLEMENTATION =====

// TenantLoggerImpl implements TenantLoggerInterface
type TenantLoggerImpl struct {
	tenantID  string
	namespace string
	logs      []TenantLogEntry
	stats     *TenantLogStats
	mu        sync.RWMutex
}

// NewTenantLoggerImpl creates a new tenant logger implementation
func NewTenantLoggerImpl(tenantID, namespace string) TenantLoggerInterface {
	return &TenantLoggerImpl{
		tenantID:  tenantID,
		namespace: namespace,
		logs:      []TenantLogEntry{},
		stats: &TenantLogStats{
			TenantID:      tenantID,
			Namespace:     namespace,
			LogsByLevel:   make(map[string]int64),
			LogsByComponent: make(map[string]int64),
		},
	}
}

// LogEvaluation implements PolicyLogger
func (tl *TenantLoggerImpl) LogEvaluation(result *PolicyEvaluationResult) error {
	entry := TenantLogEntry{
		ID:        fmt.Sprintf("log_%d", len(tl.logs)),
		TenantID:  tl.tenantID,
		Namespace: tl.namespace,
		Level:     "info",
		Component: "policy_evaluation",
		Message:   fmt.Sprintf("Policy evaluation completed: %s", result.RequestID),
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"request_id": result.RequestID,
			"decision":   result.Decision.Action,
			"confidence": result.Confidence,
		},
	}
	
	return tl.addLogEntry(entry)
}

// LogAction implements PolicyLogger
func (tl *TenantLoggerImpl) LogAction(action *ExecutedAction) error {
	entry := TenantLogEntry{
		ID:        fmt.Sprintf("log_%d", len(tl.logs)),
		TenantID:  tl.tenantID,
		Namespace: tl.namespace,
		Level:     "info",
		Component: "policy_action",
		Message:   fmt.Sprintf("Action executed: %s", action.Type),
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"action_type":   action.Type,
			"action_status": action.Status,
			"execution_time": action.ExecutionTime,
		},
	}
	
	return tl.addLogEntry(entry)
}

// LogConflict implements PolicyLogger
func (tl *TenantLoggerImpl) LogConflict(conflict *PolicyConflict) error {
	entry := TenantLogEntry{
		ID:        fmt.Sprintf("log_%d", len(tl.logs)),
		TenantID:  tl.tenantID,
		Namespace: tl.namespace,
		Level:     "warn",
		Component: "policy_conflict",
		Message:   fmt.Sprintf("Policy conflict detected: %s", conflict.Type),
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"conflict_type": conflict.Type,
			"policy_ids":    conflict.PolicyIDs,
			"severity":      conflict.Severity,
		},
	}
	
	return tl.addLogEntry(entry)
}

// GetEvaluationHistory implements PolicyLogger
func (tl *TenantLoggerImpl) GetEvaluationHistory(filters PolicyLogFilters) ([]PolicyEvaluationResult, error) {
	// In a real implementation, this would filter and return evaluation results
	return []PolicyEvaluationResult{}, nil
}

// GetTenantID implements TenantLoggerInterface
func (tl *TenantLoggerImpl) GetTenantID() string {
	return tl.tenantID
}

// GetNamespace implements TenantLoggerInterface
func (tl *TenantLoggerImpl) GetNamespace() string {
	return tl.namespace
}

// LogTenantEvent implements TenantLoggerInterface
func (tl *TenantLoggerImpl) LogTenantEvent(event *TenantAuditEvent) error {
	entry := TenantLogEntry{
		ID:        fmt.Sprintf("log_%d", len(tl.logs)),
		TenantID:  tl.tenantID,
		Namespace: tl.namespace,
		Level:     tl.mapSeverityToLevel(event.Severity),
		Component: "tenant_audit",
		Message:   fmt.Sprintf("Tenant event: %s", event.Action),
		Timestamp: time.Now(),
		Fields: map[string]interface{}{
			"action":      event.Action,
			"actor":       event.Actor,
			"actor_type":  event.ActorType,
			"resource":    event.Resource,
			"resource_id": event.ResourceID,
			"result":      event.Result,
			"details":     event.Details,
		},
	}
	
	return tl.addLogEntry(entry)
}

// GetTenantLogs implements TenantLoggerInterface
func (tl *TenantLoggerImpl) GetTenantLogs(filters *TenantLogFilters) ([]TenantLogEntry, error) {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	
	// Simple filtering - in real implementation would be more sophisticated
	var filtered []TenantLogEntry
	for _, log := range tl.logs {
		if tl.matchesFilters(log, filters) {
			filtered = append(filtered, log)
		}
	}
	
	return filtered, nil
}

// RotateLogs implements TenantLoggerInterface
func (tl *TenantLoggerImpl) RotateLogs() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	
	// In a real implementation, this would rotate log files
	tl.stats.RotationCount++
	now := time.Now()
	tl.stats.LastRotation = &now
	
	return nil
}

// PurgeLogs implements TenantLoggerInterface
func (tl *TenantLoggerImpl) PurgeLogs(olderThan time.Duration) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	
	cutoff := time.Now().Add(-olderThan)
	var kept []TenantLogEntry
	
	for _, log := range tl.logs {
		if log.Timestamp.After(cutoff) {
			kept = append(kept, log)
		}
	}
	
	tl.logs = kept
	return nil
}

// GetLogStats implements TenantLoggerInterface
func (tl *TenantLoggerImpl) GetLogStats() *TenantLogStats {
	tl.mu.RLock()
	defer tl.mu.RUnlock()
	
	// Update stats
	if len(tl.logs) > 0 {
		tl.stats.OldestLog = &tl.logs[0].Timestamp
		tl.stats.LatestLog = &tl.logs[len(tl.logs)-1].Timestamp
	}
	tl.stats.LogsGenerated = int64(len(tl.logs))
	
	return tl.stats
}

// Helper methods for TenantLoggerImpl
func (tl *TenantLoggerImpl) addLogEntry(entry TenantLogEntry) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	
	tl.logs = append(tl.logs, entry)
	tl.stats.LogsByLevel[entry.Level]++
	tl.stats.LogsByComponent[entry.Component]++
	
	// Simple rotation - keep only last 1000 logs
	if len(tl.logs) > 1000 {
		tl.logs = tl.logs[len(tl.logs)-1000:]
	}
	
	return nil
}

func (tl *TenantLoggerImpl) mapSeverityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warn"
	default:
		return "info"
	}
}

func (tl *TenantLoggerImpl) matchesFilters(log TenantLogEntry, filters *TenantLogFilters) bool {
	if filters == nil {
		return true
	}
	
	// Check log level filter
	if len(filters.LogLevel) > 0 {
		found := false
		for _, level := range filters.LogLevel {
			if log.Level == level {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check component filter
	if len(filters.Component) > 0 {
		found := false
		for _, component := range filters.Component {
			if log.Component == component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	return true
}

// ===== TENANT POLICY ENGINE IMPLEMENTATION =====

// TenantPolicyEngineImpl implements TenantPolicyEngineInterface
type TenantPolicyEngineImpl struct {
	tenantID      string
	namespace     string
	config        *TenantConfiguration
	engine        *PolicyEngine
	resourceUsage *TenantEngineResourceUsage
	health        *TenantEngineHealth
	mu            sync.RWMutex
}

// NewTenantPolicyEngineImpl creates a new tenant policy engine implementation
func NewTenantPolicyEngineImpl(tenantID, namespace string, config *TenantConfiguration) TenantPolicyEngineInterface {
	engine := NewPolicyEngine()
	
	return &TenantPolicyEngineImpl{
		tenantID:  tenantID,
		namespace: namespace,
		config:    config,
		engine:    engine,
		resourceUsage: &TenantEngineResourceUsage{
			TenantID:     tenantID,
			Namespace:    namespace,
			LastUpdated:  time.Now(),
		},
		health: &TenantEngineHealth{
			TenantID:            tenantID,
			Namespace:           namespace,
			OverallHealth:       HealthStatusHealthy,
			PolicyEngineStatus:  HealthStatusHealthy,
			CacheStatus:         HealthStatusHealthy,
			MetricsStatus:       HealthStatusHealthy,
			LoggingStatus:       HealthStatusHealthy,
			LastHealthCheck:     time.Now(),
			Issues:              []HealthIssue{},
			ResourceUtilization: make(map[string]float64),
		},
	}
}

// AddPolicy implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) AddPolicy(ctx *TenantContext, policy *Policy) error {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()
	
	// Validate tenant context
	if ctx.TenantID != tpe.tenantID {
		return fmt.Errorf("tenant context mismatch: expected %s, got %s", tpe.tenantID, ctx.TenantID)
	}
	
	// Check resource limits
	if tpe.config != nil && tpe.config.PolicyEngineConfig != nil {
		if tpe.resourceUsage.PoliciesLoaded >= tpe.config.PolicyEngineConfig.MaxPolicies {
			return fmt.Errorf("policy limit exceeded: %d", tpe.config.PolicyEngineConfig.MaxPolicies)
		}
	}
	
	// Add namespace prefix to policy ID for isolation
	policy.ID = fmt.Sprintf("%s:%s", tpe.namespace, policy.ID)
	
	err := tpe.engine.AddPolicy(policy)
	if err == nil {
		tpe.resourceUsage.PoliciesLoaded++
		tpe.resourceUsage.LastUpdated = time.Now()
	}
	
	return err
}

// GetPolicy implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetPolicy(ctx *TenantContext, id string) (*Policy, error) {
	// Validate tenant context
	if ctx.TenantID != tpe.tenantID {
		return nil, fmt.Errorf("tenant context mismatch: expected %s, got %s", tpe.tenantID, ctx.TenantID)
	}
	
	// Add namespace prefix
	namespacedID := fmt.Sprintf("%s:%s", tpe.namespace, id)
	return tpe.engine.GetPolicy(namespacedID)
}

// UpdatePolicy implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) UpdatePolicy(ctx *TenantContext, policy *Policy) error {
	// Validate tenant context
	if ctx.TenantID != tpe.tenantID {
		return fmt.Errorf("tenant context mismatch: expected %s, got %s", tpe.tenantID, ctx.TenantID)
	}
	
	// Add namespace prefix
	policy.ID = fmt.Sprintf("%s:%s", tpe.namespace, policy.ID)
	return tpe.engine.UpdatePolicy(policy)
}

// DeletePolicy implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) DeletePolicy(ctx *TenantContext, id string) error {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()
	
	// Validate tenant context
	if ctx.TenantID != tpe.tenantID {
		return fmt.Errorf("tenant context mismatch: expected %s, got %s", tpe.tenantID, ctx.TenantID)
	}
	
	// Add namespace prefix
	namespacedID := fmt.Sprintf("%s:%s", tpe.namespace, id)
	err := tpe.engine.DeletePolicy(namespacedID)
	if err == nil {
		tpe.resourceUsage.PoliciesLoaded--
		tpe.resourceUsage.LastUpdated = time.Now()
	}
	
	return err
}

// ListPolicies implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) ListPolicies(ctx *TenantContext) []*Policy {
	// Validate tenant context
	if ctx.TenantID != tpe.tenantID {
		return []*Policy{}
	}
	
	allPolicies := tpe.engine.ListPolicies()
	var tenantPolicies []*Policy
	
	// Filter policies by namespace
	for _, policy := range allPolicies {
		if len(policy.ID) > len(tpe.namespace)+1 && 
		   policy.ID[:len(tpe.namespace)+1] == tpe.namespace+":" {
			// Remove namespace prefix for external representation
			policy.ID = policy.ID[len(tpe.namespace)+1:]
			tenantPolicies = append(tenantPolicies, policy)
		}
	}
	
	return tenantPolicies
}

// EvaluateRequest implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) EvaluateRequest(ctx *TenantContext, request *TenantPolicyEvaluationRequest) (*TenantPolicyEvaluationResult, error) {
	start := time.Now()
	
	// Validate tenant context
	if ctx.TenantID != tpe.tenantID {
		return nil, fmt.Errorf("tenant context mismatch: expected %s, got %s", tpe.tenantID, ctx.TenantID)
	}
	
	// Check concurrent request limits
	tpe.mu.Lock()
	if tpe.config != nil && tpe.config.PolicyEngineConfig != nil {
		if tpe.resourceUsage.ConcurrentRequests >= tpe.resourceUsage.ConcurrentLimit {
			tpe.mu.Unlock()
			return nil, fmt.Errorf("concurrent request limit exceeded")
		}
	}
	tpe.resourceUsage.ConcurrentRequests++
	tpe.mu.Unlock()
	
	defer func() {
		tpe.mu.Lock()
		tpe.resourceUsage.ConcurrentRequests--
		tpe.resourceUsage.RequestsProcessed++
		tpe.resourceUsage.LastUpdated = time.Now()
		tpe.mu.Unlock()
	}()
	
	// Evaluate using the underlying engine
	result, err := tpe.engine.EvaluateRequest(context.Background(), &request.PolicyEvaluationRequest)
	if err != nil {
		return nil, err
	}
	
	// Create tenant-aware result
	tenantResult := &TenantPolicyEvaluationResult{
		PolicyEvaluationResult: *result,
		TenantContext:          ctx,
		ResourceUsage: &RequestResourceUsage{
			CPUTime:       time.Since(start),
			MemoryUsed:    1024, // Placeholder
			CacheAccesses: 1,    // Placeholder
		},
	}
	
	return tenantResult, nil
}

// GetTenantID implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetTenantID() string {
	return tpe.tenantID
}

// GetNamespace implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetNamespace() string {
	return tpe.namespace
}

// GetTenantConfiguration implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetTenantConfiguration() *TenantConfiguration {
	tpe.mu.RLock()
	defer tpe.mu.RUnlock()
	return tpe.config
}

// UpdateTenantConfiguration implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) UpdateTenantConfiguration(config *TenantConfiguration) error {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()
	
	tpe.config = config
	
	// Update resource limits based on configuration
	if config != nil && config.PolicyEngineConfig != nil {
		tpe.resourceUsage.PoliciesLimit = config.PolicyEngineConfig.MaxPolicies
		tpe.resourceUsage.RulesLimit = config.PolicyEngineConfig.MaxRulesPerPolicy * config.PolicyEngineConfig.MaxPolicies
		tpe.resourceUsage.ConcurrentLimit = 100 // Default
	}
	
	return nil
}

// GetResourceUsage implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetResourceUsage() *TenantEngineResourceUsage {
	tpe.mu.RLock()
	defer tpe.mu.RUnlock()
	return tpe.resourceUsage
}

// EnforceResourceLimits implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) EnforceResourceLimits() error {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()
	
	// Check if any limits are exceeded
	if tpe.config != nil && tpe.config.PolicyEngineConfig != nil {
		if tpe.resourceUsage.PoliciesLoaded > tpe.config.PolicyEngineConfig.MaxPolicies {
			return fmt.Errorf("policy limit exceeded: %d > %d", 
				tpe.resourceUsage.PoliciesLoaded, tpe.config.PolicyEngineConfig.MaxPolicies)
		}
	}
	
	return nil
}

// GetHealthStatus implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetHealthStatus() *TenantEngineHealth {
	tpe.mu.Lock()
	defer tpe.mu.Unlock()
	
	// Update health status
	tpe.health.LastHealthCheck = time.Now()
	
	// Check resource utilization
	if tpe.config != nil && tpe.config.PolicyEngineConfig != nil {
		policyUtilization := float64(tpe.resourceUsage.PoliciesLoaded) / float64(tpe.config.PolicyEngineConfig.MaxPolicies) * 100
		tpe.health.ResourceUtilization["policies"] = policyUtilization
		
		if policyUtilization > 90 {
			tpe.health.OverallHealth = HealthStatusDegraded
			tpe.health.Issues = append(tpe.health.Issues, HealthIssue{
				Component:     "policy_engine",
				Severity:      "medium",
				Message:       "Policy utilization is high",
				FirstDetected: time.Now(),
				LastDetected:  time.Now(),
				Count:         1,
			})
		}
	}
	
	return tpe.health
}

// GetPerformanceMetrics implements TenantPolicyEngineInterface
func (tpe *TenantPolicyEngineImpl) GetPerformanceMetrics() *TenantEngineMetrics {
	return &TenantEngineMetrics{
		TenantID:             tpe.tenantID,
		Namespace:            tpe.namespace,
		EvaluationsPerSecond: 0, // Placeholder
		AverageLatency:       time.Millisecond,
		P95Latency:           time.Millisecond * 5,
		P99Latency:           time.Millisecond * 10,
		ErrorRate:            0,
		LastUpdated:          time.Now(),
	}
} 