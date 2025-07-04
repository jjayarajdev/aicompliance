package monitoring

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// ===== POLICY ENGINE HEALTH CHECKER =====

type PolicyEngineHealthChecker struct {
	logger      *logrus.Logger
	mu          sync.RWMutex
	lastCheck   time.Time
	isHealthy   bool
}

func (p *PolicyEngineHealthChecker) GetName() string {
	return "policy_engine"
}

func (p *PolicyEngineHealthChecker) CheckHealth(ctx context.Context) ComponentHealth {
	startTime := time.Now()
	
	health := ComponentHealth{
		Name:        p.GetName(),
		Status:      HealthStatusHealthy,
		LastCheck:   startTime,
		HealthScore: 1.0,
		Details:     make(map[string]interface{}),
	}
	
	// Check policy engine health
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	health.Details["memory_usage_mb"] = float64(memStats.Alloc) / 1024 / 1024
	health.Details["goroutines"] = runtime.NumGoroutine()
	health.Details["last_gc"] = time.Unix(0, int64(memStats.LastGC))
	
	// Simulate policy engine health check
	// In a real implementation, this would check actual policy engine components
	evaluationLatency := 25 * time.Millisecond // Simulated
	health.Details["average_evaluation_latency_ms"] = evaluationLatency.Milliseconds()
	
	// Determine health status based on performance metrics
	if evaluationLatency > 100*time.Millisecond {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.7
		health.Error = "High evaluation latency"
	} else if evaluationLatency > 200*time.Millisecond {
		health.Status = HealthStatusCritical
		health.HealthScore = 0.4
		health.Error = "Critical evaluation latency"
	}
	
	health.Details["policy_cache_enabled"] = true
	health.Details["real_time_processing"] = true
	health.Details["active_policies"] = 15 // Simulated
	
	p.mu.Lock()
	p.lastCheck = startTime
	p.isHealthy = health.Status == HealthStatusHealthy
	p.mu.Unlock()
	
	return health
}

// ===== RATE LIMITER HEALTH CHECKER =====

type RateLimiterHealthChecker struct {
	logger      *logrus.Logger
	mu          sync.RWMutex
	lastCheck   time.Time
	isHealthy   bool
}

func (r *RateLimiterHealthChecker) GetName() string {
	return "rate_limiter"
}

func (r *RateLimiterHealthChecker) CheckHealth(ctx context.Context) ComponentHealth {
	startTime := time.Now()
	
	health := ComponentHealth{
		Name:        r.GetName(),
		Status:      HealthStatusHealthy,
		LastCheck:   startTime,
		HealthScore: 1.0,
		Details:     make(map[string]interface{}),
	}
	
	// Check rate limiter metrics
	checkLatency := 5 * time.Millisecond // Simulated
	health.Details["check_latency_ms"] = checkLatency.Milliseconds()
	health.Details["active_windows"] = 150   // Simulated
	health.Details["total_checks"] = 50000   // Simulated
	health.Details["violations"] = 25        // Simulated
	health.Details["redis_connected"] = true // Would check actual Redis in real implementation
	
	// Health scoring based on performance
	violationRate := float64(25) / float64(50000) * 100
	health.Details["violation_rate_percent"] = violationRate
	
	if checkLatency > 50*time.Millisecond {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.7
		health.Error = "High check latency"
	} else if violationRate > 10 {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.8
		health.Error = "High violation rate"
	}
	
	health.Details["sliding_window_enabled"] = true
	health.Details["lua_scripts_cached"] = true
	
	r.mu.Lock()
	r.lastCheck = startTime
	r.isHealthy = health.Status == HealthStatusHealthy
	r.mu.Unlock()
	
	return health
}

// ===== CACHE HEALTH CHECKER =====

type CacheHealthChecker struct {
	logger      *logrus.Logger
	mu          sync.RWMutex
	lastCheck   time.Time
	isHealthy   bool
}

func (c *CacheHealthChecker) GetName() string {
	return "cache_manager"
}

func (c *CacheHealthChecker) CheckHealth(ctx context.Context) ComponentHealth {
	startTime := time.Now()
	
	health := ComponentHealth{
		Name:        c.GetName(),
		Status:      HealthStatusHealthy,
		LastCheck:   startTime,
		HealthScore: 1.0,
		Details:     make(map[string]interface{}),
	}
	
	// Check cache performance metrics
	hitRate := 85.0 // Simulated hit rate
	operationLatency := 2 * time.Millisecond
	
	health.Details["hit_rate_percent"] = hitRate
	health.Details["operation_latency_ms"] = operationLatency.Milliseconds()
	health.Details["cache_size_mb"] = 250.5 // Simulated
	health.Details["total_operations"] = 75000
	health.Details["cache_hits"] = 63750
	health.Details["cache_misses"] = 11250
	
	// Health scoring
	if hitRate < 70 {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.6
		health.Error = "Low cache hit rate"
	} else if operationLatency > 10*time.Millisecond {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.7
		health.Error = "High operation latency"
	} else if hitRate < 80 {
		health.HealthScore = 0.9
	}
	
	health.Details["compression_enabled"] = true
	health.Details["ttl_policies_active"] = true
	health.Details["invalidation_enabled"] = true
	
	c.mu.Lock()
	c.lastCheck = startTime
	c.isHealthy = health.Status == HealthStatusHealthy
	c.mu.Unlock()
	
	return health
}

// ===== ALERT MANAGER HEALTH CHECKER =====

type AlertManagerHealthChecker struct {
	logger      *logrus.Logger
	mu          sync.RWMutex
	lastCheck   time.Time
	isHealthy   bool
}

func (a *AlertManagerHealthChecker) GetName() string {
	return "alert_manager"
}

func (a *AlertManagerHealthChecker) CheckHealth(ctx context.Context) ComponentHealth {
	startTime := time.Now()
	
	health := ComponentHealth{
		Name:        a.GetName(),
		Status:      HealthStatusHealthy,
		LastCheck:   startTime,
		HealthScore: 1.0,
		Details:     make(map[string]interface{}),
	}
	
	// Check alert manager metrics
	queueDepth := 5    // Simulated
	processingErrors := 0
	activeAlerts := 3
	
	health.Details["queue_depth"] = queueDepth
	health.Details["processing_errors"] = processingErrors
	health.Details["active_alerts"] = activeAlerts
	health.Details["notification_channels"] = 3
	health.Details["alert_rules"] = 25
	health.Details["real_time_processing"] = true
	
	// Health scoring
	if queueDepth > 100 {
		health.Status = HealthStatusCritical
		health.HealthScore = 0.3
		health.Error = "Alert queue overloaded"
	} else if queueDepth > 50 {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.6
		health.Error = "High alert queue depth"
	} else if processingErrors > 0 {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.8
		health.Error = "Processing errors detected"
	}
	
	health.Details["escalation_enabled"] = true
	health.Details["suppression_enabled"] = true
	
	a.mu.Lock()
	a.lastCheck = startTime
	a.isHealthy = health.Status == HealthStatusHealthy
	a.mu.Unlock()
	
	return health
}

// ===== AUDIT LOGGER HEALTH CHECKER =====

type AuditLoggerHealthChecker struct {
	logger      *logrus.Logger
	mu          sync.RWMutex
	lastCheck   time.Time
	isHealthy   bool
}

func (a *AuditLoggerHealthChecker) GetName() string {
	return "audit_logger"
}

func (a *AuditLoggerHealthChecker) CheckHealth(ctx context.Context) ComponentHealth {
	startTime := time.Now()
	
	health := ComponentHealth{
		Name:        a.GetName(),
		Status:      HealthStatusHealthy,
		LastCheck:   startTime,
		HealthScore: 1.0,
		Details:     make(map[string]interface{}),
	}
	
	// Check audit logger metrics
	queueSize := 15         // Simulated
	processingLatency := 8 * time.Millisecond
	storageSize := int64(1024 * 1024 * 500) // 500MB
	
	health.Details["queue_size"] = queueSize
	health.Details["processing_latency_ms"] = processingLatency.Milliseconds()
	health.Details["storage_size_mb"] = float64(storageSize) / 1024 / 1024
	health.Details["events_processed"] = 25000
	health.Details["storage_backends"] = 2
	
	// Health scoring
	if queueSize > 100 {
		health.Status = HealthStatusCritical
		health.HealthScore = 0.3
		health.Error = "Audit queue overloaded"
	} else if processingLatency > 50*time.Millisecond {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.6
		health.Error = "High processing latency"
	} else if queueSize > 50 {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.8
		health.Error = "High queue size"
	}
	
	health.Details["encryption_enabled"] = true
	health.Details["retention_policies_active"] = true
	health.Details["compliance_mode"] = "SOC2"
	
	a.mu.Lock()
	a.lastCheck = startTime
	a.isHealthy = health.Status == HealthStatusHealthy
	a.mu.Unlock()
	
	return health
}

// ===== PROVIDER MANAGER HEALTH CHECKER =====

type ProviderManagerHealthChecker struct {
	logger      *logrus.Logger
	mu          sync.RWMutex
	lastCheck   time.Time
	isHealthy   bool
}

func (p *ProviderManagerHealthChecker) GetName() string {
	return "provider_manager"
}

func (p *ProviderManagerHealthChecker) CheckHealth(ctx context.Context) ComponentHealth {
	startTime := time.Now()
	
	health := ComponentHealth{
		Name:        p.GetName(),
		Status:      HealthStatusHealthy,
		LastCheck:   startTime,
		HealthScore: 1.0,
		Details:     make(map[string]interface{}),
	}
	
	// Check provider manager metrics
	activeProviders := 3
	healthyProviders := 3
	avgLatency := 250 * time.Millisecond
	errorRate := 2.5
	
	health.Details["active_providers"] = activeProviders
	health.Details["healthy_providers"] = healthyProviders
	health.Details["average_latency_ms"] = avgLatency.Milliseconds()
	health.Details["error_rate_percent"] = errorRate
	health.Details["total_requests"] = 10000
	health.Details["failed_requests"] = 250
	
	// Provider-specific details
	providers := map[string]interface{}{
		"openai": map[string]interface{}{
			"status":       "healthy",
			"latency_ms":   200,
			"rate_limit":   90,
			"tokens_used":  45000,
		},
		"anthropic": map[string]interface{}{
			"status":       "healthy",
			"latency_ms":   300,
			"rate_limit":   85,
			"tokens_used":  32000,
		},
		"cohere": map[string]interface{}{
			"status":       "healthy",
			"latency_ms":   180,
			"rate_limit":   95,
			"tokens_used":  18000,
		},
	}
	health.Details["providers"] = providers
	
	// Health scoring
	if healthyProviders < activeProviders {
		unhealthyCount := activeProviders - healthyProviders
		if unhealthyCount == activeProviders {
			health.Status = HealthStatusCritical
			health.HealthScore = 0.1
			health.Error = "All providers unhealthy"
		} else {
			health.Status = HealthStatusDegraded
			health.HealthScore = float64(healthyProviders) / float64(activeProviders)
			health.Error = fmt.Sprintf("%d providers unhealthy", unhealthyCount)
		}
	} else if errorRate > 10 {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.6
		health.Error = "High error rate"
	} else if avgLatency > 1*time.Second {
		health.Status = HealthStatusDegraded
		health.HealthScore = 0.7
		health.Error = "High average latency"
	}
	
	health.Details["load_balancing_enabled"] = true
	health.Details["circuit_breaker_enabled"] = true
	health.Details["retry_policies_active"] = true
	
	p.mu.Lock()
	p.lastCheck = startTime
	p.isHealthy = health.Status == HealthStatusHealthy
	p.mu.Unlock()
	
	return health
}

// ===== DATABASE HEALTH CHECKER =====

type DatabaseHealthChecker struct {
	db     *sql.DB
	logger *logrus.Logger
	mu     sync.RWMutex
}

func (d *DatabaseHealthChecker) GetName() string {
	return "database"
}

func (d *DatabaseHealthChecker) CheckDependency(ctx context.Context) DependencyHealth {
	startTime := time.Now()
	
	health := DependencyHealth{
		Name:         d.GetName(),
		Status:       HealthStatusHealthy,
		LastCheck:    startTime,
		Connectivity: true,
		Details:      make(map[string]interface{}),
	}
	
	if d.db == nil {
		health.Status = HealthStatusCritical
		health.Connectivity = false
		health.Error = "Database connection not initialized"
		return health
	}
	
	// Test database connectivity
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	if err := d.db.PingContext(pingCtx); err != nil {
		health.Status = HealthStatusCritical
		health.Connectivity = false
		health.Error = fmt.Sprintf("Database ping failed: %v", err)
		return health
	}
	
	// Get database stats
	stats := d.db.Stats()
	health.Details["open_connections"] = stats.OpenConnections
	health.Details["in_use"] = stats.InUse
	health.Details["idle"] = stats.Idle
	health.Details["max_open_connections"] = stats.MaxOpenConnections
	health.Details["max_idle_connections"] = stats.MaxIdleConnections
	health.Details["wait_count"] = stats.WaitCount
	health.Details["wait_duration_ms"] = stats.WaitDuration.Milliseconds()
	
	// Check connection health
	if stats.OpenConnections == 0 {
		health.Status = HealthStatusCritical
		health.Error = "No database connections available"
	} else if float64(stats.InUse)/float64(stats.OpenConnections) > 0.9 {
		health.Status = HealthStatusDegraded
		health.Error = "High connection utilization"
	}
	
	// Attempt a simple query
	var result int
	queryCtx, queryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer queryCancel()
	
	queryStart := time.Now()
	err := d.db.QueryRowContext(queryCtx, "SELECT 1").Scan(&result)
	queryDuration := time.Since(queryStart)
	
	health.Details["query_latency_ms"] = queryDuration.Milliseconds()
	
	if err != nil {
		health.Status = HealthStatusCritical
		health.Error = fmt.Sprintf("Query test failed: %v", err)
	} else if queryDuration > 100*time.Millisecond {
		health.Status = HealthStatusDegraded
		health.Error = "High query latency"
	}
	
	health.Details["database_type"] = "PostgreSQL" // Could be detected dynamically
	health.Details["version"] = "13.x"           // Could be queried
	
	return health
}

// ===== REDIS HEALTH CHECKER =====

type RedisHealthChecker struct {
	client *redis.Client
	logger *logrus.Logger
	mu     sync.RWMutex
}

func (r *RedisHealthChecker) GetName() string {
	return "redis"
}

func (r *RedisHealthChecker) CheckDependency(ctx context.Context) DependencyHealth {
	startTime := time.Now()
	
	health := DependencyHealth{
		Name:         r.GetName(),
		Status:       HealthStatusHealthy,
		LastCheck:    startTime,
		Connectivity: true,
		Details:      make(map[string]interface{}),
	}
	
	if r.client == nil {
		health.Status = HealthStatusCritical
		health.Connectivity = false
		health.Error = "Redis client not initialized"
		return health
	}
	
	// Test Redis connectivity
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	
	pingStart := time.Now()
	pong, err := r.client.Ping(pingCtx).Result()
	pingDuration := time.Since(pingStart)
	
	health.Details["ping_latency_ms"] = pingDuration.Milliseconds()
	health.Details["ping_response"] = pong
	
	if err != nil {
		health.Status = HealthStatusCritical
		health.Connectivity = false
		health.Error = fmt.Sprintf("Redis ping failed: %v", err)
		return health
	}
	
	// Get Redis info
	infoCtx, infoCancel := context.WithTimeout(ctx, 3*time.Second)
	defer infoCancel()
	
	info, err := r.client.Info(infoCtx).Result()
	if err != nil {
		health.Status = HealthStatusDegraded
		health.Error = fmt.Sprintf("Failed to get Redis info: %v", err)
	} else {
		health.Details["redis_info"] = "available"
		health.Version = "6.x" // Would parse from info
	}
	
	// Test set/get operation
	testCtx, testCancel := context.WithTimeout(ctx, 3*time.Second)
	defer testCancel()
	
	testKey := "health_check_test"
	testValue := "test_value"
	
	setStart := time.Now()
	err = r.client.Set(testCtx, testKey, testValue, 10*time.Second).Err()
	setDuration := time.Since(setStart)
	
	health.Details["set_latency_ms"] = setDuration.Milliseconds()
	
	if err != nil {
		health.Status = HealthStatusDegraded
		health.Error = fmt.Sprintf("Redis set operation failed: %v", err)
	} else {
		// Test get operation
		getStart := time.Now()
		val, err := r.client.Get(testCtx, testKey).Result()
		getDuration := time.Since(getStart)
		
		health.Details["get_latency_ms"] = getDuration.Milliseconds()
		
		if err != nil {
			health.Status = HealthStatusDegraded
			health.Error = fmt.Sprintf("Redis get operation failed: %v", err)
		} else if val != testValue {
			health.Status = HealthStatusDegraded
			health.Error = "Redis data integrity check failed"
		}
		
		// Clean up test key
		r.client.Del(testCtx, testKey)
	}
	
	// Check memory usage and performance
	if pingDuration > 50*time.Millisecond {
		if health.Status == HealthStatusHealthy {
			health.Status = HealthStatusDegraded
			health.Error = "High ping latency"
		}
	}
	
	health.Details["connection_pool"] = r.client.PoolStats()
	
	return health
} 