package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"ai-gateway-poc/internal/database"
)

// HealthChecker provides comprehensive health monitoring for all AI Gateway components
type HealthChecker struct {
	// Core dependencies
	logger       *logrus.Logger
	db          *sql.DB
	redisClient *redis.Client
	
	// Component monitors
	components   map[string]ComponentHealthChecker
	dependencies map[string]DependencyChecker
	
	// Configuration
	config       *HealthConfig
	
	// State tracking
	lastCheck    time.Time
	overallHealth HealthStatus
	
	// Prometheus integration
	prometheus   *PrometheusCollector
	
	// Synchronization
	mu           sync.RWMutex
	startTime    time.Time
}

// ComponentHealthChecker interface for individual component health checks
type ComponentHealthChecker interface {
	CheckHealth(ctx context.Context) ComponentHealth
	GetName() string
}

// DependencyChecker interface for external dependency health checks
type DependencyChecker interface {
	CheckDependency(ctx context.Context) DependencyHealth
	GetName() string
}

// HealthStatus represents overall system health
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusCritical  HealthStatus = "critical"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// ComponentHealth represents individual component health
type ComponentHealth struct {
	Name           string                 `json:"name"`
	Status         HealthStatus           `json:"status"`
	LastCheck      time.Time              `json:"last_check"`
	ResponseTime   time.Duration          `json:"response_time"`
	Details        map[string]interface{} `json:"details"`
	Error          string                 `json:"error,omitempty"`
	HealthScore    float64                `json:"health_score"` // 0.0 to 1.0
}

// DependencyHealth represents external dependency health
type DependencyHealth struct {
	Name           string                 `json:"name"`
	Status         HealthStatus           `json:"status"`
	LastCheck      time.Time              `json:"last_check"`
	ResponseTime   time.Duration          `json:"response_time"`
	Details        map[string]interface{} `json:"details"`
	Error          string                 `json:"error,omitempty"`
	Version        string                 `json:"version,omitempty"`
	Connectivity   bool                   `json:"connectivity"`
}

// SystemHealth represents complete system health information
type SystemHealth struct {
	Status       HealthStatus                     `json:"status"`
	Timestamp    time.Time                        `json:"timestamp"`
	Uptime       time.Duration                    `json:"uptime"`
	Version      string                           `json:"version"`
	Environment  string                           `json:"environment"`
	Components   map[string]ComponentHealth       `json:"components"`
	Dependencies map[string]DependencyHealth      `json:"dependencies"`
	System       SystemMetrics                    `json:"system"`
	Summary      HealthSummary                    `json:"summary"`
}

// HealthSummary provides high-level health statistics
type HealthSummary struct {
	TotalComponents    int     `json:"total_components"`
	HealthyComponents  int     `json:"healthy_components"`
	TotalDependencies  int     `json:"total_dependencies"`
	HealthyDependencies int    `json:"healthy_dependencies"`
	OverallScore       float64 `json:"overall_score"`
	CriticalIssues     []string `json:"critical_issues"`
}

// SystemMetrics provides system-level health metrics
type SystemMetrics struct {
	CPUUsage         float64   `json:"cpu_usage_percent"`
	MemoryUsage      int64     `json:"memory_usage_bytes"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`
	GoroutineCount   int       `json:"goroutine_count"`
	OpenFileDescriptors int    `json:"open_file_descriptors"`
	LoadAverage      []float64 `json:"load_average"`
}

// HealthConfig holds health checker configuration
type HealthConfig struct {
	// Check intervals
	HealthCheckInterval     time.Duration `json:"health_check_interval" yaml:"health_check_interval"`
	DependencyCheckInterval time.Duration `json:"dependency_check_interval" yaml:"dependency_check_interval"`
	
	// Timeouts
	ComponentTimeout        time.Duration `json:"component_timeout" yaml:"component_timeout"`
	DependencyTimeout       time.Duration `json:"dependency_timeout" yaml:"dependency_timeout"`
	
	// Thresholds
	HealthyThreshold        float64       `json:"healthy_threshold" yaml:"healthy_threshold"`
	DegradedThreshold       float64       `json:"degraded_threshold" yaml:"degraded_threshold"`
	CriticalThreshold       float64       `json:"critical_threshold" yaml:"critical_threshold"`
	
	// System monitoring
	EnableSystemMetrics     bool          `json:"enable_system_metrics" yaml:"enable_system_metrics"`
	MemoryThresholdPercent  float64       `json:"memory_threshold_percent" yaml:"memory_threshold_percent"`
	CPUThresholdPercent     float64       `json:"cpu_threshold_percent" yaml:"cpu_threshold_percent"`
	
	// Endpoints
	HealthEndpoint          string        `json:"health_endpoint" yaml:"health_endpoint"`
	ReadinessEndpoint       string        `json:"readiness_endpoint" yaml:"readiness_endpoint"`
	LivenessEndpoint        string        `json:"liveness_endpoint" yaml:"liveness_endpoint"`
	
	// Features
	EnableDetailedHealth    bool          `json:"enable_detailed_health" yaml:"enable_detailed_health"`
	EnablePrometheusMetrics bool          `json:"enable_prometheus_metrics" yaml:"enable_prometheus_metrics"`
}

// NewHealthChecker creates a new health checker instance
func NewHealthChecker(config *HealthConfig, logger *logrus.Logger, db *sql.DB, redisClient *redis.Client, prometheus *PrometheusCollector) (*HealthChecker, error) {
	if config == nil {
		config = getDefaultHealthConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	hc := &HealthChecker{
		logger:       logger,
		db:          db,
		redisClient: redisClient,
		config:      config,
		components:  make(map[string]ComponentHealthChecker),
		dependencies: make(map[string]DependencyChecker),
		prometheus:  prometheus,
		startTime:   time.Now(),
		overallHealth: HealthStatusHealthy,
	}
	
	// Register default components and dependencies
	if err := hc.registerDefaultCheckers(); err != nil {
		return nil, fmt.Errorf("failed to register default checkers: %w", err)
	}
	
	logger.WithFields(logrus.Fields{
		"health_endpoint":   config.HealthEndpoint,
		"readiness_endpoint": config.ReadinessEndpoint,
		"liveness_endpoint":  config.LivenessEndpoint,
		"check_interval":     config.HealthCheckInterval,
	}).Info("Health checker initialized")
	
	return hc, nil
}

// registerDefaultCheckers registers default health checkers
func (hc *HealthChecker) registerDefaultCheckers() error {
	// Register component checkers
	hc.RegisterComponent(&PolicyEngineHealthChecker{logger: hc.logger})
	hc.RegisterComponent(&RateLimiterHealthChecker{logger: hc.logger})
	hc.RegisterComponent(&CacheHealthChecker{logger: hc.logger})
	hc.RegisterComponent(&AlertManagerHealthChecker{logger: hc.logger})
	hc.RegisterComponent(&AuditLoggerHealthChecker{logger: hc.logger})
	hc.RegisterComponent(&ProviderManagerHealthChecker{logger: hc.logger})
	
	// Register dependency checkers
	if hc.db != nil {
		hc.RegisterDependency(&DatabaseHealthChecker{db: hc.db, logger: hc.logger})
	}
	
	if hc.redisClient != nil {
		hc.RegisterDependency(&RedisHealthChecker{client: hc.redisClient, logger: hc.logger})
	}
	
	return nil
}

// RegisterComponent registers a component health checker
func (hc *HealthChecker) RegisterComponent(checker ComponentHealthChecker) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.components[checker.GetName()] = checker
	hc.logger.WithField("component", checker.GetName()).Info("Registered component health checker")
}

// RegisterDependency registers a dependency health checker
func (hc *HealthChecker) RegisterDependency(checker DependencyChecker) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.dependencies[checker.GetName()] = checker
	hc.logger.WithField("dependency", checker.GetName()).Info("Registered dependency health checker")
}

// CheckHealth performs comprehensive health check
func (hc *HealthChecker) CheckHealth(ctx context.Context) (*SystemHealth, error) {
	startTime := time.Now()
	
	health := &SystemHealth{
		Timestamp:    startTime,
		Uptime:       time.Since(hc.startTime),
		Version:      "1.0.0", // TODO: Get from config
		Environment:  "development", // TODO: Get from config
		Components:   make(map[string]ComponentHealth),
		Dependencies: make(map[string]DependencyHealth),
	}
	
	// Check all components
	hc.checkComponents(ctx, health)
	
	// Check all dependencies
	hc.checkDependencies(ctx, health)
	
	// Get system metrics
	health.System = hc.getSystemMetrics()
	
	// Calculate overall health
	health.Status, health.Summary = hc.calculateOverallHealth(health)
	
	// Update Prometheus metrics
	if hc.prometheus != nil && hc.config.EnablePrometheusMetrics {
		hc.updatePrometheusMetrics(health)
	}
	
	// Update state
	hc.mu.Lock()
	hc.lastCheck = startTime
	hc.overallHealth = health.Status
	hc.mu.Unlock()
	
	// Record health check duration
	if hc.prometheus != nil {
		hc.prometheus.RecordHealthCheckDuration("system", time.Since(startTime))
	}
	
	hc.logger.WithFields(logrus.Fields{
		"status":           health.Status,
		"components":       len(health.Components),
		"dependencies":     len(health.Dependencies),
		"duration":         time.Since(startTime),
		"overall_score":    health.Summary.OverallScore,
	}).Info("Health check completed")
	
	return health, nil
}

// checkComponents checks all registered components
func (hc *HealthChecker) checkComponents(ctx context.Context, health *SystemHealth) {
	hc.mu.RLock()
	components := make(map[string]ComponentHealthChecker)
	for k, v := range hc.components {
		components[k] = v
	}
	hc.mu.RUnlock()
	
	for name, checker := range components {
		componentCtx, cancel := context.WithTimeout(ctx, hc.config.ComponentTimeout)
		
		startTime := time.Now()
		componentHealth := checker.CheckHealth(componentCtx)
		componentHealth.ResponseTime = time.Since(startTime)
		componentHealth.LastCheck = startTime
		
		health.Components[name] = componentHealth
		
		// Update Prometheus metrics
		if hc.prometheus != nil {
			healthy := componentHealth.Status == HealthStatusHealthy
			hc.prometheus.UpdateComponentHealth(name, healthy)
			hc.prometheus.RecordHealthCheckDuration(name, componentHealth.ResponseTime)
		}
		
		cancel()
	}
}

// checkDependencies checks all registered dependencies
func (hc *HealthChecker) checkDependencies(ctx context.Context, health *SystemHealth) {
	hc.mu.RLock()
	dependencies := make(map[string]DependencyChecker)
	for k, v := range hc.dependencies {
		dependencies[k] = v
	}
	hc.mu.RUnlock()
	
	for name, checker := range dependencies {
		depCtx, cancel := context.WithTimeout(ctx, hc.config.DependencyTimeout)
		
		startTime := time.Now()
		depHealth := checker.CheckDependency(depCtx)
		depHealth.ResponseTime = time.Since(startTime)
		depHealth.LastCheck = startTime
		
		health.Dependencies[name] = depHealth
		
		// Update Prometheus metrics
		if hc.prometheus != nil {
			healthy := depHealth.Status == HealthStatusHealthy
			hc.prometheus.UpdateDependencyHealth(name, healthy)
			hc.prometheus.RecordHealthCheckDuration(name, depHealth.ResponseTime)
		}
		
		cancel()
	}
}

// getSystemMetrics collects system-level metrics
func (hc *HealthChecker) getSystemMetrics() SystemMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	metrics := SystemMetrics{
		MemoryUsage:    int64(memStats.Alloc),
		GoroutineCount: runtime.NumGoroutine(),
	}
	
	// Calculate memory usage percentage (simplified)
	totalMem := int64(memStats.Sys)
	if totalMem > 0 {
		metrics.MemoryUsagePercent = float64(metrics.MemoryUsage) / float64(totalMem) * 100
	}
	
	return metrics
}

// calculateOverallHealth determines overall system health
func (hc *HealthChecker) calculateOverallHealth(health *SystemHealth) (HealthStatus, HealthSummary) {
	summary := HealthSummary{
		TotalComponents:   len(health.Components),
		TotalDependencies: len(health.Dependencies),
		CriticalIssues:    []string{},
	}
	
	// Count healthy components
	componentScore := 0.0
	for _, comp := range health.Components {
		if comp.Status == HealthStatusHealthy {
			summary.HealthyComponents++
			componentScore += comp.HealthScore
		} else if comp.Status == HealthStatusCritical {
			summary.CriticalIssues = append(summary.CriticalIssues, fmt.Sprintf("Component %s is critical", comp.Name))
		}
	}
	
	// Count healthy dependencies
	dependencyScore := 0.0
	for _, dep := range health.Dependencies {
		if dep.Status == HealthStatusHealthy {
			summary.HealthyDependencies++
			dependencyScore += 1.0
		} else if dep.Status == HealthStatusCritical || dep.Status == HealthStatusUnhealthy {
			summary.CriticalIssues = append(summary.CriticalIssues, fmt.Sprintf("Dependency %s is %s", dep.Name, dep.Status))
		}
	}
	
	// Calculate overall score
	totalChecks := summary.TotalComponents + summary.TotalDependencies
	if totalChecks > 0 {
		summary.OverallScore = (componentScore + dependencyScore) / float64(totalChecks)
	} else {
		summary.OverallScore = 1.0
	}
	
	// Determine overall status
	var status HealthStatus
	switch {
	case summary.OverallScore >= hc.config.HealthyThreshold:
		status = HealthStatusHealthy
	case summary.OverallScore >= hc.config.DegradedThreshold:
		status = HealthStatusDegraded
	case summary.OverallScore >= hc.config.CriticalThreshold:
		status = HealthStatusCritical
	default:
		status = HealthStatusUnhealthy
	}
	
	// Check for critical system metrics
	if hc.config.EnableSystemMetrics {
		if health.System.MemoryUsagePercent > hc.config.MemoryThresholdPercent {
			summary.CriticalIssues = append(summary.CriticalIssues, "High memory usage")
			if status == HealthStatusHealthy {
				status = HealthStatusDegraded
			}
		}
		
		if health.System.CPUUsage > hc.config.CPUThresholdPercent {
			summary.CriticalIssues = append(summary.CriticalIssues, "High CPU usage")
			if status == HealthStatusHealthy {
				status = HealthStatusDegraded
			}
		}
	}
	
	return status, summary
}

// updatePrometheusMetrics updates Prometheus metrics based on health check results
func (hc *HealthChecker) updatePrometheusMetrics(health *SystemHealth) {
	// Update component health metrics
	for name, comp := range health.Components {
		healthy := comp.Status == HealthStatusHealthy
		hc.prometheus.UpdateComponentHealth(name, healthy)
	}
	
	// Update dependency health metrics
	for name, dep := range health.Dependencies {
		healthy := dep.Status == HealthStatusHealthy
		hc.prometheus.UpdateDependencyHealth(name, healthy)
	}
}

// HTTP Handlers

// HealthHandler returns detailed health information
func (hc *HealthChecker) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	
	health, err := hc.CheckHealth(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("Health check failed: %v", err), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	// Set appropriate HTTP status code
	switch health.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK) // Still OK but degraded
	case HealthStatusCritical:
		w.WriteHeader(http.StatusServiceUnavailable)
	case HealthStatusUnhealthy:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	if err := json.NewEncoder(w).Encode(health); err != nil {
		hc.logger.WithError(err).Error("Failed to encode health response")
	}
}

// ReadinessHandler checks if the service is ready to serve traffic
func (hc *HealthChecker) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	
	health, err := hc.CheckHealth(ctx)
	if err != nil {
		http.Error(w, "Not ready", http.StatusServiceUnavailable)
		return
	}
	
	// Service is ready if not unhealthy
	if health.Status == HealthStatusUnhealthy {
		http.Error(w, "Not ready", http.StatusServiceUnavailable)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]interface{}{
		"status": "ready",
		"timestamp": time.Now(),
		"overall_status": health.Status,
		"summary": health.Summary,
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		hc.logger.WithError(err).Error("Failed to encode readiness response")
	}
}

// LivenessHandler checks if the service is alive
func (hc *HealthChecker) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]interface{}{
		"status": "alive",
		"timestamp": time.Now(),
		"uptime": time.Since(hc.startTime),
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		hc.logger.WithError(err).Error("Failed to encode liveness response")
	}
}

// RegisterHTTPHandlers registers health check HTTP handlers
func (hc *HealthChecker) RegisterHTTPHandlers(mux *http.ServeMux) {
	mux.HandleFunc(hc.config.HealthEndpoint, hc.HealthHandler)
	mux.HandleFunc(hc.config.ReadinessEndpoint, hc.ReadinessHandler)
	mux.HandleFunc(hc.config.LivenessEndpoint, hc.LivenessHandler)
	
	hc.logger.WithFields(logrus.Fields{
		"health_endpoint":    hc.config.HealthEndpoint,
		"readiness_endpoint": hc.config.ReadinessEndpoint,
		"liveness_endpoint":  hc.config.LivenessEndpoint,
	}).Info("Health check HTTP handlers registered")
}

// getDefaultHealthConfig returns default health configuration
func getDefaultHealthConfig() *HealthConfig {
	return &HealthConfig{
		HealthCheckInterval:     30 * time.Second,
		DependencyCheckInterval: 60 * time.Second,
		ComponentTimeout:        5 * time.Second,
		DependencyTimeout:       10 * time.Second,
		HealthyThreshold:        0.9,
		DegradedThreshold:       0.7,
		CriticalThreshold:       0.5,
		EnableSystemMetrics:     true,
		MemoryThresholdPercent:  80.0,
		CPUThresholdPercent:     80.0,
		HealthEndpoint:          "/health",
		ReadinessEndpoint:       "/health/ready",
		LivenessEndpoint:        "/health/live",
		EnableDetailedHealth:    true,
		EnablePrometheusMetrics: true,
	}
} 