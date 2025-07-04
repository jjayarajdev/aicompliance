package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/database"
	"ai-gateway-poc/internal/monitoring"
)

// MonitoringDemo demonstrates comprehensive AI Gateway monitoring
type MonitoringDemo struct {
	logger           *logrus.Logger
	prometheus       *monitoring.PrometheusCollector
	healthChecker    *monitoring.HealthChecker
	db              *sql.DB
	redisClient     *redis.Client
	
	// Demo state
	requestCount    int64
	errorCount      int64
	totalLatency    time.Duration
	mu              sync.RWMutex
}

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})

	demo := &MonitoringDemo{
		logger: logger,
	}

	if err := demo.initialize(); err != nil {
		log.Fatalf("Failed to initialize demo: %v", err)
	}

	demo.logger.Info("=== AI Gateway Monitoring Demo ===")
	demo.logger.Info("Starting comprehensive monitoring demonstration...")

	// Start demo scenarios
	demo.runDemoScenarios()

	// Handle shutdown gracefully
	demo.handleShutdown()
}

func (d *MonitoringDemo) initialize() error {
	d.logger.Info("Initializing monitoring demo...")

	// Initialize database (optional for demo)
	if err := d.initializeDatabase(); err != nil {
		d.logger.WithError(err).Warn("Database initialization failed (continuing without DB)")
	}

	// Initialize Redis (optional for demo)
	if err := d.initializeRedis(); err != nil {
		d.logger.WithError(err).Warn("Redis initialization failed (continuing without Redis)")
	}

	// Initialize Prometheus metrics
	if err := d.initializePrometheus(); err != nil {
		return fmt.Errorf("failed to initialize Prometheus: %w", err)
	}

	// Initialize health checker
	if err := d.initializeHealthChecker(); err != nil {
		return fmt.Errorf("failed to initialize health checker: %w", err)
	}

	d.logger.Info("Monitoring demo initialized successfully")
	return nil
}

func (d *MonitoringDemo) initializeDatabase() error {
	cfg := &config.DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "ai_gateway",
		Username: "demo_user",
		Password: "demo_pass",
		SSLMode:  "disable",
	}

	db, err := database.NewConnection(cfg, d.logger)
	if err != nil {
		return err
	}

	d.db = db
	d.logger.Info("Database connection established")
	return nil
}

func (d *MonitoringDemo) initializeRedis() error {
	d.redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.redisClient.Ping(ctx).Err(); err != nil {
		return err
	}

	d.logger.Info("Redis connection established")
	return nil
}

func (d *MonitoringDemo) initializePrometheus() error {
	config := &monitoring.PrometheusConfig{
		MetricsPort:         9090,
		MetricsPath:         "/metrics",
		EnableMetrics:       true,
		CollectionInterval:  10 * time.Second,
		EnableSystemMetrics: true,
		ServiceName:         "ai-gateway-demo",
		ServiceVersion:      "1.0.0",
		Environment:         "demo",
		EnableHistograms:    true,
		HistogramBuckets:    []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		MaxMetricAge:        24 * time.Hour,
	}

	prometheus, err := monitoring.NewPrometheusCollector(config, d.logger)
	if err != nil {
		return err
	}

	d.prometheus = prometheus

	// Start metrics server
	if err := prometheus.StartMetricsServer(); err != nil {
		return err
	}

	d.logger.WithField("port", config.MetricsPort).Info("Prometheus metrics server started")
	return nil
}

func (d *MonitoringDemo) initializeHealthChecker() error {
	config := &monitoring.HealthConfig{
		HealthCheckInterval:     30 * time.Second,
		DependencyCheckInterval: 60 * time.Second,
		ComponentTimeout:        5 * time.Second,
		DependencyTimeout:      10 * time.Second,
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

	healthChecker, err := monitoring.NewHealthChecker(config, d.logger, d.db, d.redisClient, d.prometheus)
	if err != nil {
		return err
	}

	d.healthChecker = healthChecker

	// Start health check HTTP server
	mux := http.NewServeMux()
	healthChecker.RegisterHTTPHandlers(mux)

	// Add metrics endpoint to health server
	mux.Handle("/metrics", d.prometheus.GetHandler())

	// Add demo endpoints
	mux.HandleFunc("/demo/metrics", d.demoMetricsHandler)
	mux.HandleFunc("/demo/status", d.demoStatusHandler)

	go func() {
		d.logger.Info("Starting health check server on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			d.logger.WithError(err).Error("Health check server failed")
		}
	}()

	d.logger.Info("Health checker initialized and HTTP server started on :8080")
	return nil
}

func (d *MonitoringDemo) runDemoScenarios() {
	d.logger.Info("Starting monitoring demo scenarios...")

	// Start background workers to simulate activity
	go d.simulatePolicyEvaluations()
	go d.simulateRateLimitChecks()
	go d.simulateCacheOperations()
	go d.simulateProviderRequests()
	go d.simulateAlertProcessing()
	go d.simulateAuditEvents()

	// Start periodic health checks
	go d.periodicHealthChecks()

	// Start metrics reporting
	go d.periodicMetricsReporting()

	d.logger.Info("=== DEMO ENDPOINTS ===")
	d.logger.Info("Prometheus Metrics: http://localhost:9090/metrics")
	d.logger.Info("Health Check: http://localhost:8080/health")
	d.logger.Info("Readiness: http://localhost:8080/health/ready")
	d.logger.Info("Liveness: http://localhost:8080/health/live")
	d.logger.Info("Demo Metrics: http://localhost:8080/demo/metrics")
	d.logger.Info("Demo Status: http://localhost:8080/demo/status")
	d.logger.Info("======================")

	// Run demonstration scenarios
	d.demonstrateScenarios()
}

func (d *MonitoringDemo) simulatePolicyEvaluations() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		// Simulate various policy evaluations
		policies := []string{"security", "compliance", "cost_control", "rate_limit"}
		results := []string{"allow", "deny", "conditional"}

		for _, policy := range policies {
			for _, result := range results {
				// Simulate evaluation latency
				latency := time.Duration(10+rand.Intn(90)) * time.Millisecond
				cacheHit := rand.Float32() < 0.7 // 70% cache hit rate

				d.prometheus.RecordPolicyEvaluation(policy, result, latency, cacheHit)

				// Occasionally simulate errors
				if rand.Float32() < 0.02 { // 2% error rate
					d.prometheus.RecordPolicyError(policy, "timeout")
				}
			}
		}

		// Update aggregate metrics
		d.prometheus.UpdatePolicyMetrics(45*time.Millisecond, 250.0)
	}
}

func (d *MonitoringDemo) simulateRateLimitChecks() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	users := []string{"user1", "user2", "user3", "user4", "user5"}
	orgs := []string{"org1", "org2", "org3"}
	endpoints := []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings"}
	windows := []string{"per_second", "per_minute", "per_hour", "per_day"}

	for range ticker.C {
		user := users[rand.Intn(len(users))]
		org := orgs[rand.Intn(len(orgs))]
		endpoint := endpoints[rand.Intn(len(endpoints))]
		window := windows[rand.Intn(len(windows))]

		// Simulate check latency
		latency := time.Duration(1+rand.Intn(10)) * time.Millisecond
		windowUsage := rand.Float64() * 100

		result := "allowed"
		if windowUsage > 90 {
			result = "denied"
			d.prometheus.RecordRateLimitViolation(user, org, endpoint, window, "quota_exceeded")
		}

		d.prometheus.RecordRateLimitCheck(user, org, endpoint, window, result, latency, windowUsage)
	}
}

func (d *MonitoringDemo) simulateCacheOperations() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	cacheTypes := []string{"policy", "result", "metadata"}
	operations := []string{"get", "set", "delete", "invalidate"}

	for range ticker.C {
		cacheType := cacheTypes[rand.Intn(len(cacheTypes))]
		operation := operations[rand.Intn(len(operations))]

		latency := time.Duration(rand.Intn(5)) * time.Millisecond
		result := "hit"
		if rand.Float32() < 0.2 { // 20% miss rate
			result = "miss"
		}

		d.prometheus.RecordCacheOperation(cacheType, operation, result, latency)

		// Update cache metrics periodically
		if rand.Float32() < 0.1 {
			hitRate := 75.0 + rand.Float64()*20 // 75-95%
			sizeBytes := int64(200*1024*1024 + rand.Intn(100*1024*1024)) // 200-300MB
			compressionRatio := 0.6 + rand.Float64()*0.3 // 0.6-0.9

			d.prometheus.UpdateCacheMetrics(cacheType, hitRate, sizeBytes, compressionRatio)
		}
	}
}

func (d *MonitoringDemo) simulateProviderRequests() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	providers := []string{"openai", "anthropic", "cohere"}
	models := map[string][]string{
		"openai":    {"gpt-3.5-turbo", "gpt-4", "text-embedding-ada-002"},
		"anthropic": {"claude-3-sonnet", "claude-3-haiku", "claude-instant"},
		"cohere":    {"command", "command-light", "embed-english-v2.0"},
	}
	endpoints := []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings"}
	statuses := []string{"200", "429", "500", "503"}

	for range ticker.C {
		provider := providers[rand.Intn(len(providers))]
		model := models[provider][rand.Intn(len(models[provider]))]
		endpoint := endpoints[rand.Intn(len(endpoints))]
		status := statuses[0] // Mostly successful

		// Simulate some errors
		if rand.Float32() < 0.05 { // 5% error rate
			status = statuses[1+rand.Intn(len(statuses)-1)]
		}

		latency := time.Duration(100+rand.Intn(400)) * time.Millisecond
		d.prometheus.RecordProviderRequest(provider, model, endpoint, status, latency)

		// Record errors
		if status != "200" {
			errorType := "rate_limit"
			if status == "500" {
				errorType = "internal_error"
			} else if status == "503" {
				errorType = "service_unavailable"
			}
			d.prometheus.RecordProviderError(provider, model, errorType, status)
		}

		// Record token usage
		if status == "200" {
			tokenType := "prompt"
			count := int64(50 + rand.Intn(200))
			d.prometheus.RecordProviderTokenUsage(provider, model, tokenType, count)

			tokenType = "completion"
			count = int64(10 + rand.Intn(100))
			d.prometheus.RecordProviderTokenUsage(provider, model, tokenType, count)
		}
	}
}

func (d *MonitoringDemo) simulateAlertProcessing() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	alertTypes := []string{"rate_limit_exceeded", "provider_error", "high_latency", "system_health"}
	severities := []string{"info", "warning", "critical"}

	for range ticker.C {
		if rand.Float32() < 0.3 { // 30% chance of alert
			alertType := alertTypes[rand.Intn(len(alertTypes))]
			severity := severities[rand.Intn(len(severities))]
			status := "triggered"

			// Simulate alert processing
			processingLatency := time.Duration(10+rand.Intn(100)) * time.Millisecond

			// Record metrics
			d.prometheus.RecordAlertProcessingLatency(alertType, processingLatency)
		}
	}
}

func (d *MonitoringDemo) simulateAuditEvents() {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	categories := []string{"authentication", "authorization", "data_access", "configuration"}
	eventTypes := []string{"login", "policy_evaluation", "api_request", "config_change"}
	users := []string{"user1", "user2", "admin", "service_account"}

	for range ticker.C {
		category := categories[rand.Intn(len(categories))]
		eventType := eventTypes[rand.Intn(len(eventTypes))]
		user := users[rand.Intn(len(users))]

		processingLatency := time.Duration(1+rand.Intn(10)) * time.Millisecond

		// Record audit metrics
		d.prometheus.RecordAuditEvent(category, eventType, user)
		d.prometheus.RecordAuditProcessingLatency(category, processingLatency)
	}
}

func (d *MonitoringDemo) periodicHealthChecks() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		
		health, err := d.healthChecker.CheckHealth(ctx)
		if err != nil {
			d.logger.WithError(err).Error("Health check failed")
		} else {
			d.logger.WithFields(logrus.Fields{
				"status":         health.Status,
				"components":     len(health.Components),
				"dependencies":   len(health.Dependencies),
				"overall_score":  health.Summary.OverallScore,
				"uptime":        health.Uptime,
			}).Info("Periodic health check completed")
		}
		
		cancel()
	}
}

func (d *MonitoringDemo) periodicMetricsReporting() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		d.logger.WithFields(logrus.Fields{
			"prometheus_port": 9090,
			"health_port":     8080,
			"uptime":         time.Since(time.Now()),
		}).Info("Metrics collection active")
	}
}

func (d *MonitoringDemo) demonstrateScenarios() {
	scenarios := []struct {
		name        string
		description string
		duration    time.Duration
		action      func()
	}{
		{
			name:        "Normal Operations",
			description: "Simulating normal AI Gateway operations",
			duration:    30 * time.Second,
			action: func() {
				d.logger.Info("📊 Scenario: Normal operations - steady metrics collection")
			},
		},
		{
			name:        "High Load Simulation",
			description: "Simulating high load with increased error rates",
			duration:    20 * time.Second,
			action: func() {
				d.logger.Info("🔥 Scenario: High load - expect degraded health status")
				// Temporarily increase error simulation rates
			},
		},
		{
			name:        "Health Check Demonstration",
			description: "Triggering comprehensive health checks",
			duration:    10 * time.Second,
			action: func() {
				d.logger.Info("❤️ Scenario: Health check demonstration")
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				
				health, err := d.healthChecker.CheckHealth(ctx)
				if err != nil {
					d.logger.WithError(err).Error("Health check failed")
				} else {
					d.logHealthSummary(health)
				}
			},
		},
		{
			name:        "Metrics Analysis",
			description: "Analyzing collected metrics",
			duration:    15 * time.Second,
			action: func() {
				d.logger.Info("📈 Scenario: Metrics analysis")
				d.logMetricsSummary()
			},
		},
	}

	for _, scenario := range scenarios {
		d.logger.WithFields(logrus.Fields{
			"scenario":    scenario.name,
			"description": scenario.description,
			"duration":    scenario.duration,
		}).Info("Starting scenario")

		scenario.action()
		time.Sleep(scenario.duration)

		d.logger.WithField("scenario", scenario.name).Info("Scenario completed")
		time.Sleep(5 * time.Second) // Pause between scenarios
	}
}

func (d *MonitoringDemo) logHealthSummary(health *monitoring.SystemHealth) {
	d.logger.WithFields(logrus.Fields{
		"overall_status":      health.Status,
		"overall_score":       health.Summary.OverallScore,
		"healthy_components":  health.Summary.HealthyComponents,
		"total_components":    health.Summary.TotalComponents,
		"healthy_dependencies": health.Summary.HealthyDependencies,
		"total_dependencies":  health.Summary.TotalDependencies,
		"critical_issues":     health.Summary.CriticalIssues,
		"uptime":             health.Uptime,
		"memory_usage_mb":     float64(health.System.MemoryUsage) / 1024 / 1024,
		"goroutines":         health.System.GoroutineCount,
	}).Info("📋 Health Check Summary")

	// Log component details
	for name, comp := range health.Components {
		d.logger.WithFields(logrus.Fields{
			"component":     name,
			"status":        comp.Status,
			"health_score":  comp.HealthScore,
			"response_time": comp.ResponseTime,
			"error":        comp.Error,
		}).Info("Component health")
	}

	// Log dependency details
	for name, dep := range health.Dependencies {
		d.logger.WithFields(logrus.Fields{
			"dependency":    name,
			"status":        dep.Status,
			"connectivity":  dep.Connectivity,
			"response_time": dep.ResponseTime,
			"version":      dep.Version,
			"error":        dep.Error,
		}).Info("Dependency health")
	}
}

func (d *MonitoringDemo) logMetricsSummary() {
	d.mu.RLock()
	defer d.mu.RUnlock()

	d.logger.WithFields(logrus.Fields{
		"total_requests":   d.requestCount,
		"total_errors":     d.errorCount,
		"average_latency":  d.totalLatency / time.Duration(max(d.requestCount, 1)),
		"error_rate":      float64(d.errorCount) / float64(max(d.requestCount, 1)) * 100,
	}).Info("📊 Metrics Summary")
}

// HTTP Handlers

func (d *MonitoringDemo) demoMetricsHandler(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	response := map[string]interface{}{
		"demo_status": "active",
		"metrics": map[string]interface{}{
			"total_requests":   d.requestCount,
			"total_errors":     d.errorCount,
			"average_latency":  d.totalLatency / time.Duration(max(d.requestCount, 1)),
			"error_rate":      float64(d.errorCount) / float64(max(d.requestCount, 1)) * 100,
		},
		"endpoints": map[string]string{
			"prometheus": "http://localhost:9090/metrics",
			"health":     "http://localhost:8080/health",
			"readiness":  "http://localhost:8080/health/ready",
			"liveness":   "http://localhost:8080/health/live",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (d *MonitoringDemo) demoStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"demo_name":        "AI Gateway Monitoring Demo",
		"version":          "1.0.0",
		"status":           "running",
		"components":       []string{"prometheus", "health_checker", "policy_engine", "rate_limiter", "cache", "providers"},
		"prometheus_port":  9090,
		"health_port":      8080,
		"demonstration":    "active",
		"start_time":       time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (d *MonitoringDemo) handleShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	d.logger.Info("Monitoring demo running... Press Ctrl+C to stop")
	<-c

	d.logger.Info("Shutting down monitoring demo...")

	// Cleanup resources
	if d.db != nil {
		d.db.Close()
	}
	if d.redisClient != nil {
		d.redisClient.Close()
	}

	d.logger.Info("Monitoring demo shutdown complete")
}

// Utility functions

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// Simple random number generator for demo
var rand = struct {
	seed int64
	mu   sync.Mutex
}{seed: time.Now().UnixNano()}

func (r *struct {
	seed int64
	mu   sync.Mutex
}) Intn(n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seed = (r.seed*1103515245 + 12345) & 0x7fffffff
	return int(r.seed) % n
}

func (r *struct {
	seed int64
	mu   sync.Mutex
}) Float32() float32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seed = (r.seed*1103515245 + 12345) & 0x7fffffff
	return float32(r.seed) / float32(0x7fffffff)
}

func (r *struct {
	seed int64
	mu   sync.Mutex
}) Float64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seed = (r.seed*1103515245 + 12345) & 0x7fffffff
	return float64(r.seed) / float64(0x7fffffff)
} 