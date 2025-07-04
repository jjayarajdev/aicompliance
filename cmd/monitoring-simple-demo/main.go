package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"ai-gateway-poc/internal/monitoring"
)

// SimpleMonitoringDemo demonstrates Prometheus metrics and health checks
type SimpleMonitoringDemo struct {
	logger        *logrus.Logger
	prometheus    *monitoring.PrometheusCollector
	healthChecker *monitoring.HealthChecker
	
	// Demo state
	requestCount int64
	errorCount   int64
	mu           sync.RWMutex
}

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.JSONFormatter{})

	demo := &SimpleMonitoringDemo{
		logger: logger,
	}

	if err := demo.initialize(); err != nil {
		log.Fatalf("Failed to initialize demo: %v", err)
	}

	demo.logger.Info("=== AI Gateway Monitoring Demo (Simplified) ===")
	demo.logger.Info("Starting Prometheus metrics and health check demonstration...")

	// Start demo
	demo.runDemo()
}

func (d *SimpleMonitoringDemo) initialize() error {
	d.logger.Info("Initializing simplified monitoring demo...")

	// Initialize Prometheus metrics
	if err := d.initializePrometheus(); err != nil {
		return fmt.Errorf("failed to initialize Prometheus: %w", err)
	}

	// Initialize health checker
	if err := d.initializeHealthChecker(); err != nil {
		return fmt.Errorf("failed to initialize health checker: %w", err)
	}

	d.logger.Info("Simplified monitoring demo initialized successfully")
	return nil
}

func (d *SimpleMonitoringDemo) initializePrometheus() error {
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

func (d *SimpleMonitoringDemo) initializeHealthChecker() error {
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

	healthChecker, err := monitoring.NewHealthChecker(config, d.logger, nil, nil, d.prometheus)
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
	mux.HandleFunc("/demo/status", d.demoStatusHandler)
	mux.HandleFunc("/demo/trigger-metrics", d.triggerMetricsHandler)

	go func() {
		d.logger.Info("Starting health check server on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			d.logger.WithError(err).Error("Health check server failed")
		}
	}()

	d.logger.Info("Health checker initialized and HTTP server started on :8080")
	return nil
}

func (d *SimpleMonitoringDemo) runDemo() {
	d.logger.Info("=== DEMO ENDPOINTS ===")
	d.logger.Info("Prometheus Metrics: http://localhost:9090/metrics")
	d.logger.Info("Health Check: http://localhost:8080/health")
	d.logger.Info("Readiness: http://localhost:8080/health/ready")
	d.logger.Info("Liveness: http://localhost:8080/health/live")
	d.logger.Info("Demo Status: http://localhost:8080/demo/status")
	d.logger.Info("Trigger Metrics: http://localhost:8080/demo/trigger-metrics")
	d.logger.Info("======================")

	// Start background metric generation
	go d.simulateMetrics()

	// Start periodic health checks
	go d.periodicHealthChecks()

	// Run demonstration scenarios
	d.demonstrateFeatures()

	// Handle shutdown
	d.handleShutdown()
}

func (d *SimpleMonitoringDemo) simulateMetrics() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Simulate policy evaluations
		d.prometheus.RecordPolicyEvaluation("security", "allow", 25*time.Millisecond, true)
		d.prometheus.RecordPolicyEvaluation("compliance", "deny", 45*time.Millisecond, false)

		// Simulate rate limit checks
		d.prometheus.RecordRateLimitCheck("user1", "org1", "/v1/chat", "per_minute", "allowed", 5*time.Millisecond, 75.0)
		
		// Simulate cache operations
		d.prometheus.RecordCacheOperation("policy", "get", "hit", 2*time.Millisecond)
		d.prometheus.UpdateCacheMetrics("policy", 85.0, 256*1024*1024, 0.7)

		// Simulate provider requests
		d.prometheus.RecordProviderRequest("openai", "gpt-3.5-turbo", "/v1/chat/completions", "200", 250*time.Millisecond)
		d.prometheus.RecordProviderTokenUsage("openai", "gpt-3.5-turbo", "prompt", 150)
		d.prometheus.RecordProviderTokenUsage("openai", "gpt-3.5-turbo", "completion", 75)

		// Simulate HTTP requests
		d.prometheus.RecordHTTPRequest("POST", "/v1/chat/completions", "200", 300*time.Millisecond)

		// Update counters
		d.mu.Lock()
		d.requestCount++
		if d.requestCount%20 == 0 { // 5% error rate
			d.errorCount++
		}
		d.mu.Unlock()

		d.logger.Debug("Generated metrics sample")
	}
}

func (d *SimpleMonitoringDemo) periodicHealthChecks() {
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
				"overall_score":  health.Summary.OverallScore,
				"uptime":        health.Uptime,
			}).Info("Periodic health check completed")
		}
		
		cancel()
	}
}

func (d *SimpleMonitoringDemo) demonstrateFeatures() {
	features := []struct {
		name        string
		description string
		duration    time.Duration
		action      func()
	}{
		{
			name:        "Prometheus Metrics Collection",
			description: "Generating various metrics for AI Gateway components",
			duration:    30 * time.Second,
			action: func() {
				d.logger.Info("📊 Generating Prometheus metrics for all components...")
				
				// Generate a burst of metrics
				for i := 0; i < 50; i++ {
					d.prometheus.RecordPolicyEvaluation("rate_limit", "allow", time.Duration(10+i)*time.Millisecond, i%3 == 0)
					d.prometheus.RecordRateLimitCheck(fmt.Sprintf("user%d", i%5), "org1", "/v1/completions", "per_second", "allowed", time.Duration(2+i%5)*time.Millisecond, float64(i%100))
					d.prometheus.RecordCacheOperation("result", "set", "miss", time.Duration(1+i%3)*time.Millisecond)
				}
				
				d.logger.Info("Generated 150 metrics across policy, rate limiting, and caching components")
			},
		},
		{
			name:        "Health Check Demonstration",
			description: "Performing comprehensive health checks",
			duration:    15 * time.Second,
			action: func() {
				d.logger.Info("❤️ Performing comprehensive health check...")
				
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
			name:        "Component Health Analysis",
			description: "Analyzing individual component health",
			duration:    10 * time.Second,
			action: func() {
				d.logger.Info("🔍 Analyzing component health details...")
				
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				
				health, err := d.healthChecker.CheckHealth(ctx)
				if err == nil {
					for name, comp := range health.Components {
						d.logger.WithFields(logrus.Fields{
							"component":     name,
							"status":        comp.Status,
							"health_score":  comp.HealthScore,
							"response_time": comp.ResponseTime,
						}).Info("Component analysis")
					}
				}
			},
		},
	}

	for _, feature := range features {
		d.logger.WithFields(logrus.Fields{
			"feature":     feature.name,
			"description": feature.description,
			"duration":    feature.duration,
		}).Info("Starting feature demonstration")

		feature.action()
		time.Sleep(feature.duration)

		d.logger.WithField("feature", feature.name).Info("Feature demonstration completed")
		time.Sleep(5 * time.Second)
	}
}

func (d *SimpleMonitoringDemo) logHealthSummary(health *monitoring.SystemHealth) {
	d.logger.WithFields(logrus.Fields{
		"overall_status":       health.Status,
		"overall_score":        health.Summary.OverallScore,
		"healthy_components":   health.Summary.HealthyComponents,
		"total_components":     health.Summary.TotalComponents,
		"uptime":              health.Uptime,
		"memory_usage_mb":      float64(health.System.MemoryUsage) / 1024 / 1024,
		"goroutines":          health.System.GoroutineCount,
	}).Info("📋 Health Check Summary")

	// Log component details
	for name, comp := range health.Components {
		d.logger.WithFields(logrus.Fields{
			"component":     name,
			"status":        comp.Status,
			"health_score":  comp.HealthScore,
			"response_time": comp.ResponseTime,
		}).Info("Component health detail")
	}
}

// HTTP Handlers

func (d *SimpleMonitoringDemo) demoStatusHandler(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	status := map[string]interface{}{
		"demo_name":        "AI Gateway Monitoring Demo (Simplified)",
		"version":          "1.0.0",
		"status":           "running",
		"components":       []string{"prometheus", "health_checker"},
		"prometheus_port":  9090,
		"health_port":      8080,
		"total_requests":   d.requestCount,
		"total_errors":     d.errorCount,
		"error_rate":      float64(d.errorCount) / float64(max(d.requestCount, 1)) * 100,
		"endpoints": map[string]string{
			"prometheus": "http://localhost:9090/metrics",
			"health":     "http://localhost:8080/health",
			"readiness":  "http://localhost:8080/health/ready",
			"liveness":   "http://localhost:8080/health/live",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (d *SimpleMonitoringDemo) triggerMetricsHandler(w http.ResponseWriter, r *http.Request) {
	// Generate a burst of metrics for demonstration
	for i := 0; i < 10; i++ {
		d.prometheus.RecordPolicyEvaluation("demo", "allow", time.Duration(10+i)*time.Millisecond, i%2 == 0)
		d.prometheus.RecordHTTPRequest("GET", "/demo/trigger-metrics", "200", time.Duration(50+i)*time.Millisecond)
	}

	d.mu.Lock()
	d.requestCount += 10
	d.mu.Unlock()

	response := map[string]interface{}{
		"message":         "Generated 10 sample metrics",
		"metrics_types":   []string{"policy_evaluation", "http_requests"},
		"prometheus_url":  "http://localhost:9090/metrics",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (d *SimpleMonitoringDemo) handleShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	d.logger.Info("Monitoring demo running... Press Ctrl+C to stop")
	<-c

	d.logger.Info("Shutting down monitoring demo...")
	d.logger.Info("Monitoring demo shutdown complete")
}

// Utility functions

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
} 