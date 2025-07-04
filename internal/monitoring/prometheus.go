package monitoring

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// PrometheusCollector manages all Prometheus metrics for the AI Gateway
type PrometheusCollector struct {
	// Core metrics
	registry *prometheus.Registry
	logger   *logrus.Logger
	
	// Policy Engine Metrics
	policyEvaluationDuration *prometheus.HistogramVec
	policyEvaluationTotal    *prometheus.CounterVec
	policyEvaluationErrors   *prometheus.CounterVec
	policyCacheHits          *prometheus.CounterVec
	policyP95Latency         *prometheus.GaugeVec
	policyThroughput         *prometheus.GaugeVec
	
	// Rate Limiting Metrics
	rateLimitChecks          *prometheus.CounterVec
	rateLimitViolations      *prometheus.CounterVec
	rateLimitLatency         *prometheus.HistogramVec
	rateLimitWindowUsage     *prometheus.GaugeVec
	rateLimitActiveWindows   *prometheus.GaugeVec
	
	// Caching Metrics
	cacheOperations          *prometheus.CounterVec
	cacheHitRate             *prometheus.GaugeVec
	cacheSize                *prometheus.GaugeVec
	cacheLatency             *prometheus.HistogramVec
	cacheCompressionRatio    *prometheus.GaugeVec
	
	// Provider Metrics
	providerRequests         *prometheus.CounterVec
	providerLatency          *prometheus.HistogramVec
	providerErrors           *prometheus.CounterVec
	providerTokenUsage       *prometheus.CounterVec
	providerRateLimit        *prometheus.GaugeVec
	
	// Alert Metrics
	alertsTotal              *prometheus.CounterVec
	alertsActive             *prometheus.GaugeVec
	alertNotifications       *prometheus.CounterVec
	alertProcessingLatency   *prometheus.HistogramVec
	
	// Audit Metrics
	auditEvents              *prometheus.CounterVec
	auditStorageSize         *prometheus.GaugeVec
	auditProcessingLatency   *prometheus.HistogramVec
	
	// System Metrics
	systemUptime             *prometheus.GaugeVec
	systemMemoryUsage        *prometheus.GaugeVec
	systemGoroutines         *prometheus.GaugeVec
	systemCPUUsage           *prometheus.GaugeVec
	httpRequestDuration      *prometheus.HistogramVec
	httpRequestsTotal        *prometheus.CounterVec
	
	// Health Metrics
	componentHealth          *prometheus.GaugeVec
	dependencyHealth         *prometheus.GaugeVec
	healthCheckDuration      *prometheus.HistogramVec
	
	// Configuration
	config     *PrometheusConfig
	startTime  time.Time
	mu         sync.RWMutex
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	// Server configuration
	MetricsPort     int           `json:"metrics_port" yaml:"metrics_port"`
	MetricsPath     string        `json:"metrics_path" yaml:"metrics_path"`
	EnableMetrics   bool          `json:"enable_metrics" yaml:"enable_metrics"`
	
	// Collection settings
	CollectionInterval time.Duration `json:"collection_interval" yaml:"collection_interval"`
	EnableSystemMetrics bool         `json:"enable_system_metrics" yaml:"enable_system_metrics"`
	
	// Labels
	ServiceName     string `json:"service_name" yaml:"service_name"`
	ServiceVersion  string `json:"service_version" yaml:"service_version"`
	Environment     string `json:"environment" yaml:"environment"`
	
	// Advanced options
	EnableHistograms bool     `json:"enable_histograms" yaml:"enable_histograms"`
	HistogramBuckets []float64 `json:"histogram_buckets" yaml:"histogram_buckets"`
	MaxMetricAge     time.Duration `json:"max_metric_age" yaml:"max_metric_age"`
}

// NewPrometheusCollector creates a new Prometheus metrics collector
func NewPrometheusCollector(config *PrometheusConfig, logger *logrus.Logger) (*PrometheusCollector, error) {
	if config == nil {
		config = getDefaultPrometheusConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	// Create custom registry
	registry := prometheus.NewRegistry()
	
	collector := &PrometheusCollector{
		registry:  registry,
		logger:    logger,
		config:    config,
		startTime: time.Now(),
	}
	
	// Initialize all metrics
	if err := collector.initializeMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}
	
	// Register with Prometheus
	if err := collector.registerMetrics(); err != nil {
		return nil, fmt.Errorf("failed to register metrics: %w", err)
	}
	
	logger.WithFields(logrus.Fields{
		"service":     config.ServiceName,
		"version":     config.ServiceVersion,
		"environment": config.Environment,
		"port":        config.MetricsPort,
		"path":        config.MetricsPath,
	}).Info("Prometheus metrics collector initialized")
	
	return collector, nil
}

// initializeMetrics creates all Prometheus metrics
func (pc *PrometheusCollector) initializeMetrics() error {
	commonLabels := []string{"service", "version", "environment"}
	
	// Policy Engine Metrics
	pc.policyEvaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_policy_evaluation_duration_seconds",
			Help:    "Time spent evaluating policies",
			Buckets: pc.config.HistogramBuckets,
		},
		append(commonLabels, "policy_type", "result"),
	)
	
	pc.policyEvaluationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_policy_evaluations_total",
			Help: "Total number of policy evaluations",
		},
		append(commonLabels, "policy_type", "result", "cache_hit"),
	)
	
	pc.policyEvaluationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_policy_evaluation_errors_total",
			Help: "Total number of policy evaluation errors",
		},
		append(commonLabels, "policy_type", "error_type"),
	)
	
	pc.policyCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_policy_cache_hits_total",
			Help: "Total number of policy cache hits",
		},
		append(commonLabels, "cache_type"),
	)
	
	pc.policyP95Latency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_policy_p95_latency_seconds",
			Help: "95th percentile policy evaluation latency",
		},
		commonLabels,
	)
	
	pc.policyThroughput = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_policy_throughput_requests_per_second",
			Help: "Policy evaluation throughput in requests per second",
		},
		commonLabels,
	)
	
	// Rate Limiting Metrics
	pc.rateLimitChecks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_rate_limit_checks_total",
			Help: "Total number of rate limit checks",
		},
		append(commonLabels, "user_id", "org_id", "endpoint", "window", "result"),
	)
	
	pc.rateLimitViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_rate_limit_violations_total",
			Help: "Total number of rate limit violations",
		},
		append(commonLabels, "user_id", "org_id", "endpoint", "window", "violation_type"),
	)
	
	pc.rateLimitLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_rate_limit_check_duration_seconds",
			Help:    "Time spent checking rate limits",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
		},
		append(commonLabels, "window"),
	)
	
	pc.rateLimitWindowUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_rate_limit_window_usage_percent",
			Help: "Current rate limit window usage as percentage",
		},
		append(commonLabels, "user_id", "org_id", "endpoint", "window"),
	)
	
	pc.rateLimitActiveWindows = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_rate_limit_active_windows",
			Help: "Number of active rate limit windows",
		},
		commonLabels,
	)
	
	// Caching Metrics
	pc.cacheOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_cache_operations_total",
			Help: "Total number of cache operations",
		},
		append(commonLabels, "cache_type", "operation", "result"),
	)
	
	pc.cacheHitRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_cache_hit_rate_percent",
			Help: "Cache hit rate percentage",
		},
		append(commonLabels, "cache_type"),
	)
	
	pc.cacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_cache_size_bytes",
			Help: "Current cache size in bytes",
		},
		append(commonLabels, "cache_type"),
	)
	
	pc.cacheLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_cache_operation_duration_seconds",
			Help:    "Time spent on cache operations",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
		},
		append(commonLabels, "cache_type", "operation"),
	)
	
	pc.cacheCompressionRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_cache_compression_ratio",
			Help: "Cache compression ratio",
		},
		append(commonLabels, "cache_type"),
	)
	
	// Provider Metrics
	pc.providerRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_provider_requests_total",
			Help: "Total number of requests to AI providers",
		},
		append(commonLabels, "provider", "model", "endpoint", "status"),
	)
	
	pc.providerLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_provider_request_duration_seconds",
			Help:    "Time spent on provider requests",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0},
		},
		append(commonLabels, "provider", "model", "endpoint"),
	)
	
	pc.providerErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_provider_errors_total",
			Help: "Total number of provider errors",
		},
		append(commonLabels, "provider", "model", "error_type", "status_code"),
	)
	
	pc.providerTokenUsage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_provider_tokens_total",
			Help: "Total number of tokens consumed",
		},
		append(commonLabels, "provider", "model", "token_type"),
	)
	
	pc.providerRateLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_provider_rate_limit_remaining",
			Help: "Remaining rate limit for provider",
		},
		append(commonLabels, "provider", "limit_type"),
	)
	
	// Alert Metrics
	pc.alertsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_alerts_total",
			Help: "Total number of alerts generated",
		},
		append(commonLabels, "alert_type", "severity", "status"),
	)
	
	pc.alertsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_alerts_active",
			Help: "Number of currently active alerts",
		},
		append(commonLabels, "alert_type", "severity"),
	)
	
	pc.alertNotifications = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_alert_notifications_total",
			Help: "Total number of alert notifications sent",
		},
		append(commonLabels, "channel", "status"),
	)
	
	pc.alertProcessingLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_alert_processing_duration_seconds",
			Help:    "Time spent processing alerts",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0},
		},
		append(commonLabels, "alert_type"),
	)
	
	// Audit Metrics
	pc.auditEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_audit_events_total",
			Help: "Total number of audit events",
		},
		append(commonLabels, "event_category", "event_type", "user_id"),
	)
	
	pc.auditStorageSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_audit_storage_size_bytes",
			Help: "Current audit storage size in bytes",
		},
		append(commonLabels, "storage_type"),
	)
	
	pc.auditProcessingLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_audit_processing_duration_seconds",
			Help:    "Time spent processing audit events",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		},
		append(commonLabels, "event_category"),
	)
	
	// System Metrics
	if pc.config.EnableSystemMetrics {
		pc.systemUptime = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ai_gateway_uptime_seconds",
				Help: "System uptime in seconds",
			},
			commonLabels,
		)
		
		pc.systemMemoryUsage = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ai_gateway_memory_usage_bytes",
				Help: "Current memory usage in bytes",
			},
			append(commonLabels, "memory_type"),
		)
		
		pc.systemGoroutines = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ai_gateway_goroutines_count",
				Help: "Number of active goroutines",
			},
			commonLabels,
		)
		
		pc.systemCPUUsage = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "ai_gateway_cpu_usage_percent",
				Help: "CPU usage percentage",
			},
			commonLabels,
		)
	}
	
	// HTTP Metrics
	pc.httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_http_request_duration_seconds",
			Help:    "HTTP request duration",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		append(commonLabels, "method", "endpoint", "status_code"),
	)
	
	pc.httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ai_gateway_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		append(commonLabels, "method", "endpoint", "status_code"),
	)
	
	// Health Metrics
	pc.componentHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_component_health",
			Help: "Component health status (1=healthy, 0=unhealthy)",
		},
		append(commonLabels, "component"),
	)
	
	pc.dependencyHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ai_gateway_dependency_health",
			Help: "Dependency health status (1=healthy, 0=unhealthy)",
		},
		append(commonLabels, "dependency"),
	)
	
	pc.healthCheckDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ai_gateway_health_check_duration_seconds",
			Help:    "Time spent on health checks",
			Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1.0, 5.0},
		},
		append(commonLabels, "component"),
	)
	
	return nil
}

// registerMetrics registers all metrics with Prometheus
func (pc *PrometheusCollector) registerMetrics() error {
	metrics := []prometheus.Collector{
		// Policy metrics
		pc.policyEvaluationDuration,
		pc.policyEvaluationTotal,
		pc.policyEvaluationErrors,
		pc.policyCacheHits,
		pc.policyP95Latency,
		pc.policyThroughput,
		
		// Rate limiting metrics
		pc.rateLimitChecks,
		pc.rateLimitViolations,
		pc.rateLimitLatency,
		pc.rateLimitWindowUsage,
		pc.rateLimitActiveWindows,
		
		// Cache metrics
		pc.cacheOperations,
		pc.cacheHitRate,
		pc.cacheSize,
		pc.cacheLatency,
		pc.cacheCompressionRatio,
		
		// Provider metrics
		pc.providerRequests,
		pc.providerLatency,
		pc.providerErrors,
		pc.providerTokenUsage,
		pc.providerRateLimit,
		
		// Alert metrics
		pc.alertsTotal,
		pc.alertsActive,
		pc.alertNotifications,
		pc.alertProcessingLatency,
		
		// Audit metrics
		pc.auditEvents,
		pc.auditStorageSize,
		pc.auditProcessingLatency,
		
		// HTTP metrics
		pc.httpRequestDuration,
		pc.httpRequestsTotal,
		
		// Health metrics
		pc.componentHealth,
		pc.dependencyHealth,
		pc.healthCheckDuration,
	}
	
	// Add system metrics if enabled
	if pc.config.EnableSystemMetrics {
		metrics = append(metrics,
			pc.systemUptime,
			pc.systemMemoryUsage,
			pc.systemGoroutines,
			pc.systemCPUUsage,
		)
	}
	
	// Register all metrics
	for _, metric := range metrics {
		if err := pc.registry.Register(metric); err != nil {
			return fmt.Errorf("failed to register metric: %w", err)
		}
	}
	
	return nil
}

// Common label values
func (pc *PrometheusCollector) getCommonLabels() prometheus.Labels {
	return prometheus.Labels{
		"service":     pc.config.ServiceName,
		"version":     pc.config.ServiceVersion,
		"environment": pc.config.Environment,
	}
}

// Policy Engine Metrics Methods
func (pc *PrometheusCollector) RecordPolicyEvaluation(policyType, result string, duration time.Duration, cacheHit bool) {
	labels := pc.getCommonLabels()
	labels["policy_type"] = policyType
	labels["result"] = result
	labels["cache_hit"] = fmt.Sprintf("%t", cacheHit)
	
	pc.policyEvaluationDuration.With(labels).Observe(duration.Seconds())
	pc.policyEvaluationTotal.With(labels).Inc()
}

func (pc *PrometheusCollector) RecordPolicyError(policyType, errorType string) {
	labels := pc.getCommonLabels()
	labels["policy_type"] = policyType
	labels["error_type"] = errorType
	
	pc.policyEvaluationErrors.With(labels).Inc()
}

func (pc *PrometheusCollector) UpdatePolicyMetrics(p95Latency time.Duration, throughput float64) {
	labels := pc.getCommonLabels()
	
	pc.policyP95Latency.With(labels).Set(p95Latency.Seconds())
	pc.policyThroughput.With(labels).Set(throughput)
}

// Rate Limiting Metrics Methods
func (pc *PrometheusCollector) RecordRateLimitCheck(userID, orgID, endpoint, window, result string, duration time.Duration, windowUsage float64) {
	labels := pc.getCommonLabels()
	labels["user_id"] = userID
	labels["org_id"] = orgID
	labels["endpoint"] = endpoint
	labels["window"] = window
	labels["result"] = result
	
	pc.rateLimitChecks.With(labels).Inc()
	pc.rateLimitLatency.With(prometheus.Labels{
		"service":     pc.config.ServiceName,
		"version":     pc.config.ServiceVersion,
		"environment": pc.config.Environment,
		"window":      window,
	}).Observe(duration.Seconds())
	
	pc.rateLimitWindowUsage.With(labels).Set(windowUsage)
}

func (pc *PrometheusCollector) RecordRateLimitViolation(userID, orgID, endpoint, window, violationType string) {
	labels := pc.getCommonLabels()
	labels["user_id"] = userID
	labels["org_id"] = orgID
	labels["endpoint"] = endpoint
	labels["window"] = window
	labels["violation_type"] = violationType
	
	pc.rateLimitViolations.With(labels).Inc()
}

// Cache Metrics Methods
func (pc *PrometheusCollector) RecordCacheOperation(cacheType, operation, result string, duration time.Duration) {
	labels := pc.getCommonLabels()
	labels["cache_type"] = cacheType
	labels["operation"] = operation
	labels["result"] = result
	
	pc.cacheOperations.With(labels).Inc()
	
	latencyLabels := pc.getCommonLabels()
	latencyLabels["cache_type"] = cacheType
	latencyLabels["operation"] = operation
	
	pc.cacheLatency.With(latencyLabels).Observe(duration.Seconds())
}

func (pc *PrometheusCollector) UpdateCacheMetrics(cacheType string, hitRate float64, sizeBytes int64, compressionRatio float64) {
	labels := pc.getCommonLabels()
	labels["cache_type"] = cacheType
	
	pc.cacheHitRate.With(labels).Set(hitRate)
	pc.cacheSize.With(labels).Set(float64(sizeBytes))
	pc.cacheCompressionRatio.With(labels).Set(compressionRatio)
}

// Provider Metrics Methods
func (pc *PrometheusCollector) RecordProviderRequest(provider, model, endpoint, status string, duration time.Duration) {
	labels := pc.getCommonLabels()
	labels["provider"] = provider
	labels["model"] = model
	labels["endpoint"] = endpoint
	labels["status"] = status
	
	pc.providerRequests.With(labels).Inc()
	
	latencyLabels := pc.getCommonLabels()
	latencyLabels["provider"] = provider
	latencyLabels["model"] = model
	latencyLabels["endpoint"] = endpoint
	
	pc.providerLatency.With(latencyLabels).Observe(duration.Seconds())
}

func (pc *PrometheusCollector) RecordProviderError(provider, model, errorType, statusCode string) {
	labels := pc.getCommonLabels()
	labels["provider"] = provider
	labels["model"] = model
	labels["error_type"] = errorType
	labels["status_code"] = statusCode
	
	pc.providerErrors.With(labels).Inc()
}

func (pc *PrometheusCollector) RecordProviderTokenUsage(provider, model, tokenType string, count int64) {
	labels := pc.getCommonLabels()
	labels["provider"] = provider
	labels["model"] = model
	labels["token_type"] = tokenType
	
	pc.providerTokenUsage.With(labels).Add(float64(count))
}

// Health Metrics Methods
func (pc *PrometheusCollector) UpdateComponentHealth(component string, healthy bool) {
	labels := pc.getCommonLabels()
	labels["component"] = component
	
	var value float64
	if healthy {
		value = 1
	}
	
	pc.componentHealth.With(labels).Set(value)
}

func (pc *PrometheusCollector) UpdateDependencyHealth(dependency string, healthy bool) {
	labels := pc.getCommonLabels()
	labels["dependency"] = dependency
	
	var value float64
	if healthy {
		value = 1
	}
	
	pc.dependencyHealth.With(labels).Set(value)
}

func (pc *PrometheusCollector) RecordHealthCheckDuration(component string, duration time.Duration) {
	labels := pc.getCommonLabels()
	labels["component"] = component
	
	pc.healthCheckDuration.With(labels).Observe(duration.Seconds())
}

// HTTP Metrics Methods
func (pc *PrometheusCollector) RecordHTTPRequest(method, endpoint, statusCode string, duration time.Duration) {
	labels := pc.getCommonLabels()
	labels["method"] = method
	labels["endpoint"] = endpoint
	labels["status_code"] = statusCode
	
	pc.httpRequestsTotal.With(labels).Inc()
	pc.httpRequestDuration.With(labels).Observe(duration.Seconds())
}

// StartMetricsServer starts the Prometheus metrics HTTP server
func (pc *PrometheusCollector) StartMetricsServer() error {
	if !pc.config.EnableMetrics {
		pc.logger.Info("Prometheus metrics disabled")
		return nil
	}
	
	handler := promhttp.HandlerFor(pc.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	
	http.Handle(pc.config.MetricsPath, handler)
	
	addr := fmt.Sprintf(":%d", pc.config.MetricsPort)
	pc.logger.WithFields(logrus.Fields{
		"addr": addr,
		"path": pc.config.MetricsPath,
	}).Info("Starting Prometheus metrics server")
	
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			pc.logger.WithError(err).Error("Prometheus metrics server failed")
		}
	}()
	
	return nil
}

// GetHandler returns the Prometheus metrics handler
func (pc *PrometheusCollector) GetHandler() http.Handler {
	return promhttp.HandlerFor(pc.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// getDefaultPrometheusConfig returns default Prometheus configuration
func getDefaultPrometheusConfig() *PrometheusConfig {
	return &PrometheusConfig{
		MetricsPort:         9090,
		MetricsPath:         "/metrics",
		EnableMetrics:       true,
		CollectionInterval:  30 * time.Second,
		EnableSystemMetrics: true,
		ServiceName:         "ai-gateway",
		ServiceVersion:      "1.0.0",
		Environment:         "development",
		EnableHistograms:    true,
		HistogramBuckets:    []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		MaxMetricAge:        24 * time.Hour,
	}
} 