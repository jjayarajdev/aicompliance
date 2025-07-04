package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
	"math/rand"

	"github.com/gorilla/mux"
)

// Dashboard API Handlers

// GatewayStats represents dashboard statistics
type GatewayStats struct {
	ActivePolicies struct {
		Count         int    `json:"count"`
		ChangePercent int    `json:"changePercent"`
		Trend         string `json:"trend"`
	} `json:"activePolicies"`
	APIRequests struct {
		Count         int    `json:"count"`
		ChangePercent int    `json:"changePercent"`
		Trend         string `json:"trend"`
		Period        string `json:"period"`
	} `json:"apiRequests"`
	RateLimitViolations struct {
		Count         int    `json:"count"`
		ChangePercent int    `json:"changePercent"`
		Trend         string `json:"trend"`
	} `json:"rateLimitViolations"`
	SystemHealth struct {
		Percentage float64 `json:"percentage"`
		Status     string  `json:"status"`
		Uptime     string  `json:"uptime"`
	} `json:"systemHealth"`
}

// SystemOverview represents system status overview
type SystemOverview struct {
	PolicyEngine struct {
		Performance  int    `json:"performance"`
		Status       string `json:"status"`
		ResponseTime int    `json:"responseTime"`
	} `json:"policyEngine"`
	CacheHitRate struct {
		Percentage int    `json:"percentage"`
		Trend      string `json:"trend"`
	} `json:"cacheHitRate"`
	RateLimitUtilization struct {
		Percentage int    `json:"percentage"`
		Trend      string `json:"trend"`
	} `json:"rateLimitUtilization"`
	ProviderHealth struct {
		Percentage int `json:"percentage"`
		Providers  []struct {
			Name         string `json:"name"`
			Status       string `json:"status"`
			ResponseTime int    `json:"responseTime"`
		} `json:"providers"`
	} `json:"providerHealth"`
}

// RecentActivity represents recent system activity
type RecentActivity struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Timestamp   string `json:"timestamp"`
	User        string `json:"user,omitempty"`
	Resolved    bool   `json:"resolved,omitempty"`
}

// MetricsData represents time-series metrics
type MetricsData struct {
	Timestamp    string `json:"timestamp"`
	Requests     int    `json:"requests"`
	Violations   int    `json:"violations"`
	ResponseTime int    `json:"responseTime"`
	CacheHits    int    `json:"cacheHits"`
}

// getDashboardStatsHandler returns dashboard statistics
func (s *Server) getDashboardStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := GatewayStats{
		ActivePolicies: struct {
			Count         int    `json:"count"`
			ChangePercent int    `json:"changePercent"`
			Trend         string `json:"trend"`
		}{
			Count:         24,
			ChangePercent: 12,
			Trend:         "up",
		},
		APIRequests: struct {
			Count         int    `json:"count"`
			ChangePercent int    `json:"changePercent"`
			Trend         string `json:"trend"`
			Period        string `json:"period"`
		}{
			Count:         1200000 + rand.Intn(100000),
			ChangePercent: 15 + rand.Intn(20),
			Trend:         "up",
			Period:        "24h",
		},
		RateLimitViolations: struct {
			Count         int    `json:"count"`
			ChangePercent int    `json:"changePercent"`
			Trend         string `json:"trend"`
		}{
			Count:         15 + rand.Intn(10),
			ChangePercent: -8 + rand.Intn(5),
			Trend:         "down",
		},
		SystemHealth: struct {
			Percentage float64 `json:"percentage"`
			Status     string  `json:"status"`
			Uptime     string  `json:"uptime"`
		}{
			Percentage: 99.9,
			Status:     "healthy",
			Uptime:     "99.9%",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// getSystemOverviewHandler returns system overview data
func (s *Server) getSystemOverviewHandler(w http.ResponseWriter, r *http.Request) {
	overview := SystemOverview{
		PolicyEngine: struct {
			Performance  int    `json:"performance"`
			Status       string `json:"status"`
			ResponseTime int    `json:"responseTime"`
		}{
			Performance:  85 + rand.Intn(15),
			Status:       "optimal",
			ResponseTime: 35 + rand.Intn(20),
		},
		CacheHitRate: struct {
			Percentage int    `json:"percentage"`
			Trend      string `json:"trend"`
		}{
			Percentage: 80 + rand.Intn(15),
			Trend:      "up",
		},
		RateLimitUtilization: struct {
			Percentage int    `json:"percentage"`
			Trend      string `json:"trend"`
		}{
			Percentage: 60 + rand.Intn(20),
			Trend:      "stable",
		},
		ProviderHealth: struct {
			Percentage int `json:"percentage"`
			Providers  []struct {
				Name         string `json:"name"`
				Status       string `json:"status"`
				ResponseTime int    `json:"responseTime"`
			} `json:"providers"`
		}{
			Percentage: 98,
			Providers: []struct {
				Name         string `json:"name"`
				Status       string `json:"status"`
				ResponseTime int    `json:"responseTime"`
			}{
				{Name: "OpenAI", Status: "healthy", ResponseTime: 120 + rand.Intn(50)},
				{Name: "Anthropic", Status: "healthy", ResponseTime: 95 + rand.Intn(30)},
				{Name: "Azure OpenAI", Status: "degraded", ResponseTime: 250 + rand.Intn(100)},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(overview)
}

// getRecentActivityHandler returns recent system activity
func (s *Server) getRecentActivityHandler(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	now := time.Now()
	activities := []RecentActivity{
		{
			ID:          "1",
			Type:        "violation",
			Title:       "PII Detection Alert",
			Description: "Sensitive data detected in API request from user@company.com",
			Severity:    "high",
			Timestamp:   now.Add(-5 * time.Minute).Format(time.RFC3339),
			User:        "user@company.com",
			Resolved:    false,
		},
		{
			ID:          "2",
			Type:        "alert",
			Title:       "Rate Limit Exceeded",
			Description: "User exceeded 1000 requests/hour limit",
			Severity:    "medium",
			Timestamp:   now.Add(-15 * time.Minute).Format(time.RFC3339),
			User:        "api-user-123",
			Resolved:    true,
		},
		{
			ID:          "3",
			Type:        "optimization",
			Title:       "Cache Performance Improved",
			Description: "Cache hit rate increased to 85% (+5%)",
			Severity:    "low",
			Timestamp:   now.Add(-30 * time.Minute).Format(time.RFC3339),
			Resolved:    true,
		},
		{
			ID:          "4",
			Type:        "config",
			Title:       "Policy Updated",
			Description: "Updated financial data classification policy",
			Severity:    "low",
			Timestamp:   now.Add(-45 * time.Minute).Format(time.RFC3339),
			User:        "admin@company.com",
			Resolved:    true,
		},
		{
			ID:          "5",
			Type:        "violation",
			Title:       "Unusual Request Pattern",
			Description: "Detected unusual request pattern from IP 192.168.1.100",
			Severity:    "medium",
			Timestamp:   now.Add(-60 * time.Minute).Format(time.RFC3339),
			Resolved:    false,
		},
	}

	if limit < len(activities) {
		activities = activities[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activities)
}

// getMetricsHandler returns time-series metrics data
func (s *Server) getMetricsHandler(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil {
			hours = parsed
		}
	}

	now := time.Now()
	var metrics []MetricsData

	for i := hours - 1; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		metrics = append(metrics, MetricsData{
			Timestamp:    timestamp.Format(time.RFC3339),
			Requests:     2000 + rand.Intn(3000),
			Violations:   1 + rand.Intn(10),
			ResponseTime: 50 + rand.Intn(100),
			CacheHits:    500 + rand.Intn(1000),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Monitoring API Handlers

// SystemMetrics represents system monitoring metrics
type SystemMetrics struct {
	CPU     int `json:"cpu"`
	Memory  int `json:"memory"`
	Disk    int `json:"disk"`
	Network struct {
		BytesIn     int `json:"bytesIn"`
		BytesOut    int `json:"bytesOut"`
		Connections int `json:"connections"`
	} `json:"network"`
	Uptime int `json:"uptime"`
}

// Alert represents system alerts
type Alert struct {
	ID           string `json:"id"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Message      string `json:"message"`
	Timestamp    string `json:"timestamp"`
	Acknowledged bool   `json:"acknowledged"`
	Source       string `json:"source"`
}

// PerformanceMetrics represents performance monitoring data
type PerformanceMetrics struct {
	RequestsPerSecond     float64 `json:"requestsPerSecond"`
	AverageResponseTime   int     `json:"averageResponseTime"`
	ErrorRate             float64 `json:"errorRate"`
	ActiveConnections     int     `json:"activeConnections"`
	CacheHitRate          int     `json:"cacheHitRate"`
}

// ProviderHealth represents AI provider health status
type ProviderHealth struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	ResponseTime int    `json:"responseTime"`
	ErrorRate    float64 `json:"errorRate"`
	LastCheck    string `json:"lastCheck"`
}

// getSystemMetricsHandler returns system monitoring metrics
func (s *Server) getSystemMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := SystemMetrics{
		CPU:    30 + rand.Intn(40),
		Memory: 50 + rand.Intn(30),
		Disk:   20 + rand.Intn(15),
		Network: struct {
			BytesIn     int `json:"bytesIn"`
			BytesOut    int `json:"bytesOut"`
			Connections int `json:"connections"`
		}{
			BytesIn:     500000 + rand.Intn(500000),
			BytesOut:    300000 + rand.Intn(300000),
			Connections: 100 + rand.Intn(100),
		},
		Uptime: 86400 + rand.Intn(100000),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// getAlertsHandler returns system alerts
func (s *Server) getAlertsHandler(w http.ResponseWriter, r *http.Request) {
	alerts := []Alert{
		{
			ID:           "1",
			Severity:     "warning",
			Title:        "High CPU Usage",
			Message:      "CPU usage is above 80%",
			Timestamp:    time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
			Acknowledged: false,
			Source:       "system",
		},
		{
			ID:           "2",
			Severity:     "info",
			Title:        "Cache Hit Rate Improved",
			Message:      "Cache hit rate has improved to 90%",
			Timestamp:    time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
			Acknowledged: true,
			Source:       "cache",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

// getPerformanceMetricsHandler returns performance metrics
func (s *Server) getPerformanceMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := PerformanceMetrics{
		RequestsPerSecond:   120 + rand.Float64()*80,
		AverageResponseTime: 35 + rand.Intn(30),
		ErrorRate:           0.1 + rand.Float64()*0.9,
		ActiveConnections:   200 + rand.Intn(100),
		CacheHitRate:        80 + rand.Intn(15),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// getProviderHealthHandler returns AI provider health status
func (s *Server) getProviderHealthHandler(w http.ResponseWriter, r *http.Request) {
	providers := []ProviderHealth{
		{
			Name:         "OpenAI",
			Status:       "healthy",
			ResponseTime: 100 + rand.Intn(50),
			ErrorRate:    0.05 + rand.Float64()*0.1,
			LastCheck:    time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
		},
		{
			Name:         "Anthropic",
			Status:       "healthy",
			ResponseTime: 80 + rand.Intn(40),
			ErrorRate:    0.02 + rand.Float64()*0.08,
			LastCheck:    time.Now().Add(-2 * time.Minute).Format(time.RFC3339),
		},
		{
			Name:         "Azure OpenAI",
			Status:       "degraded",
			ResponseTime: 200 + rand.Intn(100),
			ErrorRate:    0.15 + rand.Float64()*0.1,
			LastCheck:    time.Now().Add(-30 * time.Second).Format(time.RFC3339),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(providers)
}

// Policy API Handlers

// Policy represents an AI Gateway policy
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	Priority    string `json:"priority"`
	Conditions  []struct {
		ID       string `json:"id"`
		Field    string `json:"field"`
		Operator string `json:"operator"`
		Value    string `json:"value"`
	} `json:"conditions"`
	Actions []struct {
		ID         string                 `json:"id"`
		Type       string                 `json:"type"`
		Parameters map[string]interface{} `json:"parameters"`
	} `json:"actions"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
	Version   string   `json:"version"`
	Tags      []string `json:"tags"`
	Enabled   bool     `json:"enabled"`
}

// getPoliciesHandler returns all policies
func (s *Server) getPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies := []Policy{
		{
			ID:          "1",
			Name:        "PII Detection Policy",
			Description: "Detect and block requests containing personally identifiable information",
			Type:        "security",
			Status:      "active",
			Priority:    "high",
			Conditions: []struct {
				ID       string `json:"id"`
				Field    string `json:"field"`
				Operator string `json:"operator"`
				Value    string `json:"value"`
			}{
				{ID: "1", Field: "content", Operator: "contains", Value: "ssn|credit_card|email"},
			},
			Actions: []struct {
				ID         string                 `json:"id"`
				Type       string                 `json:"type"`
				Parameters map[string]interface{} `json:"parameters"`
			}{
				{ID: "1", Type: "deny", Parameters: map[string]interface{}{"reason": "PII detected"}},
			},
			CreatedAt: "2024-01-01T00:00:00Z",
			UpdatedAt: "2024-01-15T00:00:00Z",
			Version:   "1.0.0",
			Tags:      []string{"security", "pii", "compliance"},
			Enabled:   true,
		},
		{
			ID:          "2",
			Name:        "Rate Limiting Policy",
			Description: "Enforce rate limits for API requests per user",
			Type:        "performance",
			Status:      "active",
			Priority:    "medium",
			Conditions: []struct {
				ID       string `json:"id"`
				Field    string `json:"field"`
				Operator string `json:"operator"`
				Value    string `json:"value"`
			}{
				{ID: "2", Field: "user_id", Operator: "exists", Value: ""},
			},
			Actions: []struct {
				ID         string                 `json:"id"`
				Type       string                 `json:"type"`
				Parameters map[string]interface{} `json:"parameters"`
			}{
				{ID: "2", Type: "log", Parameters: map[string]interface{}{"level": "info"}},
			},
			CreatedAt: "2024-01-02T00:00:00Z",
			UpdatedAt: "2024-01-10T00:00:00Z",
			Version:   "1.0.0",
			Tags:      []string{"performance", "rate-limiting"},
			Enabled:   true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

// createPolicyHandler creates a new policy
func (s *Server) createPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var policy Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Generate ID and timestamps
	policy.ID = fmt.Sprintf("policy_%d", time.Now().Unix())
	policy.CreatedAt = time.Now().Format(time.RFC3339)
	policy.UpdatedAt = time.Now().Format(time.RFC3339)
	policy.Version = "1.0.0"

	s.logger.WithFields(map[string]interface{}{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
		"policy_type": policy.Type,
	}).Info("Policy created")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

// updatePolicyHandler updates an existing policy
func (s *Server) updatePolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	var policy Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	policy.ID = policyID
	policy.UpdatedAt = time.Now().Format(time.RFC3339)

	s.logger.WithFields(map[string]interface{}{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
	}).Info("Policy updated")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// deletePolicyHandler deletes a policy
func (s *Server) deletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	s.logger.WithFields(map[string]interface{}{
		"policy_id": policyID,
	}).Info("Policy deleted")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Policy deleted successfully"})
}

// Analytics API Handlers

// AnalyticsData represents analytics overview data
type AnalyticsData struct {
	Period              string  `json:"period"`
	TotalRequests       int     `json:"totalRequests"`
	SuccessfulRequests  int     `json:"successfulRequests"`
	FailedRequests      int     `json:"failedRequests"`
	AverageResponseTime int     `json:"averageResponseTime"`
	TotalTokens         int     `json:"totalTokens"`
	Cost                float64 `json:"cost"`
	CacheHitRate        int     `json:"cacheHitRate"`
	PolicyViolations    int     `json:"policyViolations"`
	UniqueUsers         int     `json:"uniqueUsers"`
}

// getAnalyticsHandler returns analytics data
func (s *Server) getAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Range string `json:"range"`
	}
	json.NewDecoder(r.Body).Decode(&request)

	analytics := AnalyticsData{
		Period:              request.Range,
		TotalRequests:       45000 + rand.Intn(10000),
		SuccessfulRequests:  43500 + rand.Intn(1000),
		FailedRequests:      1500 + rand.Intn(500),
		AverageResponseTime: 100 + rand.Intn(50),
		TotalTokens:         2000000 + rand.Intn(500000),
		Cost:                100.50 + rand.Float64()*50,
		CacheHitRate:        80 + rand.Intn(15),
		PolicyViolations:    20 + rand.Intn(10),
		UniqueUsers:         1000 + rand.Intn(250),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analytics)
}

// Settings API Handlers

// SystemSettings represents system configuration
type SystemSettings struct {
	Environment          string `json:"environment"`
	DebugMode           bool   `json:"debugMode"`
	LogLevel            string `json:"logLevel"`
	MaintenanceMode     bool   `json:"maintenanceMode"`
	MaxConcurrentRequests int   `json:"maxConcurrentRequests"`
	RequestTimeout      int    `json:"requestTimeout"`
	RateLimitEnabled    bool   `json:"rateLimitEnabled"`
	RateLimitRequests   int    `json:"rateLimitRequests"`
	RateLimitWindow     int    `json:"rateLimitWindow"`
}

// getSystemSettingsHandler returns system settings
func (s *Server) getSystemSettingsHandler(w http.ResponseWriter, r *http.Request) {
	settings := SystemSettings{
		Environment:          s.config.Environment,
		DebugMode:           s.config.Logging.Level == "debug",
		LogLevel:            s.config.Logging.Level,
		MaintenanceMode:     false,
		MaxConcurrentRequests: 1000,
		RequestTimeout:      30000,
		RateLimitEnabled:    true,
		RateLimitRequests:   100,
		RateLimitWindow:     60,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// updateSystemSettingsHandler updates system settings
func (s *Server) updateSystemSettingsHandler(w http.ResponseWriter, r *http.Request) {
	var settings SystemSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"environment":     settings.Environment,
		"debug_mode":      settings.DebugMode,
		"maintenance":     settings.MaintenanceMode,
	}).Info("System settings updated")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Settings updated successfully"})
} 