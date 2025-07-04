package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-API-Key, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Health check handler
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"service":   "ai-gateway-poc",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// Dashboard stats handler
func dashboardStatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"activePolicies": map[string]interface{}{
			"count":         24,
			"changePercent": 12,
			"trend":         "up",
		},
		"apiRequests": map[string]interface{}{
			"count":         1200000 + rand.Intn(100000),
			"changePercent": 15 + rand.Intn(20),
			"trend":         "up",
			"period":        "24h",
		},
		"rateLimitViolations": map[string]interface{}{
			"count":         15 + rand.Intn(10),
			"changePercent": -8 + rand.Intn(5),
			"trend":         "down",
		},
		"systemHealth": map[string]interface{}{
			"percentage": 99.9,
			"status":     "healthy",
			"uptime":     "99.9%",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// System overview handler
func systemOverviewHandler(w http.ResponseWriter, r *http.Request) {
	overview := map[string]interface{}{
		"policyEngine": map[string]interface{}{
			"performance":  85 + rand.Intn(15),
			"status":       "optimal",
			"responseTime": 35 + rand.Intn(20),
		},
		"cacheHitRate": map[string]interface{}{
			"percentage": 80 + rand.Intn(15),
			"trend":      "up",
		},
		"rateLimitUtilization": map[string]interface{}{
			"percentage": 60 + rand.Intn(20),
			"trend":      "stable",
		},
		"providerHealth": map[string]interface{}{
			"percentage": 98,
			"providers": []map[string]interface{}{
				{"name": "OpenAI", "status": "healthy", "responseTime": 120 + rand.Intn(50)},
				{"name": "Anthropic", "status": "healthy", "responseTime": 95 + rand.Intn(30)},
				{"name": "Azure OpenAI", "status": "degraded", "responseTime": 250 + rand.Intn(100)},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(overview)
}

// Recent activity handler
func recentActivityHandler(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	now := time.Now()
	activities := []map[string]interface{}{
		{
			"id":          "1",
			"type":        "violation",
			"title":       "PII Detection Alert",
			"description": "Sensitive data detected in API request from user@company.com",
			"severity":    "high",
			"timestamp":   now.Add(-5 * time.Minute).Format(time.RFC3339),
			"user":        "user@company.com",
			"resolved":    false,
		},
		{
			"id":          "2",
			"type":        "alert",
			"title":       "Rate Limit Exceeded",
			"description": "User exceeded 1000 requests/hour limit",
			"severity":    "medium",
			"timestamp":   now.Add(-15 * time.Minute).Format(time.RFC3339),
			"user":        "api-user-123",
			"resolved":    true,
		},
		{
			"id":          "3",
			"type":        "optimization",
			"title":       "Cache Performance Improved",
			"description": "Cache hit rate increased to 85% (+5%)",
			"severity":    "low",
			"timestamp":   now.Add(-30 * time.Minute).Format(time.RFC3339),
			"resolved":    true,
		},
		{
			"id":          "4",
			"type":        "config",
			"title":       "Policy Updated",
			"description": "Updated financial data classification policy",
			"severity":    "low",
			"timestamp":   now.Add(-45 * time.Minute).Format(time.RFC3339),
			"user":        "admin@company.com",
			"resolved":    true,
		},
		{
			"id":          "5",
			"type":        "violation",
			"title":       "Unusual Request Pattern",
			"description": "Detected unusual request pattern from IP 192.168.1.100",
			"severity":    "medium",
			"timestamp":   now.Add(-60 * time.Minute).Format(time.RFC3339),
			"resolved":    false,
		},
	}

	if limit < len(activities) {
		activities = activities[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activities)
}

// Metrics handler
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if parsed, err := strconv.Atoi(h); err == nil {
			hours = parsed
		}
	}

	now := time.Now()
	var metrics []map[string]interface{}

	for i := hours - 1; i >= 0; i-- {
		timestamp := now.Add(-time.Duration(i) * time.Hour)
		metrics = append(metrics, map[string]interface{}{
			"timestamp":    timestamp.Format(time.RFC3339),
			"requests":     2000 + rand.Intn(3000),
			"violations":   1 + rand.Intn(10),
			"responseTime": 50 + rand.Intn(100),
			"cacheHits":    500 + rand.Intn(1000),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// System metrics handler
func systemMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := map[string]interface{}{
		"cpu":    30 + rand.Intn(40),
		"memory": 50 + rand.Intn(30),
		"disk":   20 + rand.Intn(15),
		"network": map[string]interface{}{
			"bytesIn":     500000 + rand.Intn(500000),
			"bytesOut":    300000 + rand.Intn(300000),
			"connections": 100 + rand.Intn(100),
		},
		"uptime": 86400 + rand.Intn(100000),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Policies handler
func policiesHandler(w http.ResponseWriter, r *http.Request) {
	policies := []map[string]interface{}{
		{
			"id":          "1",
			"name":        "PII Detection Policy",
			"description": "Detect and block requests containing personally identifiable information",
			"type":        "security",
			"status":      "active",
			"priority":    "high",
			"conditions": []map[string]interface{}{
				{"id": "1", "field": "content", "operator": "contains", "value": "ssn|credit_card|email"},
			},
			"actions": []map[string]interface{}{
				{"id": "1", "type": "deny", "parameters": map[string]interface{}{"reason": "PII detected"}},
			},
			"createdAt": "2024-01-01T00:00:00Z",
			"updatedAt": "2024-01-15T00:00:00Z",
			"version":   "1.0.0",
			"tags":      []string{"security", "pii", "compliance"},
			"enabled":   true,
		},
		{
			"id":          "2",
			"name":        "Rate Limiting Policy",
			"description": "Enforce rate limits for API requests per user",
			"type":        "performance",
			"status":      "active",
			"priority":    "medium",
			"conditions": []map[string]interface{}{
				{"id": "2", "field": "user_id", "operator": "exists", "value": ""},
			},
			"actions": []map[string]interface{}{
				{"id": "2", "type": "log", "parameters": map[string]interface{}{"level": "info"}},
			},
			"createdAt": "2024-01-02T00:00:00Z",
			"updatedAt": "2024-01-10T00:00:00Z",
			"version":   "1.0.0",
			"tags":      []string{"performance", "rate-limiting"},
			"enabled":   true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func main() {
	router := mux.NewRouter()

	// Apply CORS middleware
	router.Use(corsMiddleware)

	// API v1 routes
	api := router.PathPrefix("/api/v1").Subrouter()

	// Health endpoints
	api.HandleFunc("/health", healthHandler).Methods("GET")
	router.HandleFunc("/health", healthHandler).Methods("GET") // Also root level

	// Dashboard API routes
	api.HandleFunc("/dashboard/stats", dashboardStatsHandler).Methods("GET")
	api.HandleFunc("/dashboard/overview", systemOverviewHandler).Methods("GET")
	api.HandleFunc("/dashboard/activity", recentActivityHandler).Methods("GET")
	api.HandleFunc("/dashboard/metrics", metricsHandler).Methods("GET")

	// Monitoring API routes
	api.HandleFunc("/monitoring/system", systemMetricsHandler).Methods("GET")

	// Policy API routes
	api.HandleFunc("/policies", policiesHandler).Methods("GET")

	fmt.Println("🚀 AI Gateway server starting on http://localhost:8080")
	fmt.Println("📊 Dashboard available at http://localhost:3000")
	fmt.Println("🔍 Health check: http://localhost:8080/health")
	fmt.Println("📈 API endpoints:")
	fmt.Println("  GET /api/v1/dashboard/stats")
	fmt.Println("  GET /api/v1/dashboard/overview")
	fmt.Println("  GET /api/v1/dashboard/activity")
	fmt.Println("  GET /api/v1/dashboard/metrics")
	fmt.Println("  GET /api/v1/monitoring/system")
	fmt.Println("  GET /api/v1/policies")

	log.Fatal(http.ListenAndServe(":8080", router))
} 