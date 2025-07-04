package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ai-gateway-poc/internal/monitoring"
)

func main() {
	fmt.Println("🔍 AI Gateway - Comprehensive Audit Logging System Demo")
	fmt.Println(strings.Repeat("=", 60))

	// Clean up previous demo files
	os.RemoveAll("./demo_audit_logs")

	// Run all demo sections
	if err := runDemo(); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}

	fmt.Println("\n✅ Demo completed successfully!")
	fmt.Println("📁 Check './demo_audit_logs' directory for generated audit files")
}

func runDemo() error {
	demos := []struct {
		name string
		fn   func() error
	}{
		{"1. Basic Audit Logger Setup", demoBasicSetup},
		{"2. Request/Response Tracking", demoRequestResponse},
		{"3. Security Event Logging", demoSecurityEvents},
		{"4. Policy & Provider Tracking", demoPolicyProvider},
		{"5. Data Sanitization", demoDataSanitization},
		{"6. Storage & Querying", demoStorageQuerying},
		{"7. Performance Monitoring", demoPerformanceMonitoring},
		{"8. Data Retention & Archival", demoRetentionArchival},
	}

	for _, demo := range demos {
		fmt.Printf("\n📋 %s\n", demo.name)
		fmt.Println(strings.Repeat("-", len(demo.name)+4))
		
		if err := demo.fn(); err != nil {
			return fmt.Errorf("%s failed: %w", demo.name, err)
		}
		
		time.Sleep(time.Millisecond * 500) // Brief pause between demos
	}

	return nil
}

func demoBasicSetup() error {
	fmt.Println("Setting up comprehensive audit logging system...")

	// Create storage configuration
	storageConfig := &monitoring.FileStorageConfig{
		BaseDirectory:    "./demo_audit_logs",
		FilePrefix:       "demo_audit",
		FileExtension:    ".log",
		MaxFileSize:      50 * 1024, // 50KB for demo
		MaxFiles:         10,
		CompressOldFiles: true,
		SyncInterval:     time.Second,
		CreateDirs:       true,
		FilePermissions:  0644,
	}

	// Create audit configuration
	auditConfig := &monitoring.AuditConfig{
		Enabled:           true,
		LogLevel:          "info",
		LogRequests:       true,
		LogResponses:      true,
		LogHeaders:        true,
		LogBody:           true,
		MaxBodySize:       4096,
		SanitizeBody:      true,
		HashSensitiveData: true,
		EnableAsync:       false,
		BufferSize:        1000,
		SampleRate:        1.0,
		PIIPatterns: []string{
			`\d{3}-\d{2}-\d{4}`,     // SSN
			`\d{16}`,                // Credit card
			`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, // Email
		},
		SensitiveHeaders: []string{"Authorization", "Cookie", "X-API-Key"},
		RetentionPolicy: &monitoring.RetentionPolicy{
			DefaultRetention:  30 * 24 * time.Hour,
			ArchiveAfter:      7 * 24 * time.Hour,
			DeleteAfter:       90 * 24 * time.Hour,
			EnableAutoCleanup: true,
			CleanupInterval:   time.Hour,
		},
	}

	// Create storage
	storage, err := monitoring.NewFileAuditStorage(storageConfig)
	if err != nil {
		return fmt.Errorf("failed to create storage: %w", err)
	}
	defer storage.Close()

	// Create audit logger
	logger, err := monitoring.NewAuditLogger(auditConfig, storage)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Start logger
	if err := logger.Start(); err != nil {
		return fmt.Errorf("failed to start audit logger: %w", err)
	}
	defer logger.Stop()

	fmt.Println("✅ Audit logging system initialized successfully")
	fmt.Printf("📁 Storage: %s\n", storageConfig.BaseDirectory)
	fmt.Printf("🔒 PII patterns: %d configured\n", len(auditConfig.PIIPatterns))
	fmt.Printf("📊 Retention: %v default\n", auditConfig.RetentionPolicy.DefaultRetention)

	return nil
}

func demoRequestResponse() error {
	fmt.Println("Demonstrating request/response tracking...")

	storage := monitoring.NewMemoryAuditStorage()
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled:     true,
		LogRequests: true,
		LogResponses: true,
		LogHeaders:  true,
		LogBody:     true,
		MaxBodySize: 4096,
		RetentionPolicy: &monitoring.RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	// Simulate various requests
	requests := []struct {
		method string
		path   string
		body   string
		status int
	}{
		{"GET", "/api/health", "", 200},
		{"POST", "/api/chat", `{"message": "Hello world!"}`, 200},
		{"PUT", "/api/users/123", `{"name": "John Doe"}`, 200},
		{"DELETE", "/api/sessions/abc", "", 204},
	}

	for i, req := range requests {
		correlationID := fmt.Sprintf("demo-correlation-%d", i+1)
		
		// Create request
		httpReq := httptest.NewRequest(req.method, req.path, strings.NewReader(req.body))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("User-Agent", "DemoClient/1.0")
		httpReq.Header.Set("X-Request-ID", correlationID)

		// Log request
		if err := logger.LogGatewayRequest(httpReq, correlationID); err != nil {
			return err
		}

		// Simulate response
		resp := &http.Response{
			StatusCode: req.status,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		duration := time.Millisecond * time.Duration(50+i*25)
		if err := logger.LogGatewayResponse(resp, duration, correlationID); err != nil {
			return err
		}

		fmt.Printf("📝 Logged: %s %s (%d) - %v\n", req.method, req.path, req.status, duration)
	}

	// Show results
	events, err := storage.Query(&monitoring.AuditQueryFilters{})
	if err != nil {
		return err
	}

	fmt.Printf("✅ Tracked %d events (%d requests + %d responses)\n", 
		len(events), len(requests), len(requests))

	return nil
}

func demoSecurityEvents() error {
	fmt.Println("Demonstrating security event logging...")

	storage := monitoring.NewMemoryAuditStorage()
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled:           true,
		SanitizeBody:      true,
		HashSensitiveData: true,
		PIIPatterns:       []string{`\d{3}-\d{2}-\d{4}`, `\d{16}`},
		SensitiveHeaders:  []string{"Authorization"},
		RetentionPolicy: &monitoring.RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	// Simulate security violations
	violations := []struct {
		violation string
		details   map[string]interface{}
	}{
		{
			"PII detected in request",
			map[string]interface{}{
				"pii_type":   "SSN",
				"confidence": 0.95,
				"location":   "request_body",
			},
		},
		{
			"Suspicious IP activity",
			map[string]interface{}{
				"client_ip":      "192.168.1.100",
				"request_count":  50,
				"time_window":    "5 minutes",
				"threat_level":   "medium",
			},
		},
		{
			"Invalid authentication token",
			map[string]interface{}{
				"token_type": "JWT",
				"error":      "signature verification failed",
				"user_id":    "unknown",
			},
		},
	}

	for i, violation := range violations {
		req := httptest.NewRequest("POST", "/api/chat", 
			strings.NewReader(`{"message": "My SSN is 123-45-6789"}`))
		req.Header.Set("Authorization", "Bearer invalid-token-12345")

		if err := logger.LogSecurityViolation(violation.violation, req, violation.details); err != nil {
			return err
		}

		fmt.Printf("🚨 Security violation #%d: %s\n", i+1, violation.violation)
	}

	// Query security events
	securityEvents, err := storage.Query(&monitoring.AuditQueryFilters{
		Categories: []monitoring.AuditCategory{monitoring.CategorySecurity},
	})
	if err != nil {
		return err
	}

	fmt.Printf("✅ Logged %d security events\n", len(securityEvents))
	return nil
}

func demoPolicyProvider() error {
	fmt.Println("Demonstrating policy and provider event tracking...")

	storage := monitoring.NewMemoryAuditStorage()
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled: true,
		RetentionPolicy: &monitoring.RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	req := httptest.NewRequest("POST", "/api/chat", 
		strings.NewReader(`{"message": "Analyze this data"}`))

	// Simulate policy evaluations
	policies := []struct {
		id       string
		decision string
		details  map[string]interface{}
	}{
		{
			"content-filter-policy",
			"ALLOW",
			map[string]interface{}{
				"content_score": 0.2,
				"categories":    []string{"general"},
			},
		},
		{
			"rate-limit-policy",
			"ALLOW",
			map[string]interface{}{
				"requests_count": 45,
				"limit":          100,
				"window":         "1 hour",
			},
		},
		{
			"cost-control-policy",
			"ALLOW",
			map[string]interface{}{
				"estimated_cost": 0.05,
				"budget_remaining": 95.50,
			},
		},
	}

	for _, policy := range policies {
		if err := logger.LogPolicyEvaluation(policy.id, policy.decision, req, policy.details); err != nil {
			return err
		}
		fmt.Printf("📋 Policy: %s -> %s\n", policy.id, policy.decision)
	}

	// Simulate provider calls
	providers := []struct {
		name     string
		model    string
		tokens   int64
		cost     float64
		duration time.Duration
		success  bool
	}{
		{"openai", "gpt-4", 1500, 0.045, time.Millisecond * 800, true},
		{"anthropic", "claude-3", 1200, 0.036, time.Millisecond * 650, true},
		{"azure", "gpt-3.5-turbo", 900, 0.018, time.Millisecond * 400, true},
	}

	for _, provider := range providers {
		if err := logger.LogProviderCall(provider.name, provider.model, 
			provider.tokens, provider.cost, provider.duration, provider.success); err != nil {
			return err
		}
		fmt.Printf("🤖 Provider: %s/%s - %d tokens, $%.3f, %v\n", 
			provider.name, provider.model, provider.tokens, provider.cost, provider.duration)
	}

	// Show results
	policyEvents, err := storage.Query(&monitoring.AuditQueryFilters{
		Categories: []monitoring.AuditCategory{monitoring.CategoryPolicy},
	})
	if err != nil {
		return err
	}

	providerEvents, err := storage.Query(&monitoring.AuditQueryFilters{
		Categories: []monitoring.AuditCategory{monitoring.CategoryProvider},
	})
	if err != nil {
		return err
	}

	fmt.Printf("✅ Logged %d policy events and %d provider events\n", 
		len(policyEvents), len(providerEvents))

	return nil
}

func demoDataSanitization() error {
	fmt.Println("Demonstrating data sanitization capabilities...")

	storage := monitoring.NewMemoryAuditStorage()
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled:           true,
		SanitizeBody:      true,
		HashSensitiveData: true,
		PIIPatterns: []string{
			`\d{3}-\d{2}-\d{4}`,     // SSN
			`\d{16}`,                // Credit card
			`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, // Email
		},
		SensitiveHeaders: []string{"Authorization", "X-API-Key", "Cookie"},
		RetentionPolicy: &monitoring.RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	// Test data with PII
	testData := `{
		"user": {
			"name": "John Doe",
			"ssn": "123-45-6789",
			"email": "john.doe@example.com",
			"credit_card": "1234567890123456"
		},
		"message": "Please analyze this sensitive data"
	}`

	req := httptest.NewRequest("POST", "/api/analyze", strings.NewReader(testData))
	req.Header.Set("Authorization", "Bearer secret-api-key-12345")
	req.Header.Set("X-API-Key", "api-key-67890")
	req.Header.Set("Content-Type", "application/json")

	if err := logger.LogGatewayRequest(req, "sanitization-demo"); err != nil {
		return err
	}

	// Retrieve and examine sanitized event
	events, err := storage.Query(&monitoring.AuditQueryFilters{})
	if err != nil {
		return err
	}

	if len(events) == 0 {
		return fmt.Errorf("no events found")
	}

	event := events[0]
	
	fmt.Println("📤 Original data contained:")
	fmt.Println("  - SSN: 123-45-6789")
	fmt.Println("  - Email: john.doe@example.com") 
	fmt.Println("  - Credit Card: 1234567890123456")
	fmt.Println("  - API Key: secret-api-key-12345")

	fmt.Println("\n🔒 Sanitized data shows:")
	if strings.Contains(event.RequestBody, "[HASH:") {
		fmt.Println("  - PII replaced with secure hashes")
	}
	if strings.Contains(event.Headers["Authorization"], "[HASH:") {
		fmt.Println("  - Sensitive headers hashed")
	}

	fmt.Printf("✅ Data sanitization working correctly\n")
	return nil
}

func demoStorageQuerying() error {
	fmt.Println("Demonstrating storage and querying capabilities...")

	storage := monitoring.NewMemoryAuditStorage()
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled: true,
		RetentionPolicy: &monitoring.RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	// Generate diverse events
	baseTime := time.Now().Add(-time.Hour)
	
	events := []monitoring.AuditEvent{
		{
			Category:  monitoring.CategoryGateway,
			Type:      monitoring.EventTypeRequest,
			Severity:  monitoring.SeverityLow,
			Source:    "demo",
			Component: "api",
			UserID:    "user1",
			ClientIP:  "192.168.1.10",
			Outcome:   monitoring.OutcomeSuccess,
			Timestamp: baseTime,
		},
		{
			Category:  monitoring.CategorySecurity,
			Type:      monitoring.EventTypeSecurityViolation,
			Severity:  monitoring.SeverityHigh,
			Source:    "demo",
			Component: "security",
			UserID:    "user2",
			ClientIP:  "10.0.0.5",
			Outcome:   monitoring.OutcomeBlocked,
			Timestamp: baseTime.Add(time.Minute * 15),
		},
		{
			Category:  monitoring.CategoryProvider,
			Type:      monitoring.EventTypeProviderCall,
			Severity:  monitoring.SeverityMedium,
			Source:    "demo",
			Component: "openai",
			UserID:    "user1",
			Outcome:   monitoring.OutcomeSuccess,
			Timestamp: baseTime.Add(time.Minute * 30),
		},
	}

	for _, event := range events {
		if err := logger.LogEvent(&event); err != nil {
			return err
		}
	}

	// Demonstrate various queries
	queries := []struct {
		name    string
		filters monitoring.AuditQueryFilters
	}{
		{
			"All events",
			monitoring.AuditQueryFilters{},
		},
		{
			"Security events only",
			monitoring.AuditQueryFilters{
				Categories: []monitoring.AuditCategory{monitoring.CategorySecurity},
			},
		},
		{
			"High severity events",
			monitoring.AuditQueryFilters{
				Severities: []monitoring.AuditSeverity{monitoring.SeverityHigh, monitoring.SeverityCritical},
			},
		},
		{
			"Events from user1",
			monitoring.AuditQueryFilters{
				UserIDs: []string{"user1"},
			},
		},
		{
			"Recent events (last 20 minutes)",
			monitoring.AuditQueryFilters{
				StartTime: &[]time.Time{baseTime.Add(time.Minute * 10)}[0],
			},
		},
	}

	for _, query := range queries {
		results, err := storage.Query(&query.filters)
		if err != nil {
			return err
		}
		fmt.Printf("🔍 %s: %d results\n", query.name, len(results))
	}

	// Test counting
	count, err := storage.Count(&monitoring.AuditQueryFilters{})
	if err != nil {
		return err
	}

	fmt.Printf("✅ Storage contains %d total events\n", count)
	return nil
}

func demoPerformanceMonitoring() error {
	fmt.Println("Demonstrating performance monitoring...")

	storage := monitoring.NewMemoryAuditStorage()
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled: true,
		RetentionPolicy: &monitoring.RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	fmt.Println("🚀 Generating load to test performance...")

	// Generate load
	start := time.Now()
	eventCount := 100

	for i := 0; i < eventCount; i++ {
		event := &monitoring.AuditEvent{
			Category:  monitoring.CategoryGateway,
			Type:      monitoring.EventTypeRequest,
			Severity:  monitoring.SeverityLow,
			Source:    "performance-test",
			Component: "load-generator",
			Outcome:   monitoring.OutcomeSuccess,
		}
		
		if err := logger.LogEvent(event); err != nil {
			return err
		}
	}

	duration := time.Since(start)
	
	// Get performance metrics
	metrics := logger.GetPerformanceMetrics()

	fmt.Printf("📊 Performance Results:\n")
	fmt.Printf("  - Events logged: %d\n", metrics.EventsLogged)
	fmt.Printf("  - Events dropped: %d\n", metrics.EventsDropped)
	fmt.Printf("  - Total time: %v\n", duration)
	fmt.Printf("  - Average latency: %v\n", metrics.AverageLatency)
	fmt.Printf("  - Max latency: %v\n", metrics.MaxLatency)
	fmt.Printf("  - Min latency: %v\n", metrics.MinLatency)
	fmt.Printf("  - Events per second: %.2f\n", float64(eventCount)/duration.Seconds())

	fmt.Printf("✅ Performance monitoring active\n")
	return nil
}

func demoRetentionArchival() error {
	fmt.Println("Demonstrating data retention and archival...")

	// Create temporary directory
	tempDir := "./demo_retention"
	os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)

	storageConfig := &monitoring.FileStorageConfig{
		BaseDirectory:    tempDir,
		FilePrefix:       "retention_demo",
		FileExtension:    ".log",
		MaxFileSize:      1024,
		MaxFiles:         5,
		CompressOldFiles: true,
		CreateDirs:       true,
	}

	storage, err := monitoring.NewFileAuditStorage(storageConfig)
	if err != nil {
		return err
	}
	defer storage.Close()

	config := &monitoring.AuditConfig{
		Enabled: true,
		RetentionPolicy: &monitoring.RetentionPolicy{
			DefaultRetention:  24 * time.Hour,
			ArchiveAfter:      time.Minute,   // Archive after 1 minute for demo
			DeleteAfter:       time.Hour * 2, // Delete after 2 hours for demo
			EnableAutoCleanup: false,         // Manual for demo
		},
	}

	logger, err := monitoring.NewAuditLogger(config, storage)
	if err != nil {
		return err
	}

	if err := logger.Start(); err != nil {
		return err
	}
	defer logger.Stop()

	// Generate some events
	for i := 0; i < 5; i++ {
		event := &monitoring.AuditEvent{
			Category:  monitoring.CategorySystem,
			Type:      monitoring.EventTypeConfiguration,
			Severity:  monitoring.SeverityLow,
			Source:    "retention-demo",
			Component: "archival",
			Outcome:   monitoring.OutcomeSuccess,
			Timestamp: time.Now().Add(-time.Duration(i) * time.Minute * 2),
		}
		
		if err := logger.LogEvent(event); err != nil {
			return err
		}
	}

	fmt.Println("📁 Generated audit files:")
	files, err := filepath.Glob(filepath.Join(tempDir, "retention_demo_*"))
	if err != nil {
		return err
	}

	for _, file := range files {
		info, _ := os.Stat(file)
		fmt.Printf("  - %s (%d bytes)\n", filepath.Base(file), info.Size())
	}

	// Demonstrate archival
	fmt.Println("\n📦 Simulating archival process...")
	archiveTime := time.Now().Add(-time.Minute * 30)
	if err := storage.Archive(archiveTime); err != nil {
		return err
	}

	// Check for compressed files
	compressedFiles, err := filepath.Glob(filepath.Join(tempDir, "*.gz"))
	if err != nil {
		return err
	}

	fmt.Printf("✅ Archival complete. Compressed files: %d\n", len(compressedFiles))

	// Count remaining events
	count, err := storage.Count(&monitoring.AuditQueryFilters{})
	if err != nil {
		return err
	}

	fmt.Printf("📊 Events remaining in storage: %d\n", count)
	return nil
} 