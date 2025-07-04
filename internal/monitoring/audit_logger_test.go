package monitoring

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== AUDIT LOGGER TESTS =====

func TestNewAuditLogger(t *testing.T) {
	tests := []struct {
		name        string
		config      *AuditConfig
		storage     AuditStorage
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			storage:     NewMemoryAuditStorage(),
			expectError: true,
		},
		{
			name: "nil storage",
			config: &AuditConfig{
				Enabled: true,
				PIIPatterns: []string{`\d{3}-\d{2}-\d{4}`}, // SSN pattern
			},
			storage:     nil,
			expectError: true,
		},
		{
			name: "valid config and storage",
			config: &AuditConfig{
				Enabled:         true,
				LogLevel:        "info",
				LogRequests:     true,
				LogResponses:    true,
				LogHeaders:      true,
				LogBody:         true,
				MaxBodySize:     1024,
				SanitizeBody:    true,
				HashSensitiveData: true,
				EnableAsync:     false,
				BufferSize:      100,
				SampleRate:      1.0,
				PIIPatterns:     []string{`\d{3}-\d{2}-\d{4}`, `\d{16}`},
				SensitiveHeaders: []string{"Authorization", "Cookie"},
				RetentionPolicy: &RetentionPolicy{
					DefaultRetention:  30 * 24 * time.Hour,
					ArchiveAfter:      7 * 24 * time.Hour,
					DeleteAfter:       90 * 24 * time.Hour,
					EnableAutoCleanup: true,
					CleanupInterval:   time.Hour,
				},
			},
			storage:     NewMemoryAuditStorage(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewAuditLogger(tt.config, tt.storage)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
				assert.Equal(t, tt.config, logger.config)
				assert.Equal(t, tt.storage, logger.storage)
			}
		})
	}
}

func TestAuditLogger_StartStop(t *testing.T) {
	config := &AuditConfig{
		Enabled:    true,
		EnableAsync: false,
		RetentionPolicy: &RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}
	storage := NewMemoryAuditStorage()
	
	logger, err := NewAuditLogger(config, storage)
	require.NoError(t, err)
	
	// Test start
	err = logger.Start()
	assert.NoError(t, err)
	assert.True(t, logger.isRunning)
	
	// Test start when already running
	err = logger.Start()
	assert.Error(t, err)
	
	// Test stop
	err = logger.Stop()
	assert.NoError(t, err)
	assert.False(t, logger.isRunning)
	
	// Test stop when already stopped
	err = logger.Stop()
	assert.NoError(t, err)
}

func TestAuditLogger_LogEvent(t *testing.T) {
	config := &AuditConfig{
		Enabled:    true,
		EnableAsync: false,
		SampleRate: 1.0,
		PIIPatterns: []string{`\d{3}-\d{2}-\d{4}`},
		SensitiveHeaders: []string{"Authorization"},
		SanitizeBody: true,
		HashSensitiveData: true,
		RetentionPolicy: &RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}
	storage := NewMemoryAuditStorage()
	
	logger, err := NewAuditLogger(config, storage)
	require.NoError(t, err)
	
	err = logger.Start()
	require.NoError(t, err)
	defer logger.Stop()
	
	// Test basic event logging
	event := &AuditEvent{
		Category:    CategoryGateway,
		Type:        EventTypeRequest,
		Severity:    SeverityLow,
		Source:      "test",
		Component:   "test-component",
		Action:      "test-action",
		Outcome:     OutcomeSuccess,
		ClientIP:    "192.168.1.1",
		UserAgent:   "test-agent",
		RequestBody: "SSN: 123-45-6789",
		Headers: map[string]string{
			"Authorization": "Bearer secret-token",
			"Content-Type":  "application/json",
		},
	}
	
	err = logger.LogEvent(event)
	assert.NoError(t, err)
	
	// Verify event was stored
	events, err := storage.Query(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Len(t, events, 1)
	
	storedEvent := events[0]
	assert.Equal(t, CategoryGateway, storedEvent.Category)
	assert.Equal(t, EventTypeRequest, storedEvent.Type)
	assert.NotEmpty(t, storedEvent.ID)
	assert.False(t, storedEvent.Timestamp.IsZero())
	
	// Verify PII was sanitized
	assert.Contains(t, storedEvent.RequestBody, "[HASH:")
	assert.NotContains(t, storedEvent.RequestBody, "123-45-6789")
	
	// Verify sensitive headers were sanitized
	assert.Contains(t, storedEvent.Headers["Authorization"], "[HASH:")
	assert.NotContains(t, storedEvent.Headers["Authorization"], "secret-token")
	assert.Equal(t, "application/json", storedEvent.Headers["Content-Type"])
}

func TestAuditLogger_Filtering(t *testing.T) {
	config := &AuditConfig{
		Enabled:         true,
		EnableAsync:     false,
		SampleRate:      1.0,
		IncludePatterns: []string{"request", "response"},
		ExcludePatterns: []string{"health_check"},
		RetentionPolicy: &RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}
	storage := NewMemoryAuditStorage()
	
	logger, err := NewAuditLogger(config, storage)
	require.NoError(t, err)
	
	err = logger.Start()
	require.NoError(t, err)
	defer logger.Stop()
	
	// Event that should be included
	includedEvent := &AuditEvent{
		Type:      EventTypeRequest,
		Category:  CategoryGateway,
		Severity:  SeverityLow,
		Source:    "test",
		Component: "test",
		Outcome:   OutcomeSuccess,
	}
	
	// Event that should be excluded
	excludedEvent := &AuditEvent{
		Type:      EventTypeHealthCheck,
		Category:  CategorySystem,
		Severity:  SeverityLow,
		Source:    "test",
		Component: "test",
		Outcome:   OutcomeSuccess,
	}
	
	// Event that doesn't match include patterns
	notIncludedEvent := &AuditEvent{
		Type:      EventTypeConfiguration,
		Category:  CategorySystem,
		Severity:  SeverityLow,
		Source:    "test",
		Component: "test",
		Outcome:   OutcomeSuccess,
	}
	
	err = logger.LogEvent(includedEvent)
	assert.NoError(t, err)
	
	err = logger.LogEvent(excludedEvent)
	assert.NoError(t, err)
	
	err = logger.LogEvent(notIncludedEvent)
	assert.NoError(t, err)
	
	// Only the included event should be stored
	events, err := storage.Query(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, EventTypeRequest, events[0].Type)
}

func TestAuditLogger_ConvenienceMethods(t *testing.T) {
	config := &AuditConfig{
		Enabled:    true,
		EnableAsync: false,
		LogHeaders: true,
		LogBody:    true,
		MaxBodySize: 1024,
		RetentionPolicy: &RetentionPolicy{
			EnableAutoCleanup: false,
		},
	}
	storage := NewMemoryAuditStorage()
	
	logger, err := NewAuditLogger(config, storage)
	require.NoError(t, err)
	
	err = logger.Start()
	require.NoError(t, err)
	defer logger.Stop()
	
	// Test LogGatewayRequest
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(`{"message": "Hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client")
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	
	err = logger.LogGatewayRequest(req, "test-correlation-123")
	assert.NoError(t, err)
	
	// Test LogGatewayResponse
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}
	
	err = logger.LogGatewayResponse(resp, time.Millisecond*150, "test-correlation-123")
	assert.NoError(t, err)
	
	// Test LogSecurityViolation
	err = logger.LogSecurityViolation("PII detected in request", req, map[string]interface{}{
		"detected_pii": "SSN",
		"confidence":   0.95,
	})
	assert.NoError(t, err)
	
	// Test LogPolicyEvaluation
	err = logger.LogPolicyEvaluation("policy-123", "DENY", req, map[string]interface{}{
		"reason": "Content contains sensitive information",
	})
	assert.NoError(t, err)
	
	// Test LogProviderCall
	err = logger.LogProviderCall("openai", "gpt-4", 1500, 0.03, time.Millisecond*500, true)
	assert.NoError(t, err)
	
	// Verify all events were logged
	events, err := storage.Query(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Len(t, events, 5)
	
	// Verify specific events
	var requestEvent, responseEvent, securityEvent, policyEvent, providerEvent *AuditEvent
	for _, event := range events {
		switch event.Type {
		case EventTypeRequest:
			requestEvent = event
		case EventTypeResponse:
			responseEvent = event
		case EventTypeSecurityViolation:
			securityEvent = event
		case EventTypePolicyEvaluation:
			policyEvent = event
		case EventTypeProviderCall:
			providerEvent = event
		}
	}
	
	// Verify request event
	require.NotNil(t, requestEvent)
	assert.Equal(t, "test-correlation-123", requestEvent.CorrelationID)
	assert.Equal(t, "POST", requestEvent.Method)
	assert.Equal(t, "/api/chat", requestEvent.Path)
	assert.Equal(t, "203.0.113.1", requestEvent.ClientIP)
	assert.Equal(t, "application/json", requestEvent.Headers["Content-Type"])
	
	// Verify response event
	require.NotNil(t, responseEvent)
	assert.Equal(t, "test-correlation-123", responseEvent.CorrelationID)
	assert.Equal(t, 200, responseEvent.StatusCode)
	assert.Equal(t, time.Millisecond*150, responseEvent.Duration)
	assert.Equal(t, OutcomeSuccess, responseEvent.Outcome)
	
	// Verify security violation event
	require.NotNil(t, securityEvent)
	assert.Equal(t, CategorySecurity, securityEvent.Category)
	assert.Equal(t, SeverityHigh, securityEvent.Severity)
	assert.Equal(t, OutcomeBlocked, securityEvent.Outcome)
	
	// Verify policy evaluation event
	require.NotNil(t, policyEvent)
	assert.Equal(t, "policy-123", policyEvent.PolicyID)
	assert.Equal(t, "DENY", policyEvent.PolicyDecision)
	assert.Equal(t, OutcomeDenied, policyEvent.Outcome)
	
	// Verify provider call event
	require.NotNil(t, providerEvent)
	assert.Equal(t, "openai", providerEvent.ProviderName)
	assert.Equal(t, "gpt-4", providerEvent.ProviderModel)
	assert.Equal(t, int64(1500), providerEvent.TokensUsed)
	assert.Equal(t, 0.03, providerEvent.Cost)
}

// ===== STORAGE TESTS =====

func TestMemoryAuditStorage(t *testing.T) {
	storage := NewMemoryAuditStorage()
	defer storage.Close()
	
	// Test storing events
	events := []*AuditEvent{
		{
			ID:        "1",
			Timestamp: time.Now().Add(-time.Hour),
			Category:  CategoryGateway,
			Type:      EventTypeRequest,
			Severity:  SeverityLow,
			Source:    "test",
			Component: "component1",
			UserID:    "user1",
			ClientIP:  "192.168.1.1",
			Outcome:   OutcomeSuccess,
		},
		{
			ID:        "2",
			Timestamp: time.Now().Add(-time.Minute * 30),
			Category:  CategorySecurity,
			Type:      EventTypeSecurityViolation,
			Severity:  SeverityHigh,
			Source:    "test",
			Component: "component2",
			UserID:    "user2",
			ClientIP:  "192.168.1.2",
			Outcome:   OutcomeBlocked,
		},
		{
			ID:        "3",
			Timestamp: time.Now(),
			Category:  CategoryPolicy,
			Type:      EventTypePolicyEvaluation,
			Severity:  SeverityMedium,
			Source:    "test",
			Component: "component1",
			UserID:    "user1",
			ClientIP:  "192.168.1.1",
			Outcome:   OutcomeDenied,
		},
	}
	
	// Store events
	for _, event := range events {
		err := storage.Store(event)
		assert.NoError(t, err)
	}
	
	// Test querying all events
	allEvents, err := storage.Query(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Len(t, allEvents, 3)
	
	// Test counting all events
	count, err := storage.Count(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
	
	// Test filtering by category
	gatewayEvents, err := storage.Query(&AuditQueryFilters{
		Categories: []AuditCategory{CategoryGateway},
	})
	assert.NoError(t, err)
	assert.Len(t, gatewayEvents, 1)
	assert.Equal(t, CategoryGateway, gatewayEvents[0].Category)
	
	// Test filtering by severity
	highSeverityEvents, err := storage.Query(&AuditQueryFilters{
		Severities: []AuditSeverity{SeverityHigh, SeverityCritical},
	})
	assert.NoError(t, err)
	assert.Len(t, highSeverityEvents, 1)
	assert.Equal(t, SeverityHigh, highSeverityEvents[0].Severity)
	
	// Test filtering by user ID
	user1Events, err := storage.Query(&AuditQueryFilters{
		UserIDs: []string{"user1"},
	})
	assert.NoError(t, err)
	assert.Len(t, user1Events, 2)
	
	// Test time range filtering
	now := time.Now()
	recentEvents, err := storage.Query(&AuditQueryFilters{
		StartTime: &[]time.Time{now.Add(-time.Minute * 45)}[0],
		EndTime:   &now,
	})
	assert.NoError(t, err)
	assert.Len(t, recentEvents, 2)
	
	// Test limit and offset
	limitedEvents, err := storage.Query(&AuditQueryFilters{
		Limit:  1,
		Offset: 1,
	})
	assert.NoError(t, err)
	assert.Len(t, limitedEvents, 1)
	
	// Test sorting
	sortedEvents, err := storage.Query(&AuditQueryFilters{
		SortBy:    "timestamp",
		SortOrder: "asc",
	})
	assert.NoError(t, err)
	assert.Len(t, sortedEvents, 3)
	assert.True(t, sortedEvents[0].Timestamp.Before(sortedEvents[1].Timestamp))
	assert.True(t, sortedEvents[1].Timestamp.Before(sortedEvents[2].Timestamp))
	
	// Test search text
	searchEvents, err := storage.Query(&AuditQueryFilters{
		SearchText: "component1",
	})
	assert.NoError(t, err)
	assert.Len(t, searchEvents, 2)
	
	// Test delete old events
	err = storage.Delete(time.Now().Add(-time.Minute * 45))
	assert.NoError(t, err)
	
	remainingEvents, err := storage.Query(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Len(t, remainingEvents, 2) // Should only have the 2 recent events
}

func TestFileAuditStorage(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "audit_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	config := &FileStorageConfig{
		BaseDirectory:    tempDir,
		FilePrefix:       "test_audit",
		FileExtension:    ".log",
		MaxFileSize:      1024, // Small size to test rotation
		MaxFiles:         5,
		CompressOldFiles: false,
		SyncInterval:     time.Millisecond * 100,
		CreateDirs:       true,
		FilePermissions:  0644,
	}
	
	storage, err := NewFileAuditStorage(config)
	require.NoError(t, err)
	defer storage.Close()
	
	// Test storing events
	event1 := &AuditEvent{
		ID:        "1",
		Timestamp: time.Now(),
		Category:  CategoryGateway,
		Type:      EventTypeRequest,
		Severity:  SeverityLow,
		Source:    "test",
		Component: "test",
		Outcome:   OutcomeSuccess,
	}
	
	err = storage.Store(event1)
	assert.NoError(t, err)
	
	// Create a large event to test file rotation
	largeEvent := &AuditEvent{
		ID:          "2",
		Timestamp:   time.Now(),
		Category:    CategoryGateway,
		Type:        EventTypeRequest,
		Severity:    SeverityLow,
		Source:      "test",
		Component:   "test",
		RequestBody: strings.Repeat("x", 2000), // Large body to trigger rotation
		Outcome:     OutcomeSuccess,
	}
	
	err = storage.Store(largeEvent)
	assert.NoError(t, err)
	
	// Verify events can be queried
	events, err := storage.Query(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Len(t, events, 2)
	
	// Count events
	count, err := storage.Count(&AuditQueryFilters{})
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)
	
	// Verify files were created
	files, err := filepath.Glob(filepath.Join(tempDir, "test_audit_*"))
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 1)
}

// ===== DATA SANITIZER TESTS =====

func TestDataSanitizer(t *testing.T) {
	config := &AuditConfig{
		SanitizeBody:      true,
		HashSensitiveData: true,
		PIIPatterns: []string{
			`\d{3}-\d{2}-\d{4}`,     // SSN
			`\d{16}`,                // Credit card
			`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Email
		},
		SensitiveHeaders: []string{"Authorization", "X-API-Key"},
	}
	
	sanitizer, err := NewDataSanitizer(config)
	require.NoError(t, err)
	
	event := &AuditEvent{
		RequestBody: "User SSN: 123-45-6789, CC: 1234567890123456, Email: user@example.com",
		Headers: map[string]string{
			"Authorization": "Bearer secret-token",
			"X-API-Key":     "api-key-12345",
			"Content-Type":  "application/json",
		},
		UserAgent: "Mozilla/5.0 (contains PII: 123-45-6789)",
	}
	
	sanitizedEvent := sanitizer.SanitizeEvent(event)
	
	// Verify PII was sanitized in body
	assert.NotContains(t, sanitizedEvent.RequestBody, "123-45-6789")
	assert.NotContains(t, sanitizedEvent.RequestBody, "1234567890123456")
	assert.NotContains(t, sanitizedEvent.RequestBody, "user@example.com")
	assert.Contains(t, sanitizedEvent.RequestBody, "[HASH:")
	
	// Verify sensitive headers were sanitized
	assert.NotContains(t, sanitizedEvent.Headers["Authorization"], "secret-token")
	assert.NotContains(t, sanitizedEvent.Headers["X-API-Key"], "api-key-12345")
	assert.Contains(t, sanitizedEvent.Headers["Authorization"], "[HASH:")
	assert.Contains(t, sanitizedEvent.Headers["X-API-Key"], "[HASH:")
	
	// Verify non-sensitive headers were preserved
	assert.Equal(t, "application/json", sanitizedEvent.Headers["Content-Type"])
	
	// Verify user agent was sanitized
	assert.NotContains(t, sanitizedEvent.UserAgent, "123-45-6789")
	assert.Contains(t, sanitizedEvent.UserAgent, "[HASH:")
}

func TestDataSanitizer_DisabledSanitization(t *testing.T) {
	config := &AuditConfig{
		SanitizeBody:      false,
		HashSensitiveData: false,
	}
	
	sanitizer, err := NewDataSanitizer(config)
	require.NoError(t, err)
	
	event := &AuditEvent{
		RequestBody: "User SSN: 123-45-6789",
		Headers: map[string]string{
			"Authorization": "Bearer secret-token",
		},
	}
	
	sanitizedEvent := sanitizer.SanitizeEvent(event)
	
	// When sanitization is disabled, event should be returned as-is
	assert.Equal(t, event, sanitizedEvent)
}

// ===== PERFORMANCE TRACKER TESTS =====

func TestAuditPerformanceTracker(t *testing.T) {
	tracker := NewAuditPerformanceTracker()
	
	// Record some events
	tracker.RecordEvent(time.Millisecond*10, true)
	tracker.RecordEvent(time.Millisecond*20, true)
	tracker.RecordEvent(time.Millisecond*5, false)
	tracker.RecordEvent(time.Millisecond*15, true)
	
	metrics := tracker.GetMetrics()
	
	assert.Equal(t, int64(3), metrics.EventsLogged)
	assert.Equal(t, int64(1), metrics.EventsDropped)
	assert.Equal(t, int64(1), metrics.ErrorsCount)
	assert.Equal(t, time.Millisecond*20, metrics.MaxLatency)
	assert.Equal(t, time.Millisecond*10, metrics.MinLatency)
	assert.False(t, metrics.LastEventTime.IsZero())
	assert.False(t, metrics.StartTime.IsZero())
}

// ===== HELPER FUNCTIONS =====

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func() *http.Request
		expectedIP string
	}{
		{
			name: "X-Forwarded-For header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")
				return req
			},
			expectedIP: "203.0.113.1",
		},
		{
			name: "X-Real-IP header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Real-IP", "203.0.113.2")
				return req
			},
			expectedIP: "203.0.113.2",
		},
		{
			name: "RemoteAddr",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "203.0.113.3:8080"
				return req
			},
			expectedIP: "203.0.113.3",
		},
		{
			name: "no IP information",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = ""
				return req
			},
			expectedIP: "unknown",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			ip := getClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestExtractHeaders(t *testing.T) {
	headers := http.Header{
		"Content-Type":   []string{"application/json"},
		"Authorization":  []string{"Bearer token"},
		"X-Custom":       []string{"value1", "value2"},
	}
	
	// Test with logging enabled
	extracted := extractHeaders(headers, true)
	assert.Equal(t, "application/json", extracted["Content-Type"])
	assert.Equal(t, "Bearer token", extracted["Authorization"])
	assert.Equal(t, "value1", extracted["X-Custom"]) // Should take first value
	
	// Test with logging disabled
	extracted = extractHeaders(headers, false)
	assert.Nil(t, extracted)
}

// ===== INTEGRATION TESTS =====

func TestAuditLogger_Integration(t *testing.T) {
	// Create temporary directory for file storage
	tempDir, err := os.MkdirTemp("", "audit_integration_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	// Configure file storage
	storageConfig := &FileStorageConfig{
		BaseDirectory:    tempDir,
		FilePrefix:       "integration_audit",
		FileExtension:    ".log",
		MaxFileSize:      10 * 1024, // 10KB
		MaxFiles:         3,
		CompressOldFiles: true,
		SyncInterval:     time.Millisecond * 50,
		CreateDirs:       true,
		FilePermissions:  0644,
	}
	
	storage, err := NewFileAuditStorage(storageConfig)
	require.NoError(t, err)
	defer storage.Close()
	
	// Configure audit logger
	auditConfig := &AuditConfig{
		Enabled:         true,
		LogLevel:        "info",
		LogRequests:     true,
		LogResponses:    true,
		LogHeaders:      true,
		LogBody:         true,
		MaxBodySize:     2048,
		SanitizeBody:    true,
		HashSensitiveData: true,
		EnableAsync:     false,
		BufferSize:      100,
		SampleRate:      1.0,
		PIIPatterns:     []string{`\d{3}-\d{2}-\d{4}`},
		SensitiveHeaders: []string{"Authorization"},
		RetentionPolicy: &RetentionPolicy{
			DefaultRetention:  24 * time.Hour,
			ArchiveAfter:      time.Hour,
			DeleteAfter:       48 * time.Hour,
			EnableAutoCleanup: false, // Disable for test
			CleanupInterval:   time.Minute,
		},
	}
	
	logger, err := NewAuditLogger(auditConfig, storage)
	require.NoError(t, err)
	
	err = logger.Start()
	require.NoError(t, err)
	defer logger.Stop()
	
	// Simulate a complete request/response cycle
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(`{
		"message": "Hello, my SSN is 123-45-6789",
		"user_id": "user123"
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token-12345")
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.Header.Set("User-Agent", "TestClient/1.0")
	
	correlationID := "correlation-" + fmt.Sprintf("%d", time.Now().UnixNano())
	
	// Log request
	err = logger.LogGatewayRequest(req, correlationID)
	require.NoError(t, err)
	
	// Simulate policy evaluation
	err = logger.LogPolicyEvaluation("pii-detection-policy", "BLOCK", req, map[string]interface{}{
		"detected_pii": []string{"SSN"},
		"confidence":   0.95,
		"action":       "block_request",
	})
	require.NoError(t, err)
	
	// Log security violation
	err = logger.LogSecurityViolation("PII detected in request body", req, map[string]interface{}{
		"pii_type":    "SSN",
		"location":    "request_body",
		"pattern":     "XXX-XX-XXXX",
		"risk_level":  "high",
	})
	require.NoError(t, err)
	
	// Simulate provider call (blocked)
	err = logger.LogProviderCall("openai", "gpt-4", 0, 0.0, 0, false)
	require.NoError(t, err)
	
	// Log response
	resp := &http.Response{
		StatusCode: 403,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}
	
	err = logger.LogGatewayResponse(resp, time.Millisecond*25, correlationID)
	require.NoError(t, err)
	
	// Wait a bit for file operations to complete
	time.Sleep(time.Millisecond * 100)
	
	// Query and verify events
	allEvents, err := storage.Query(&AuditQueryFilters{
		SortBy:    "timestamp",
		SortOrder: "asc",
	})
	require.NoError(t, err)
	assert.Len(t, allEvents, 5)
	
	// Verify request event
	requestEvent := allEvents[0]
	assert.Equal(t, EventTypeRequest, requestEvent.Type)
	assert.Equal(t, correlationID, requestEvent.CorrelationID)
	assert.Equal(t, "POST", requestEvent.Method)
	assert.Equal(t, "/api/chat", requestEvent.Path)
	assert.Equal(t, "203.0.113.195", requestEvent.ClientIP)
	assert.Contains(t, requestEvent.RequestBody, "[HASH:")
	assert.NotContains(t, requestEvent.RequestBody, "123-45-6789")
	assert.Contains(t, requestEvent.Headers["Authorization"], "[HASH:")
	assert.NotContains(t, requestEvent.Headers["Authorization"], "secret-token-12345")
	
	// Verify policy evaluation event
	policyEvent := allEvents[1]
	assert.Equal(t, EventTypePolicyEvaluation, policyEvent.Type)
	assert.Equal(t, "pii-detection-policy", policyEvent.PolicyID)
	assert.Equal(t, "BLOCK", policyEvent.PolicyDecision)
	assert.Equal(t, OutcomeDenied, policyEvent.Outcome)
	
	// Verify security violation event
	securityEvent := allEvents[2]
	assert.Equal(t, EventTypeSecurityViolation, securityEvent.Type)
	assert.Equal(t, CategorySecurity, securityEvent.Category)
	assert.Equal(t, SeverityHigh, securityEvent.Severity)
	assert.Equal(t, OutcomeBlocked, securityEvent.Outcome)
	
	// Verify provider event
	providerEvent := allEvents[3]
	assert.Equal(t, EventTypeProviderCall, providerEvent.Type)
	assert.Equal(t, CategoryProvider, providerEvent.Category)
	assert.Equal(t, "openai", providerEvent.ProviderName)
	assert.Equal(t, OutcomeFailure, providerEvent.Outcome)
	
	// Verify response event
	responseEvent := allEvents[4]
	assert.Equal(t, EventTypeResponse, responseEvent.Type)
	assert.Equal(t, correlationID, responseEvent.CorrelationID)
	assert.Equal(t, 403, responseEvent.StatusCode)
	assert.Equal(t, time.Millisecond*25, responseEvent.Duration)
	assert.Equal(t, OutcomeFailure, responseEvent.Outcome)
	
	// Test filtering by correlation ID
	correlatedEvents, err := storage.Query(&AuditQueryFilters{
		SearchText: correlationID,
	})
	require.NoError(t, err)
	assert.Len(t, correlatedEvents, 2) // Request and response events
	
	// Test filtering by category
	securityEvents, err := storage.Query(&AuditQueryFilters{
		Categories: []AuditCategory{CategorySecurity},
	})
	require.NoError(t, err)
	assert.Len(t, securityEvents, 1)
	
	// Test counting
	count, err := storage.Count(&AuditQueryFilters{})
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
	
	// Test performance metrics
	metrics := logger.GetPerformanceMetrics()
	assert.Equal(t, int64(5), metrics.EventsLogged)
	assert.Equal(t, int64(0), metrics.EventsDropped)
	assert.False(t, metrics.LastEventTime.IsZero())
	
	// Verify audit files were created
	files, err := filepath.Glob(filepath.Join(tempDir, "integration_audit_*"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(files), 1)
} 