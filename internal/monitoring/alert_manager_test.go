package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"ai-gateway-poc/internal/policy"
)

// TestNewRealTimeAlertManager tests the creation of a new alert manager
func TestNewRealTimeAlertManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests
	
	// Test with nil config (should use defaults)
	manager, err := NewRealTimeAlertManager(nil, logger, nil)
	require.NoError(t, err)
	require.NotNil(t, manager)
	assert.NotNil(t, manager.config)
	assert.Equal(t, 5, manager.processingWorkers)
	assert.Equal(t, 10000, cap(manager.eventQueue))
	
	// Test with custom config
	config := &AlertManagerConfig{
		QueueSize:         1000,
		ProcessingWorkers: 3,
		MaxQueueDepth:     500,
	}
	
	manager2, err := NewRealTimeAlertManager(config, logger, nil)
	require.NoError(t, err)
	require.NotNil(t, manager2)
	assert.Equal(t, 3, manager2.processingWorkers)
	assert.Equal(t, 1000, cap(manager2.eventQueue))
}

// TestAlertLifecycle tests the complete alert lifecycle
func TestAlertLifecycle(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create an alert
	alert := &policy.Alert{
		Type:        policy.AlertTypePolicyViolation,
		Severity:    policy.AlertSeverityHigh,
		Title:       "Test Policy Violation",
		Description: "This is a test alert for policy violation",
		Source:      "test_source",
		Tags: map[string]string{
			"environment": "test",
			"component":   "policy_engine",
		},
		Metadata: map[string]interface{}{
			"test_field": "test_value",
		},
		TenantID: "test_tenant",
		PolicyID: "test_policy",
	}
	
	// Test alert creation
	err := manager.CreateAlert(alert)
	require.NoError(t, err)
	assert.NotEmpty(t, alert.ID)
	assert.Equal(t, policy.AlertStatusActive, alert.Status)
	assert.Equal(t, 1, alert.OccurrenceCount)
	
	// Test alert retrieval
	retrievedAlert, err := manager.GetAlert(alert.ID)
	require.NoError(t, err)
	assert.Equal(t, alert.ID, retrievedAlert.ID)
	assert.Equal(t, alert.Title, retrievedAlert.Title)
	assert.Equal(t, alert.Type, retrievedAlert.Type)
	
	// Test alert update
	updates := map[string]interface{}{
		"title":       "Updated Test Alert",
		"assigned_to": "test_user",
	}
	err = manager.UpdateAlert(alert.ID, updates)
	require.NoError(t, err)
	
	updatedAlert, err := manager.GetAlert(alert.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Test Alert", updatedAlert.Title)
	assert.Equal(t, "test_user", updatedAlert.AssignedTo)
	
	// Test alert acknowledgment
	err = manager.AcknowledgeAlert(alert.ID, "test_acknowledger")
	require.NoError(t, err)
	
	acknowledgedAlert, err := manager.GetAlert(alert.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.AlertStatusAcknowledged, acknowledgedAlert.Status)
	assert.Equal(t, "test_acknowledger", acknowledgedAlert.AcknowledgedBy)
	assert.NotNil(t, acknowledgedAlert.AcknowledgedAt)
	
	// Test alert resolution
	err = manager.ResolveAlert(alert.ID, "test_resolver", "Issue fixed")
	require.NoError(t, err)
	
	resolvedAlert, err := manager.GetAlert(alert.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.AlertStatusResolved, resolvedAlert.Status)
	assert.Equal(t, "test_resolver", resolvedAlert.ResolvedBy)
	assert.NotNil(t, resolvedAlert.ResolvedAt)
	assert.Equal(t, "Issue fixed", resolvedAlert.Metadata["resolution"])
}

// TestAlertSuppression tests alert suppression functionality
func TestAlertSuppression(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Test alert suppression
	alert := createTestAlert()
	err := manager.CreateAlert(alert)
	require.NoError(t, err)
	
	// Suppress the alert
	err = manager.SuppressAlert(alert.ID, 5*time.Minute, "Testing suppression")
	require.NoError(t, err)
	
	suppressedAlert, err := manager.GetAlert(alert.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.AlertStatusSuppressed, suppressedAlert.Status)
	assert.Equal(t, "Testing suppression", suppressedAlert.Metadata["suppression_reason"])
}

// TestAlertFiltering tests alert filtering and retrieval
func TestAlertFiltering(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create multiple alerts with different properties
	alerts := []*policy.Alert{
		{
			Type:     policy.AlertTypePolicyViolation,
			Severity: policy.AlertSeverityHigh,
			Title:    "Policy Violation Alert",
			Source:   "policy_engine",
			TenantID: "tenant1",
			Tags:     map[string]string{"env": "prod"},
		},
		{
			Type:     policy.AlertTypeSecurityIncident,
			Severity: policy.AlertSeverityCritical,
			Title:    "Security Incident Alert",
			Source:   "security_scanner",
			TenantID: "tenant2",
			Tags:     map[string]string{"env": "prod"},
		},
		{
			Type:     policy.AlertTypePerformanceDegraded,
			Severity: policy.AlertSeverityMedium,
			Title:    "Performance Issue",
			Source:   "monitoring",
			TenantID: "tenant1",
			Tags:     map[string]string{"env": "staging"},
		},
	}
	
	for _, alert := range alerts {
		err := manager.CreateAlert(alert)
		require.NoError(t, err)
	}
	
	// Test filtering by type
	policyAlerts, err := manager.GetAlertsByType(policy.AlertTypePolicyViolation)
	require.NoError(t, err)
	assert.Len(t, policyAlerts, 1)
	assert.Equal(t, "Policy Violation Alert", policyAlerts[0].Title)
	
	// Test filtering by severity
	criticalAlerts, err := manager.GetAlertsBySeverity(policy.AlertSeverityCritical)
	require.NoError(t, err)
	assert.Len(t, criticalAlerts, 1)
	assert.Equal(t, "Security Incident Alert", criticalAlerts[0].Title)
	
	// Test filtering by tenant
	tenant1Alerts, err := manager.GetAlertsByTenant("tenant1")
	require.NoError(t, err)
	assert.Len(t, tenant1Alerts, 2)
	
	// Test complex filtering
	filters := policy.AlertFilters{
		Types:      []policy.AlertType{policy.AlertTypePolicyViolation, policy.AlertTypeSecurityIncident},
		Severities: []policy.AlertSeverity{policy.AlertSeverityHigh, policy.AlertSeverityCritical},
		Tags:       map[string]string{"env": "prod"},
	}
	
	filteredAlerts, err := manager.ListAlerts(filters)
	require.NoError(t, err)
	assert.Len(t, filteredAlerts, 2)
	
	// Test pagination
	paginatedFilters := policy.AlertFilters{
		Limit:  1,
		Offset: 0,
	}
	
	paginatedAlerts, err := manager.ListAlerts(paginatedFilters)
	require.NoError(t, err)
	assert.Len(t, paginatedAlerts, 1)
	
	// Test search
	searchFilters := policy.AlertFilters{
		SearchQuery: "security",
	}
	
	searchResults, err := manager.ListAlerts(searchFilters)
	require.NoError(t, err)
	assert.Len(t, searchResults, 1)
	assert.Contains(t, searchResults[0].Title, "Security")
}

// TestAlertRules tests alert rules management
func TestAlertRules(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create an alert rule
	rule := &policy.AlertRule{
		Name:        "Test Alert Rule",
		Description: "A test alert rule",
		Enabled:     true,
		Type:        policy.AlertTypePolicyViolation,
		Severity:    policy.AlertSeverityHigh,
		Conditions: policy.AlertConditions{
			EventType:     "policy_violation",
			EventSeverity: "high",
		},
		EvaluationInterval: 1 * time.Minute,
		SuppressRepeats:    true,
		SuppressionWindow:  5 * time.Minute,
		AutoResolveTimeout: 24 * time.Hour,
		CreatedBy:          "test_user",
	}
	
	// Test rule creation
	err := manager.CreateAlertRule(rule)
	require.NoError(t, err)
	assert.NotEmpty(t, rule.ID)
	
	// Test rule retrieval
	retrievedRule, err := manager.GetAlertRule(rule.ID)
	require.NoError(t, err)
	assert.Equal(t, rule.Name, retrievedRule.Name)
	assert.Equal(t, rule.Type, retrievedRule.Type)
	
	// Test rule update
	rule.Name = "Updated Test Rule"
	err = manager.UpdateAlertRule(rule.ID, rule)
	require.NoError(t, err)
	
	updatedRule, err := manager.GetAlertRule(rule.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Test Rule", updatedRule.Name)
	
	// Test rule listing
	rules, err := manager.ListAlertRules()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rules), 1) // Should include our test rule plus default rules
	
	// Test rule disable/enable
	err = manager.DisableAlertRule(rule.ID)
	require.NoError(t, err)
	
	disabledRule, err := manager.GetAlertRule(rule.ID)
	require.NoError(t, err)
	assert.False(t, disabledRule.Enabled)
	
	err = manager.EnableAlertRule(rule.ID)
	require.NoError(t, err)
	
	enabledRule, err := manager.GetAlertRule(rule.ID)
	require.NoError(t, err)
	assert.True(t, enabledRule.Enabled)
	
	// Test rule deletion
	err = manager.DeleteAlertRule(rule.ID)
	require.NoError(t, err)
	
	_, err = manager.GetAlertRule(rule.ID)
	assert.Error(t, err)
}

// TestAggregationRules tests alert aggregation rules
func TestAggregationRules(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create an aggregation rule
	rule := &policy.AlertAggregationRule{
		Name:        "Test Aggregation Rule",
		Enabled:     true,
		GroupByFields: []string{"source", "type"},
		GroupByTags:   []string{"environment"},
		TimeWindow:    5 * time.Minute,
		MaxAlerts:     10,
		AggregateTitle: "Aggregated Alert: {{.Count}} similar alerts",
		AggregateDescription: "Multiple similar alerts have been aggregated",
		ApplyToTypes: []policy.AlertType{policy.AlertTypePolicyViolation},
		ApplyToSeverities: []policy.AlertSeverity{policy.AlertSeverityHigh},
	}
	
	// Test rule creation
	err := manager.CreateAggregationRule(rule)
	require.NoError(t, err)
	assert.NotEmpty(t, rule.ID)
	
	// Test rule retrieval
	rules, err := manager.ListAggregationRules()
	require.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, rule.Name, rules[0].Name)
	
	// Test rule update
	rule.Name = "Updated Aggregation Rule"
	err = manager.UpdateAggregationRule(rule.ID, rule)
	require.NoError(t, err)
	
	// Test rule deletion
	err = manager.DeleteAggregationRule(rule.ID)
	require.NoError(t, err)
	
	rules, err = manager.ListAggregationRules()
	require.NoError(t, err)
	assert.Len(t, rules, 0)
}

// TestSuppressionRules tests alert suppression rules
func TestSuppressionRules(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create a suppression rule
	suppression := &policy.AlertSuppression{
		Name:    "Test Suppression Rule",
		Enabled: true,
		AlertTypes: []policy.AlertType{policy.AlertTypePolicyViolation},
		AlertSeverities: []policy.AlertSeverity{policy.AlertSeverityLow},
		Sources: []string{"test_source"},
		Tags: map[string]string{
			"environment": "test",
		},
		Reason:    "Testing suppression rules",
		CreatedBy: "test_user",
	}
	
	// Test suppression creation
	err := manager.CreateSuppression(suppression)
	require.NoError(t, err)
	assert.NotEmpty(t, suppression.ID)
	
	// Test suppression retrieval
	suppressions, err := manager.ListSuppressions()
	require.NoError(t, err)
	assert.Len(t, suppressions, 1)
	assert.Equal(t, suppression.Name, suppressions[0].Name)
	
	// Test suppression update
	suppression.Name = "Updated Suppression Rule"
	err = manager.UpdateSuppression(suppression.ID, suppression)
	require.NoError(t, err)
	
	// Test suppression deletion
	err = manager.DeleteSuppression(suppression.ID)
	require.NoError(t, err)
	
	suppressions, err = manager.ListSuppressions()
	require.NoError(t, err)
	assert.Len(t, suppressions, 0)
}

// TestNotifications tests notification functionality
func TestNotifications(t *testing.T) {
	manager := createTestAlertManager(t)
	
	alert := createTestAlert()
	err := manager.CreateAlert(alert)
	require.NoError(t, err)
	
	// Test notification sending
	recipients := []string{"test@example.com", "admin@example.com"}
	err = manager.SendNotification(alert, policy.NotificationChannelEmail, recipients)
	require.NoError(t, err)
	
	// Test notification history
	history, err := manager.GetNotificationHistory(alert.ID)
	require.NoError(t, err)
	assert.Len(t, history, 1)
	assert.Equal(t, policy.NotificationChannelEmail, history[0].Channel)
	assert.Equal(t, "sent", history[0].Status)
	
	// Test notification channel testing
	config := policy.NotificationConfig{
		Channel:    policy.NotificationChannelWebhook,
		Enabled:    true,
		Recipients: []string{"https://example.com/webhook"},
	}
	
	err = manager.TestNotificationChannel(policy.NotificationChannelWebhook, config)
	require.NoError(t, err)
}

// TestMetricsAndStatistics tests metrics and statistics functionality
func TestMetricsAndStatistics(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create several test alerts
	alerts := []*policy.Alert{
		{
			Type:     policy.AlertTypePolicyViolation,
			Severity: policy.AlertSeverityHigh,
			Title:    "Alert 1",
			Source:   "source1",
		},
		{
			Type:     policy.AlertTypeSecurityIncident,
			Severity: policy.AlertSeverityCritical,
			Title:    "Alert 2",
			Source:   "source2",
		},
		{
			Type:     policy.AlertTypePolicyViolation,
			Severity: policy.AlertSeverityMedium,
			Title:    "Alert 3",
			Source:   "source1",
		},
	}
	
	for _, alert := range alerts {
		err := manager.CreateAlert(alert)
		require.NoError(t, err)
	}
	
	// Acknowledge and resolve some alerts
	err := manager.AcknowledgeAlert(alerts[0].ID, "test_user")
	require.NoError(t, err)
	
	err = manager.ResolveAlert(alerts[1].ID, "test_user", "Fixed")
	require.NoError(t, err)
	
	// Test metrics
	metrics, err := manager.GetAlertMetrics()
	require.NoError(t, err)
	assert.Equal(t, int64(3), metrics.TotalAlerts)
	assert.Equal(t, int64(1), metrics.ActiveAlerts)
	assert.Equal(t, int64(1), metrics.AcknowledgedAlerts)
	assert.Equal(t, int64(1), metrics.ResolvedAlerts)
	assert.Equal(t, int64(2), metrics.AlertsByType[policy.AlertTypePolicyViolation])
	assert.Equal(t, int64(1), metrics.AlertsByType[policy.AlertTypeSecurityIncident])
	
	// Test statistics
	stats, err := manager.GetAlertStatistics("hour")
	require.NoError(t, err)
	assert.Equal(t, "hour", stats.Period)
	assert.Equal(t, 3, stats.TotalAlerts)
	assert.Equal(t, 3, stats.NewAlerts)
	assert.Equal(t, 1, stats.ResolvedAlerts)
	assert.Equal(t, 2, stats.OngoingAlerts)
	
	// Test trends
	trends, err := manager.GetAlertTrends(1 * time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, trends["period"])
	assert.NotNil(t, trends["data_points"])
}

// TestRealTimeProcessing tests real-time processing functionality
func TestRealTimeProcessing(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Test starting real-time processing
	err := manager.StartRealTimeProcessing()
	require.NoError(t, err)
	
	status, err := manager.GetProcessingStatus()
	require.NoError(t, err)
	assert.True(t, status["is_processing"].(bool))
	
	// Test event processing
	event := &AlertEvent{
		Type:        "policy_violation",
		Source:      "test_source",
		Severity:    "high",
		Title:       "Test Event",
		Description: "This is a test event",
		Timestamp:   time.Now(),
		Tags: map[string]string{
			"environment": "test",
		},
		Metadata: map[string]interface{}{
			"test_field": "test_value",
		},
	}
	
	err = manager.ProcessEvent(event)
	require.NoError(t, err)
	
	// Wait for processing
	time.Sleep(100 * time.Millisecond)
	
	// Check if alert was created from the event
	alerts, err := manager.GetActiveAlerts()
	require.NoError(t, err)
	
	// Should have at least one alert created from the event
	var eventAlert *policy.Alert
	for _, alert := range alerts {
		if alert.Title == "Test Event" {
			eventAlert = alert
			break
		}
	}
	assert.NotNil(t, eventAlert, "Alert should have been created from the event")
	
	// Test stopping real-time processing
	err = manager.StopRealTimeProcessing()
	require.NoError(t, err)
	
	status, err = manager.GetProcessingStatus()
	require.NoError(t, err)
	assert.False(t, status["is_processing"].(bool))
}

// TestHealthAndMonitoring tests health monitoring functionality
func TestHealthAndMonitoring(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Test health check
	health := manager.GetHealth()
	assert.NotNil(t, health["status"])
	assert.NotNil(t, health["uptime"])
	assert.NotNil(t, health["queue_depth"])
	assert.NotNil(t, health["components"])
	
	// Test metrics
	metrics := manager.GetMetrics()
	assert.NotNil(t, metrics["total_alerts"])
	assert.NotNil(t, metrics["uptime"])
	assert.NotNil(t, metrics["queue_depth"])
}

// TestEscalation tests alert escalation functionality
func TestEscalation(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Create an alert rule with escalation
	rule := &policy.AlertRule{
		Name:              "Escalation Test Rule",
		Type:              policy.AlertTypeSecurityIncident,
		Severity:          policy.AlertSeverityCritical,
		Enabled:           true,
		EscalationEnabled: true,
		EscalationLevels: []policy.AlertEscalationLevel{
			{
				Level:             1,
				DelayFromPrevious: 1 * time.Minute,
				AutoEscalate:      true,
			},
			{
				Level:             2,
				DelayFromPrevious: 5 * time.Minute,
				AutoEscalate:      false,
			},
		},
		Conditions: policy.AlertConditions{
			EventType: "security_incident",
		},
	}
	
	err := manager.CreateAlertRule(rule)
	require.NoError(t, err)
	
	// Create an alert
	alert := &policy.Alert{
		Type:        policy.AlertTypeSecurityIncident,
		Severity:    policy.AlertSeverityCritical,
		Title:       "Escalation Test Alert",
		Description: "Test alert for escalation",
		Source:      "test_source",
	}
	
	err = manager.CreateAlert(alert)
	require.NoError(t, err)
	
	// Test manual escalation
	err = manager.EscalateAlert(alert.ID)
	require.NoError(t, err)
	
	escalatedAlert, err := manager.GetAlert(alert.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.AlertStatusEscalated, escalatedAlert.Status)
	assert.Equal(t, 1, escalatedAlert.EscalationLevel)
	assert.NotNil(t, escalatedAlert.EscalatedAt)
}

// TestShutdown tests graceful shutdown
func TestShutdown(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Start processing
	err := manager.StartRealTimeProcessing()
	require.NoError(t, err)
	
	// Test shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = manager.Shutdown(ctx)
	require.NoError(t, err)
	
	// Verify processing stopped
	status, err := manager.GetProcessingStatus()
	require.NoError(t, err)
	assert.False(t, status["is_processing"].(bool))
}

// TestErrorHandling tests various error conditions
func TestErrorHandling(t *testing.T) {
	manager := createTestAlertManager(t)
	
	// Test non-existent alert operations
	_, err := manager.GetAlert("non-existent-id")
	assert.Error(t, err)
	
	err = manager.UpdateAlert("non-existent-id", map[string]interface{}{})
	assert.Error(t, err)
	
	err = manager.AcknowledgeAlert("non-existent-id", "test_user")
	assert.Error(t, err)
	
	err = manager.ResolveAlert("non-existent-id", "test_user", "fixed")
	assert.Error(t, err)
	
	err = manager.EscalateAlert("non-existent-id")
	assert.Error(t, err)
	
	err = manager.SuppressAlert("non-existent-id", 1*time.Hour, "test")
	assert.Error(t, err)
	
	// Test non-existent rule operations
	_, err = manager.GetAlertRule("non-existent-id")
	assert.Error(t, err)
	
	err = manager.UpdateAlertRule("non-existent-id", &policy.AlertRule{})
	assert.Error(t, err)
	
	err = manager.DeleteAlertRule("non-existent-id")
	assert.Error(t, err)
	
	err = manager.EnableAlertRule("non-existent-id")
	assert.Error(t, err)
	
	err = manager.DisableAlertRule("non-existent-id")
	assert.Error(t, err)
	
	// Test invalid notification channel
	alert := createTestAlert()
	err = manager.CreateAlert(alert)
	require.NoError(t, err)
	
	err = manager.SendNotification(alert, policy.NotificationChannel("invalid"), []string{"test"})
	assert.Error(t, err)
	
	// Test double start/stop processing
	err = manager.StartRealTimeProcessing()
	require.NoError(t, err)
	
	err = manager.StartRealTimeProcessing()
	assert.Error(t, err, "Should not be able to start processing twice")
	
	err = manager.StopRealTimeProcessing()
	require.NoError(t, err)
	
	err = manager.StopRealTimeProcessing()
	assert.Error(t, err, "Should not be able to stop processing twice")
}

// Helper functions for tests

func createTestAlertManager(t *testing.T) *RealTimeAlertManager {
	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests
	
	config := &AlertManagerConfig{
		QueueSize:               1000,
		ProcessingWorkers:       2,
		MaxQueueDepth:          500,
		EventProcessingTimeout: 5 * time.Second,
		RuleEvaluationTimeout:  2 * time.Second,
		NotificationTimeout:    10 * time.Second,
		EscalationCheckInterval: 1 * time.Second,
		DefaultEscalationDelay: 5 * time.Second,
		MaxEscalationLevel:     3,
		CleanupInterval:        10 * time.Second,
		ResolvedAlertRetention: 1 * time.Hour,
		MetricsUpdateInterval:  5 * time.Second,
		StatisticsRetention:    24 * time.Hour,
		NotificationRateLimit:  10,
		NotificationRatePeriod: 1 * time.Minute,
		EnableAggregation:      true,
		EnableSuppression:      true,
		EnableEscalation:       true,
		EnableNotifications:    true,
	}
	
	manager, err := NewRealTimeAlertManager(config, logger, nil)
	require.NoError(t, err)
	
	return manager
}

func createTestAlert() *policy.Alert {
	return &policy.Alert{
		Type:        policy.AlertTypePolicyViolation,
		Severity:    policy.AlertSeverityHigh,
		Title:       "Test Alert",
		Description: "This is a test alert",
		Source:      "test_source",
		Tags: map[string]string{
			"environment": "test",
			"component":   "test_component",
		},
		Metadata: map[string]interface{}{
			"test_field": "test_value",
			"number":     42,
		},
		TenantID: "test_tenant",
		PolicyID: "test_policy",
	}
}

// Benchmark tests for performance validation

func BenchmarkCreateAlert(b *testing.B) {
	manager := createBenchmarkAlertManager(b)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alert := createTestAlert()
		alert.Title = fmt.Sprintf("Benchmark Alert %d", i)
		err := manager.CreateAlert(alert)
		if err != nil {
			b.Fatalf("Failed to create alert: %v", err)
		}
	}
}

func BenchmarkListAlerts(b *testing.B) {
	manager := createBenchmarkAlertManager(b)
	
	// Create some alerts first
	for i := 0; i < 1000; i++ {
		alert := createTestAlert()
		alert.Title = fmt.Sprintf("Benchmark Alert %d", i)
		manager.CreateAlert(alert)
	}
	
	filters := policy.AlertFilters{
		Limit: 100,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ListAlerts(filters)
		if err != nil {
			b.Fatalf("Failed to list alerts: %v", err)
		}
	}
}

func BenchmarkProcessEvent(b *testing.B) {
	manager := createBenchmarkAlertManager(b)
	
	err := manager.StartRealTimeProcessing()
	if err != nil {
		b.Fatalf("Failed to start processing: %v", err)
	}
	defer manager.StopRealTimeProcessing()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &AlertEvent{
			Type:        "policy_violation",
			Source:      "benchmark_source",
			Severity:    "high",
			Title:       fmt.Sprintf("Benchmark Event %d", i),
			Description: "Benchmark event description",
			Timestamp:   time.Now(),
		}
		
		err := manager.ProcessEvent(event)
		if err != nil {
			b.Fatalf("Failed to process event: %v", err)
		}
	}
}

func createBenchmarkAlertManager(b *testing.B) *RealTimeAlertManager {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Minimal logging for benchmarks
	
	config := &AlertManagerConfig{
		QueueSize:         10000,
		ProcessingWorkers: 4,
		MaxQueueDepth:     5000,
	}
	
	manager, err := NewRealTimeAlertManager(config, logger, nil)
	if err != nil {
		b.Fatalf("Failed to create alert manager: %v", err)
	}
	
	return manager
} 