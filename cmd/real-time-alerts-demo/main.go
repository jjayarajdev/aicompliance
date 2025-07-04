package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"ai-gateway-poc/internal/monitoring"
	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("🚨 AI Gateway Real-Time Alert System Demo")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Initialize logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create alert manager
	config := &monitoring.AlertManagerConfig{
		QueueSize:               10000,
		ProcessingWorkers:       3,
		MaxQueueDepth:          5000,
		EventProcessingTimeout: 30 * time.Second,
		RuleEvaluationTimeout:  10 * time.Second,
		NotificationTimeout:    60 * time.Second,
		EscalationCheckInterval: 1 * time.Minute,
		DefaultEscalationDelay: 5 * time.Minute,
		MaxEscalationLevel:     3,
		CleanupInterval:        10 * time.Minute,
		ResolvedAlertRetention: 24 * time.Hour,
		MetricsUpdateInterval:  30 * time.Second,
		StatisticsRetention:    7 * 24 * time.Hour,
		NotificationRateLimit:  100,
		NotificationRatePeriod: 1 * time.Hour,
		EnableAggregation:      true,
		EnableSuppression:      true,
		EnableEscalation:       true,
		EnableNotifications:    true,
	}

	alertManager, err := monitoring.NewRealTimeAlertManager(config, logger, nil)
	if err != nil {
		fmt.Printf("❌ Failed to create alert manager: %v\n", err)
		os.Exit(1)
	}

	// Start real-time processing
	if err := alertManager.StartRealTimeProcessing(); err != nil {
		fmt.Printf("❌ Failed to start real-time processing: %v\n", err)
		os.Exit(1)
	}
	defer alertManager.StopRealTimeProcessing()

	// Run demo sections
	fmt.Println("🎯 Demo Overview:")
	fmt.Println("  1. Alert Management & Lifecycle")
	fmt.Println("  2. Alert Rules & Configuration")
	fmt.Println("  3. Real-Time Event Processing")
	fmt.Println("  4. Alert Escalation & Suppression")
	fmt.Println("  5. Notification System")
	fmt.Println("  6. Analytics & Reporting")
	fmt.Println("  7. Health Monitoring")
	fmt.Println()

	runAlertManagementDemo(alertManager)
	runAlertRulesDemo(alertManager)
	runRealTimeProcessingDemo(alertManager)
	runEscalationSuppressionDemo(alertManager)
	runNotificationDemo(alertManager)
	runAnalyticsDemo(alertManager)
	runHealthMonitoringDemo(alertManager)

	// Final summary
	fmt.Println("📊 Final System Summary")
	fmt.Println(strings.Repeat("-", 40))
	
	metrics, _ := alertManager.GetAlertMetrics()
	status, _ := alertManager.GetProcessingStatus()
	
	fmt.Printf("  Total Alerts Created: %d\n", metrics.TotalAlerts)
	fmt.Printf("  Active Alerts: %d\n", metrics.ActiveAlerts)
	fmt.Printf("  Resolved Alerts: %d\n", metrics.ResolvedAlerts)
	fmt.Printf("  Processing Queue Depth: %v\n", status["queue_depth"])
	fmt.Printf("  System Uptime: %v\n", status["uptime"])
	fmt.Println()

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	if err := alertManager.Shutdown(ctx); err != nil {
		fmt.Printf("⚠️ Shutdown error: %v\n", err)
	} else {
		fmt.Println("✅ Alert system shut down gracefully")
	}
}

func runAlertManagementDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("🎯 Demo 1: Alert Management & Lifecycle")
	fmt.Println(strings.Repeat("-", 45))

	// Create different types of alerts
	alerts := []*policy.Alert{
		{
			Type:        policy.AlertTypePolicyViolation,
			Severity:    policy.AlertSeverityHigh,
			Title:       "Unauthorized Data Access Attempt",
			Description: "Multiple failed attempts to access protected customer data detected",
			Source:      "policy_engine",
			Tags: map[string]string{
				"environment": "production",
				"component":   "data_access_controller",
				"risk_level":  "high",
			},
			TenantID: "tenant_healthcare",
			PolicyID: "data_protection_policy_001",
		},
		{
			Type:        policy.AlertTypeSecurityIncident,
			Severity:    policy.AlertSeverityCritical,
			Title:       "Potential Data Breach - Suspicious API Activity",
			Description: "Anomalous API usage patterns detected suggesting potential data exfiltration",
			Source:      "security_monitor",
			Tags: map[string]string{
				"environment": "production",
				"component":   "api_gateway",
				"severity":    "critical",
			},
			TenantID: "tenant_finance",
		},
		{
			Type:        policy.AlertTypePerformanceDegraded,
			Severity:    policy.AlertSeverityMedium,
			Title:       "AI Model Response Time Degradation",
			Description: "Response time for GPT-4 model requests has increased by 200%",
			Source:      "performance_monitor",
			Tags: map[string]string{
				"environment": "production",
				"provider":    "openai",
				"model":       "gpt-4",
			},
			TenantID: "tenant_retail",
		},
	}

	fmt.Printf("📝 Creating %d demonstration alerts...\n", len(alerts))
	for i, alert := range alerts {
		if err := alertManager.CreateAlert(alert); err != nil {
			fmt.Printf("  ❌ Failed to create alert %d: %v\n", i+1, err)
		} else {
			fmt.Printf("  ✅ Alert %d created: %s [%s]\n", i+1, alert.Title, alert.Severity)
		}
	}
	fmt.Println()

	// Demonstrate alert lifecycle operations
	if len(alerts) > 0 {
		firstAlert := alerts[0]
		
		fmt.Printf("🔄 Demonstrating alert lifecycle for: %s\n", firstAlert.Title)
		
		// Acknowledge alert
		if err := alertManager.AcknowledgeAlert(firstAlert.ID, "security_analyst_john"); err != nil {
			fmt.Printf("  ❌ Failed to acknowledge: %v\n", err)
		} else {
			fmt.Printf("  ✅ Alert acknowledged by security_analyst_john\n")
		}
		
		// Update alert
		updates := map[string]interface{}{
			"assigned_to": "incident_response_team",
			"tags": map[string]string{
				"environment": "production",
				"component":   "data_access_controller",
				"risk_level":  "high",
				"assigned":    "true",
			},
		}
		if err := alertManager.UpdateAlert(firstAlert.ID, updates); err != nil {
			fmt.Printf("  ❌ Failed to update: %v\n", err)
		} else {
			fmt.Printf("  ✅ Alert assigned to incident_response_team\n")
		}
		
		// Simulate investigation time
		time.Sleep(500 * time.Millisecond)
		
		// Resolve alert
		if err := alertManager.ResolveAlert(firstAlert.ID, "incident_response_team", "False positive - legitimate admin access during maintenance window"); err != nil {
			fmt.Printf("  ❌ Failed to resolve: %v\n", err)
		} else {
			fmt.Printf("  ✅ Alert resolved by incident_response_team\n")
		}
		
		// Get updated alert
		if updatedAlert, err := alertManager.GetAlert(firstAlert.ID); err != nil {
			fmt.Printf("  ❌ Failed to retrieve updated alert: %v\n", err)
		} else {
			fmt.Printf("  📊 Alert Status: %s | Resolution Time: %v\n", 
				updatedAlert.Status, 
				updatedAlert.ResolvedAt.Sub(updatedAlert.CreatedAt).Round(time.Second))
		}
	}
	fmt.Println()
}

func runAlertRulesDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("⚙️ Demo 2: Alert Rules & Configuration")
	fmt.Println(strings.Repeat("-", 40))

	// Create advanced alert rules
	rules := []*policy.AlertRule{
		{
			Name:        "High-Frequency API Violations",
			Description: "Detects rapid succession of policy violations from same source",
			Enabled:     true,
			Type:        policy.AlertTypePolicyViolation,
			Severity:    policy.AlertSeverityHigh,
			Conditions: policy.AlertConditions{
				EventType:      "policy_violation",
				MinOccurrences: 5,
				TimeWindow:     2 * time.Minute,
			},
			EvaluationInterval: 30 * time.Second,
			SuppressRepeats:    true,
			SuppressionWindow:  10 * time.Minute,
			AutoResolveTimeout: 1 * time.Hour,
			EscalationEnabled:  true,
			EscalationLevels: []policy.AlertEscalationLevel{
				{
					Level:             1,
					DelayFromPrevious: 5 * time.Minute,
					AutoEscalate:      true,
					EscalationMessage: "High-frequency violations require immediate attention",
				},
				{
					Level:             2,
					DelayFromPrevious: 15 * time.Minute,
					AutoEscalate:      false,
					EscalationMessage: "Critical: Escalated to security operations center",
				},
			},
			NotificationChannels: []policy.NotificationConfig{
				{
					Channel:    policy.NotificationChannelEmail,
					Enabled:    true,
					Recipients: []string{"security-team@company.com", "soc@company.com"},
					SeverityFilter: []policy.AlertSeverity{
						policy.AlertSeverityHigh, 
						policy.AlertSeverityCritical,
					},
				},
				{
					Channel:    policy.NotificationChannelWebhook,
					Enabled:    true,
					Recipients: []string{"https://company.slack.com/hooks/security-alerts"},
				},
			},
		},
		{
			Name:        "Anomalous Authentication Patterns",
			Description: "Detects unusual authentication behaviors and potential account compromise",
			Enabled:     true,
			Type:        policy.AlertTypeSecurityIncident,
			Severity:    policy.AlertSeverityCritical,
			Conditions: policy.AlertConditions{
				EventType:     "auth_failure",
				EventSeverity: "high",
				CustomCondition: "source_ip not in whitelist AND failure_count > 10",
			},
			EvaluationInterval: 1 * time.Minute,
			SuppressRepeats:    false,
			AutoResolveTimeout: 4 * time.Hour,
			EscalationEnabled:  true,
			EscalationLevels: []policy.AlertEscalationLevel{
				{
					Level:                  1,
					DelayFromPrevious:      2 * time.Minute,
					RequiredAcknowledgment: true,
					AutoEscalate:          true,
				},
			},
		},
	}

	fmt.Printf("📋 Creating %d advanced alert rules...\n", len(rules))
	for i, rule := range rules {
		if err := alertManager.CreateAlertRule(rule); err != nil {
			fmt.Printf("  ❌ Failed to create rule %d: %v\n", i+1, err)
		} else {
			fmt.Printf("  ✅ Rule created: %s\n", rule.Name)
			fmt.Printf("     Type: %s | Severity: %s | Escalation: %v\n", 
				rule.Type, rule.Severity, rule.EscalationEnabled)
		}
	}
	fmt.Println()

	// List all rules
	allRules, err := alertManager.ListAlertRules()
	if err != nil {
		fmt.Printf("❌ Failed to list rules: %v\n", err)
	} else {
		fmt.Printf("📊 Total Alert Rules: %d\n", len(allRules))
		fmt.Printf("  Active Rules: %d\n", countEnabledRules(allRules))
		fmt.Printf("  Rules with Escalation: %d\n", countEscalationRules(allRules))
		fmt.Printf("  Rules with Notifications: %d\n", countNotificationRules(allRules))
	}
	fmt.Println()
}

func runRealTimeProcessingDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("⚡ Demo 3: Real-Time Event Processing")
	fmt.Println(strings.Repeat("-", 40))

	// Simulate various types of events
	events := []*monitoring.AlertEvent{
		{
			Type:        "policy_violation",
			Source:      "api_gateway",
			Severity:    "high",
			Title:       "PII Data Access Without Consent",
			Description: "Attempted access to PII data without proper user consent",
			Timestamp:   time.Now(),
			Tags: map[string]string{
				"environment": "production",
				"endpoint":    "/customer/personal-info",
				"method":      "GET",
			},
			Metadata: map[string]interface{}{
				"user_id":     "user_12345",
				"request_id":  "req_abcdef123",
				"pii_fields":  []string{"ssn", "email", "phone"},
				"consent_status": "missing",
			},
			TenantID: "tenant_healthcare",
		},
		{
			Type:        "security_incident",
			Source:      "intrusion_detection",
			Severity:    "critical",
			Title:       "SQL Injection Attack Detected",
			Description: "Malicious SQL injection attempt blocked by WAF",
			Timestamp:   time.Now(),
			Tags: map[string]string{
				"environment": "production",
				"attack_type": "sql_injection",
				"blocked":     "true",
			},
			Metadata: map[string]interface{}{
				"source_ip":    "192.168.1.100",
				"target_endpoint": "/api/users",
				"payload_size": 1024,
				"waf_rule_id": "sql_injection_001",
			},
			TenantID: "tenant_finance",
		},
		{
			Type:        "performance_degraded",
			Source:      "monitoring_system",
			Severity:    "medium",
			Title:       "Model Inference Latency Spike",
			Description: "AI model inference time exceeded SLA thresholds",
			Timestamp:   time.Now(),
			Tags: map[string]string{
				"environment": "production",
				"provider":    "anthropic",
				"model":       "claude-3",
			},
			Metadata: map[string]interface{}{
				"avg_latency_ms": 2500,
				"sla_threshold_ms": 1000,
				"requests_affected": 150,
				"percentile_p95": 3200,
			},
			TenantID: "tenant_retail",
		},
	}

	fmt.Printf("🔄 Processing %d real-time events...\n", len(events))
	
	// Get initial status
	initialStatus, _ := alertManager.GetProcessingStatus()
	fmt.Printf("  Initial Queue Depth: %v\n", initialStatus["queue_depth"])
	
	// Process events
	for i, event := range events {
		if err := alertManager.ProcessEvent(event); err != nil {
			fmt.Printf("  ❌ Failed to process event %d: %v\n", i+1, err)
		} else {
			fmt.Printf("  ✅ Event %d queued: %s\n", i+1, event.Title)
		}
	}
	
	// Wait for processing
	fmt.Printf("⏱️ Waiting for event processing...\n")
	time.Sleep(2 * time.Second)
	
	// Check results
	finalStatus, _ := alertManager.GetProcessingStatus()
	activeAlerts, _ := alertManager.GetActiveAlerts()
	
	fmt.Printf("  Final Queue Depth: %v\n", finalStatus["queue_depth"])
	fmt.Printf("  Alerts Generated: %d\n", len(activeAlerts))
	
	// Show generated alerts
	if len(activeAlerts) > 0 {
		fmt.Printf("  🚨 Generated Alerts:\n")
		for i, alert := range activeAlerts {
			if i < 3 { // Show first 3
				fmt.Printf("     %d. %s [%s] - %s\n", 
					i+1, alert.Title, alert.Severity, alert.Source)
			}
		}
	}
	fmt.Println()
}

func runEscalationSuppressionDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("🔺 Demo 4: Alert Escalation & Suppression")
	fmt.Println(strings.Repeat("-", 45))

	// Create a test alert for escalation
	escalationAlert := &policy.Alert{
		Type:        policy.AlertTypeSecurityIncident,
		Severity:    policy.AlertSeverityCritical,
		Title:       "Persistent Authentication Failures",
		Description: "Multiple failed authentication attempts from same source IP",
		Source:      "auth_service",
		Tags: map[string]string{
			"environment": "production",
			"source_ip":   "192.168.1.50",
			"attack_type": "brute_force",
		},
		TenantID: "tenant_security_test",
	}

	if err := alertManager.CreateAlert(escalationAlert); err != nil {
		fmt.Printf("❌ Failed to create escalation test alert: %v\n", err)
	} else {
		fmt.Printf("🔺 Created escalation test alert: %s\n", escalationAlert.Title)
		
		// Manually escalate
		if err := alertManager.EscalateAlert(escalationAlert.ID); err != nil {
			fmt.Printf("  ❌ Failed to escalate: %v\n", err)
		} else {
			fmt.Printf("  ✅ Alert escalated to Level 1\n")
			
			// Check escalation status
			if escalatedAlert, err := alertManager.GetAlert(escalationAlert.ID); err == nil {
				fmt.Printf("  📊 Current Escalation Level: %d\n", escalatedAlert.EscalationLevel)
				fmt.Printf("  📊 Status: %s\n", escalatedAlert.Status)
			}
		}
	}
	fmt.Println()

	// Create suppression rules
	suppression := &policy.AlertSuppression{
		Name:    "Maintenance Window Suppression",
		Enabled: true,
		AlertTypes: []policy.AlertType{
			policy.AlertTypePerformanceDegraded,
			policy.AlertTypeSystemError,
		},
		AlertSeverities: []policy.AlertSeverity{
			policy.AlertSeverityLow,
			policy.AlertSeverityMedium,
		},
		Tags: map[string]string{
			"environment": "staging",
		},
		Reason:    "Scheduled maintenance window - suppress non-critical alerts",
		CreatedBy: "ops_team",
	}

	if err := alertManager.CreateSuppression(suppression); err != nil {
		fmt.Printf("❌ Failed to create suppression rule: %v\n", err)
	} else {
		fmt.Printf("🔇 Created suppression rule: %s\n", suppression.Name)
		fmt.Printf("  Applies to: %v\n", suppression.AlertTypes)
		fmt.Printf("  Severities: %v\n", suppression.AlertSeverities)
		fmt.Printf("  Reason: %s\n", suppression.Reason)
	}

	// Test suppression with a new alert
	suppressedAlert := &policy.Alert{
		Type:        policy.AlertTypePerformanceDegraded,
		Severity:    policy.AlertSeverityLow,
		Title:       "Staging Environment Slow Response",
		Description: "Response time slightly elevated in staging",
		Source:      "staging_monitor",
		Tags: map[string]string{
			"environment": "staging",
			"component":   "api_server",
		},
	}

	if err := alertManager.CreateAlert(suppressedAlert); err != nil {
		fmt.Printf("❌ Failed to create test suppressed alert: %v\n", err)
	} else {
		fmt.Printf("🔇 Created potentially suppressed alert: %s\n", suppressedAlert.Title)
		
		// Check if it was suppressed
		if retrievedAlert, err := alertManager.GetAlert(suppressedAlert.ID); err == nil {
			if retrievedAlert.Status == policy.AlertStatusSuppressed {
				fmt.Printf("  ✅ Alert automatically suppressed by rule\n")
			} else {
				fmt.Printf("  ℹ️ Alert not suppressed (Status: %s)\n", retrievedAlert.Status)
			}
		}
	}
	fmt.Println()
}

func runNotificationDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("📧 Demo 5: Notification System")
	fmt.Println(strings.Repeat("-", 35))

	// Create an alert for notification testing
	notificationAlert := &policy.Alert{
		Type:        policy.AlertTypeSecurityIncident,
		Severity:    policy.AlertSeverityCritical,
		Title:       "Critical Security Breach - Immediate Action Required",
		Description: "Unauthorized access detected to sensitive customer database",
		Source:      "security_monitor",
		Tags: map[string]string{
			"environment": "production",
			"database":    "customer_pii",
			"urgency":     "immediate",
		},
		TenantID: "tenant_enterprise",
	}

	if err := alertManager.CreateAlert(notificationAlert); err != nil {
		fmt.Printf("❌ Failed to create notification test alert: %v\n", err)
		return
	}

	fmt.Printf("📧 Created notification test alert: %s\n", notificationAlert.Title)

	// Test different notification channels
	channels := []struct {
		channel    policy.NotificationChannel
		recipients []string
		name       string
	}{
		{
			channel:    policy.NotificationChannelEmail,
			recipients: []string{"security-team@company.com", "soc@company.com", "ciso@company.com"},
			name:       "Email",
		},
		{
			channel:    policy.NotificationChannelWebhook,
			recipients: []string{"https://hooks.slack.com/services/security-alerts"},
			name:       "Slack Webhook",
		},
		{
			channel:    policy.NotificationChannelSMS,
			recipients: []string{"+1-555-0123", "+1-555-0124"},
			name:       "SMS",
		},
	}

	fmt.Printf("📤 Testing notification channels...\n")
	for _, ch := range channels {
		err := alertManager.SendNotification(notificationAlert, ch.channel, ch.recipients)
		if err != nil {
			fmt.Printf("  ❌ %s notification failed: %v\n", ch.name, err)
		} else {
			fmt.Printf("  ✅ %s notification sent to %d recipients\n", ch.name, len(ch.recipients))
		}
	}

	// Check notification history
	history, err := alertManager.GetNotificationHistory(notificationAlert.ID)
	if err != nil {
		fmt.Printf("❌ Failed to get notification history: %v\n", err)
	} else {
		fmt.Printf("📊 Notification History: %d notifications sent\n", len(history))
		for i, record := range history {
			fmt.Printf("  %d. %s to %s - Status: %s\n", 
				i+1, record.Channel, record.Recipient, record.Status)
		}
	}
	fmt.Println()
}

func runAnalyticsDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("📊 Demo 6: Analytics & Reporting")
	fmt.Println(strings.Repeat("-", 35))

	// Get current metrics
	metrics, err := alertManager.GetAlertMetrics()
	if err != nil {
		fmt.Printf("❌ Failed to get metrics: %v\n", err)
		return
	}

	fmt.Printf("📈 Current Alert Metrics:\n")
	fmt.Printf("  Total Alerts: %d\n", metrics.TotalAlerts)
	fmt.Printf("  Active Alerts: %d\n", metrics.ActiveAlerts)
	fmt.Printf("  Resolved Alerts: %d\n", metrics.ResolvedAlerts)
	fmt.Printf("  Acknowledged Alerts: %d\n", metrics.AcknowledgedAlerts)
	fmt.Printf("  Escalated Alerts: %d\n", metrics.EscalatedAlerts)
	fmt.Printf("  Suppressed Alerts: %d\n", metrics.SuppressedAlerts)
	fmt.Println()

	// Alert distribution by severity
	fmt.Printf("🔥 Alerts by Severity:\n")
	for severity, count := range metrics.AlertsBySeverity {
		fmt.Printf("  %s: %d\n", severity, count)
	}
	fmt.Println()

	// Alert distribution by type
	fmt.Printf("📋 Alerts by Type:\n")
	for alertType, count := range metrics.AlertsByType {
		fmt.Printf("  %s: %d\n", alertType, count)
	}
	fmt.Println()

	// Get detailed statistics
	stats, err := alertManager.GetAlertStatistics("hour")
	if err != nil {
		fmt.Printf("❌ Failed to get statistics: %v\n", err)
	} else {
		fmt.Printf("📊 Hourly Statistics:\n")
		fmt.Printf("  New Alerts: %d\n", stats.NewAlerts)
		fmt.Printf("  Resolved Alerts: %d\n", stats.ResolvedAlerts)
		fmt.Printf("  Ongoing Alerts: %d\n", stats.OngoingAlerts)
		fmt.Printf("  Average Acknowledgment Time: %v\n", stats.AverageAckTime)
		fmt.Printf("  Average Resolution Time: %v\n", stats.AverageResolutionTime)
		fmt.Printf("  Alert Trend: %s (%.1f%%)\n", stats.AlertTrend, stats.TrendPercentage)
	}
	fmt.Println()

	// Get trends
	trends, err := alertManager.GetAlertTrends(2 * time.Hour)
	if err != nil {
		fmt.Printf("❌ Failed to get trends: %v\n", err)
	} else {
		fmt.Printf("📈 Alert Trends (Last 2 Hours):\n")
		fmt.Printf("  Period: %s\n", trends["period"])
		dataPoints := trends["data_points"].([]map[string]interface{})
		if len(dataPoints) > 0 {
			latest := dataPoints[len(dataPoints)-1]
			fmt.Printf("  Latest Hour: %d total alerts\n", latest["total_alerts"])
			fmt.Printf("  Critical: %d | High: %d | Medium: %d | Low: %d\n",
				latest["critical_alerts"], latest["high_alerts"],
				latest["medium_alerts"], latest["low_alerts"])
		}
	}
	fmt.Println()
}

func runHealthMonitoringDemo(alertManager *monitoring.RealTimeAlertManager) {
	fmt.Println("🏥 Demo 7: Health Monitoring")
	fmt.Println(strings.Repeat("-", 35))

	// Get system health
	health := alertManager.GetHealth()
	fmt.Printf("🩺 System Health Status: %s\n", health["status"])
	fmt.Printf("  Uptime: %v\n", health["uptime"])
	fmt.Printf("  Processing Status: %v\n", health["is_processing"])
	fmt.Printf("  Queue Depth: %v\n", health["queue_depth"])
	fmt.Printf("  Queue Utilization: %.1f%%\n", health["queue_utilization"])
	fmt.Printf("  Processing Errors: %v\n", health["processing_errors"])
	fmt.Println()

	// Component health
	if components, ok := health["components"].(map[string]interface{}); ok {
		fmt.Printf("🔧 Component Health:\n")
		for name, component := range components {
			if comp, ok := component.(map[string]interface{}); ok {
				fmt.Printf("  %s: %s\n", name, comp["status"])
			}
		}
	}
	fmt.Println()

	// Get detailed metrics
	metrics := alertManager.GetMetrics()
	fmt.Printf("📊 Performance Metrics:\n")
	fmt.Printf("  Total Alerts: %v\n", metrics["total_alerts"])
	fmt.Printf("  Alert Rules: %v\n", metrics["alert_rules"])
	fmt.Printf("  Aggregation Rules: %v\n", metrics["aggregation_rules"])
	fmt.Printf("  Suppressions: %v\n", metrics["suppressions"])
	fmt.Printf("  Notification Providers: %v\n", metrics["notification_providers"])
	fmt.Println()

	// Processing status
	status, err := alertManager.GetProcessingStatus()
	if err != nil {
		fmt.Printf("❌ Failed to get processing status: %v\n", err)
	} else {
		fmt.Printf("⚡ Processing Status:\n")
		fmt.Printf("  Worker Count: %v\n", status["worker_count"])
		fmt.Printf("  Queue Capacity: %v\n", status["queue_capacity"])
		fmt.Printf("  Last Processed Event: %v\n", status["last_processed_event"])
	}
	fmt.Println()
}

// Helper functions

func countEnabledRules(rules []*policy.AlertRule) int {
	count := 0
	for _, rule := range rules {
		if rule.Enabled {
			count++
		}
	}
	return count
}

func countEscalationRules(rules []*policy.AlertRule) int {
	count := 0
	for _, rule := range rules {
		if rule.EscalationEnabled {
			count++
		}
	}
	return count
}

func countNotificationRules(rules []*policy.AlertRule) int {
	count := 0
	for _, rule := range rules {
		if len(rule.NotificationChannels) > 0 {
			count++
		}
	}
	return count
} 