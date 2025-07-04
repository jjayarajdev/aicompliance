package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"ai-gateway-poc/internal/policy"
)

// ===== REAL-TIME ALERT MANAGER =====

// RealTimeAlertManager implements the AlertManager interface
type RealTimeAlertManager struct {
	// Core components
	alerts              map[string]*policy.Alert
	alertRules          map[string]*policy.AlertRule
	aggregationRules    map[string]*policy.AlertAggregationRule
	suppressions        map[string]*policy.AlertSuppression
	notificationProviders map[policy.NotificationChannel]policy.NotificationProvider
	
	// Processing components
	eventQueue          chan *AlertEvent
	processingWorkers   int
	workerCtx           context.Context
	workerCancel        context.CancelFunc
	
	// State management
	isProcessing        bool
	metrics             *policy.AlertMetrics
	statistics          map[string]*policy.AlertStatistics
	
	// Synchronization
	mu                  sync.RWMutex
	eventMu             sync.Mutex
	
	// Configuration
	config              *AlertManagerConfig
	logger              *logrus.Logger
	auditLogger         *AuditLogger
	
	// Background processing
	escalationTicker    *time.Ticker
	cleanupTicker       *time.Ticker
	metricsTicker       *time.Ticker
	
	// Performance tracking
	startTime           time.Time
	lastProcessedEvent  time.Time
	queueDepth          int
	processingErrors    int64
}

// AlertManagerConfig contains configuration for the alert manager
type AlertManagerConfig struct {
	// Queue configuration
	QueueSize             int           `json:"queue_size"`
	ProcessingWorkers     int           `json:"processing_workers"`
	MaxQueueDepth         int           `json:"max_queue_depth"`
	
	// Processing timeouts
	EventProcessingTimeout time.Duration `json:"event_processing_timeout"`
	RuleEvaluationTimeout  time.Duration `json:"rule_evaluation_timeout"`
	NotificationTimeout    time.Duration `json:"notification_timeout"`
	
	// Escalation configuration
	EscalationCheckInterval time.Duration `json:"escalation_check_interval"`
	DefaultEscalationDelay  time.Duration `json:"default_escalation_delay"`
	MaxEscalationLevel      int           `json:"max_escalation_level"`
	
	// Cleanup configuration
	CleanupInterval         time.Duration `json:"cleanup_interval"`
	ResolvedAlertRetention  time.Duration `json:"resolved_alert_retention"`
	
	// Metrics configuration
	MetricsUpdateInterval   time.Duration `json:"metrics_update_interval"`
	StatisticsRetention     time.Duration `json:"statistics_retention"`
	
	// Rate limiting
	NotificationRateLimit   int           `json:"notification_rate_limit"`
	NotificationRatePeriod  time.Duration `json:"notification_rate_period"`
	
	// Performance settings
	EnableAggregation       bool          `json:"enable_aggregation"`
	EnableSuppression       bool          `json:"enable_suppression"`
	EnableEscalation        bool          `json:"enable_escalation"`
	EnableNotifications     bool          `json:"enable_notifications"`
}

// AlertEvent represents an event that may trigger alerts
type AlertEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Tags        map[string]string      `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	TenantID    string                 `json:"tenant_id,omitempty"`
	PolicyID    string                 `json:"policy_id,omitempty"`
}

// NewRealTimeAlertManager creates a new real-time alert manager
func NewRealTimeAlertManager(config *AlertManagerConfig, logger *logrus.Logger, auditLogger *AuditLogger) (*RealTimeAlertManager, error) {
	if config == nil {
		config = getDefaultAlertManagerConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	manager := &RealTimeAlertManager{
		alerts:                make(map[string]*policy.Alert),
		alertRules:            make(map[string]*policy.AlertRule),
		aggregationRules:      make(map[string]*policy.AlertAggregationRule),
		suppressions:          make(map[string]*policy.AlertSuppression),
		notificationProviders: make(map[policy.NotificationChannel]policy.NotificationProvider),
		eventQueue:            make(chan *AlertEvent, config.QueueSize),
		processingWorkers:     config.ProcessingWorkers,
		config:                config,
		logger:                logger,
		auditLogger:           auditLogger,
		statistics:            make(map[string]*policy.AlertStatistics),
		startTime:             time.Now(),
		metrics:               initializeAlertMetrics(),
	}
	
	// Initialize notification providers
	if err := manager.initializeNotificationProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize notification providers: %w", err)
	}
	
	// Initialize default alert rules
	if err := manager.initializeDefaultRules(); err != nil {
		return nil, fmt.Errorf("failed to initialize default rules: %w", err)
	}
	
	manager.logger.Info("Real-time alert manager initialized successfully")
	return manager, nil
}

// getDefaultAlertManagerConfig returns default configuration
func getDefaultAlertManagerConfig() *AlertManagerConfig {
	return &AlertManagerConfig{
		QueueSize:               10000,
		ProcessingWorkers:       5,
		MaxQueueDepth:          5000,
		EventProcessingTimeout: 30 * time.Second,
		RuleEvaluationTimeout:  10 * time.Second,
		NotificationTimeout:    60 * time.Second,
		EscalationCheckInterval: 5 * time.Minute,
		DefaultEscalationDelay: 15 * time.Minute,
		MaxEscalationLevel:     3,
		CleanupInterval:        1 * time.Hour,
		ResolvedAlertRetention: 7 * 24 * time.Hour,
		MetricsUpdateInterval:  1 * time.Minute,
		StatisticsRetention:    30 * 24 * time.Hour,
		NotificationRateLimit:  100,
		NotificationRatePeriod: 1 * time.Hour,
		EnableAggregation:      true,
		EnableSuppression:      true,
		EnableEscalation:       true,
		EnableNotifications:    true,
	}
}

// initializeAlertMetrics initializes alert metrics
func initializeAlertMetrics() *policy.AlertMetrics {
	return &policy.AlertMetrics{
		AlertsBySeverity:       make(map[policy.AlertSeverity]int64),
		AlertsByType:           make(map[policy.AlertType]int64),
		NotificationsByChannel: make(map[policy.NotificationChannel]int64),
		LastUpdate:             time.Now(),
		SystemHealth:           "healthy",
	}
}

// initializeNotificationProviders sets up notification providers
func (am *RealTimeAlertManager) initializeNotificationProviders() error {
	// Initialize webhook provider
	webhookProvider := &WebhookNotificationProvider{
		logger: am.logger,
	}
	am.notificationProviders[policy.NotificationChannelWebhook] = webhookProvider
	
	// Initialize email provider (mock implementation)
	emailProvider := &EmailNotificationProvider{
		logger: am.logger,
	}
	am.notificationProviders[policy.NotificationChannelEmail] = emailProvider
	
	am.logger.Info("Notification providers initialized")
	return nil
}

// initializeDefaultRules creates default alert rules
func (am *RealTimeAlertManager) initializeDefaultRules() error {
	rules := []*policy.AlertRule{
		{
			ID:          "policy_violation_rule",
			Name:        "Policy Violation Detection",
			Description: "Detects policy violations and creates alerts",
			Enabled:     true,
			Type:        policy.AlertTypePolicyViolation,
			Severity:    policy.AlertSeverityHigh,
			Conditions: policy.AlertConditions{
				EventType: "policy_violation",
			},
			EvaluationInterval: 1 * time.Minute,
			SuppressRepeats:    true,
			SuppressionWindow:  5 * time.Minute,
			AutoResolveTimeout: 24 * time.Hour,
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
			CreatedBy:          "system",
		},
		{
			ID:          "security_incident_rule",
			Name:        "Security Incident Detection",
			Description: "Detects security incidents and creates critical alerts",
			Enabled:     true,
			Type:        policy.AlertTypeSecurityIncident,
			Severity:    policy.AlertSeverityCritical,
			Conditions: policy.AlertConditions{
				EventType: "security_incident",
			},
			EvaluationInterval: 30 * time.Second,
			SuppressRepeats:    false,
			AutoResolveTimeout: 48 * time.Hour,
			EscalationEnabled:  true,
			EscalationLevels: []policy.AlertEscalationLevel{
				{
					Level:             1,
					DelayFromPrevious: 5 * time.Minute,
					AutoEscalate:      true,
				},
				{
					Level:             2,
					DelayFromPrevious: 15 * time.Minute,
					AutoEscalate:      true,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			CreatedBy: "system",
		},
	}
	
	for _, rule := range rules {
		am.alertRules[rule.ID] = rule
	}
	
	am.logger.Info("Default alert rules initialized")
	return nil
}

// findSimilarAlert finds similar alerts for aggregation
func (am *RealTimeAlertManager) findSimilarAlert(newAlert *policy.Alert) *policy.Alert {
	for _, existingAlert := range am.alerts {
		if existingAlert.Type == newAlert.Type &&
		   existingAlert.Source == newAlert.Source &&
		   existingAlert.Status == policy.AlertStatusActive &&
		   time.Since(existingAlert.LastOccurredAt) < 5*time.Minute {
			return existingAlert
		}
	}
	return nil
}

// aggregateAlert aggregates a new alert with an existing one
func (am *RealTimeAlertManager) aggregateAlert(existingAlert, newAlert *policy.Alert) error {
	existingAlert.OccurrenceCount++
	existingAlert.LastOccurredAt = newAlert.FirstOccurredAt
	existingAlert.UpdatedAt = time.Now()
	
	// Merge metadata
	if existingAlert.Metadata == nil {
		existingAlert.Metadata = make(map[string]interface{})
	}
	for k, v := range newAlert.Metadata {
		existingAlert.Metadata[k] = v
	}
	
	am.logger.WithFields(logrus.Fields{
		"existing_alert_id": existingAlert.ID,
		"occurrence_count":  existingAlert.OccurrenceCount,
	}).Info("Alert aggregated")
	
	return nil
}

// isAlertSuppressed checks if an alert should be suppressed
func (am *RealTimeAlertManager) isAlertSuppressed(alert *policy.Alert) bool {
	for _, suppression := range am.suppressions {
		if !suppression.Enabled {
			continue
		}
		
		// Check if suppression has expired
		if suppression.ExpiresAt != nil && time.Now().After(*suppression.ExpiresAt) {
			continue
		}
		
		// Check alert type filter
		if len(suppression.AlertTypes) > 0 {
			found := false
			for _, alertType := range suppression.AlertTypes {
				if alertType == alert.Type {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Check severity filter
		if len(suppression.AlertSeverities) > 0 {
			found := false
			for _, severity := range suppression.AlertSeverities {
				if severity == alert.Severity {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Check source filter
		if len(suppression.Sources) > 0 {
			found := false
			for _, source := range suppression.Sources {
				if source == alert.Source {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Check tenant filter
		if len(suppression.TenantIDs) > 0 && alert.TenantID != "" {
			found := false
			for _, tenantID := range suppression.TenantIDs {
				if tenantID == alert.TenantID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Check tag filters
		if len(suppression.Tags) > 0 {
			allTagsMatch := true
			for key, value := range suppression.Tags {
				if alertValue, exists := alert.Tags[key]; !exists || alertValue != value {
					allTagsMatch = false
					break
				}
			}
			if !allTagsMatch {
				continue
			}
		}
		
		// If we reach here, the alert matches the suppression rule
		return true
	}
	
	return false
}

// updateMetrics updates alert metrics
func (am *RealTimeAlertManager) updateMetrics() {
	am.metrics.TotalAlerts = int64(len(am.alerts))
	am.metrics.ActiveAlerts = 0
	am.metrics.ResolvedAlerts = 0
	am.metrics.AcknowledgedAlerts = 0
	am.metrics.EscalatedAlerts = 0
	am.metrics.SuppressedAlerts = 0
	
	// Reset severity and type counters
	am.metrics.AlertsBySeverity = make(map[policy.AlertSeverity]int64)
	am.metrics.AlertsByType = make(map[policy.AlertType]int64)
	
	for _, alert := range am.alerts {
		switch alert.Status {
		case policy.AlertStatusActive:
			am.metrics.ActiveAlerts++
		case policy.AlertStatusResolved:
			am.metrics.ResolvedAlerts++
		case policy.AlertStatusAcknowledged:
			am.metrics.AcknowledgedAlerts++
		case policy.AlertStatusEscalated:
			am.metrics.EscalatedAlerts++
		case policy.AlertStatusSuppressed:
			am.metrics.SuppressedAlerts++
		}
		
		am.metrics.AlertsBySeverity[alert.Severity]++
		am.metrics.AlertsByType[alert.Type]++
	}
	
	am.metrics.LastUpdate = time.Now()
	am.metrics.QueueDepth = am.queueDepth
}

// sendAlertNotifications sends notifications for a new alert
func (am *RealTimeAlertManager) sendAlertNotifications(alert *policy.Alert) {
	rule := am.findAlertRule(alert)
	if rule == nil {
		return
	}
	
	for _, notificationConfig := range rule.NotificationChannels {
		if !notificationConfig.Enabled {
			continue
		}
		
		// Check severity filter
		if len(notificationConfig.SeverityFilter) > 0 {
			found := false
			for _, severity := range notificationConfig.SeverityFilter {
				if severity == alert.Severity {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Check type filter
		if len(notificationConfig.TypeFilter) > 0 {
			found := false
			for _, alertType := range notificationConfig.TypeFilter {
				if alertType == alert.Type {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		
		// Send notification
		err := am.SendNotification(alert, notificationConfig.Channel, notificationConfig.Recipients)
		if err != nil {
			am.logger.WithError(err).WithFields(logrus.Fields{
				"alert_id": alert.ID,
				"channel":  notificationConfig.Channel,
			}).Error("Failed to send notification")
		}
	}
}

// findAlertRule finds the alert rule that applies to this alert
func (am *RealTimeAlertManager) findAlertRule(alert *policy.Alert) *policy.AlertRule {
	for _, rule := range am.alertRules {
		if rule.Enabled && rule.Type == alert.Type {
			return rule
		}
	}
	return nil
}

// sendEscalationNotifications sends escalation notifications
func (am *RealTimeAlertManager) sendEscalationNotifications(alert *policy.Alert, escalationLevel *policy.AlertEscalationLevel) {
	for _, notificationConfig := range escalationLevel.NotificationChannels {
		if !notificationConfig.Enabled {
			continue
		}
		
		err := am.SendNotification(alert, notificationConfig.Channel, notificationConfig.Recipients)
		if err != nil {
			am.logger.WithError(err).WithFields(logrus.Fields{
				"alert_id":         alert.ID,
				"escalation_level": escalationLevel.Level,
				"channel":          notificationConfig.Channel,
			}).Error("Failed to send escalation notification")
		}
	}
}

// ===== ALERT LIFECYCLE METHODS =====

// CreateAlert creates a new alert
func (am *RealTimeAlertManager) CreateAlert(alert *policy.Alert) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	
	now := time.Now()
	alert.CreatedAt = now
	alert.UpdatedAt = now
	alert.FirstOccurredAt = now
	alert.LastOccurredAt = now
	alert.Status = policy.AlertStatusActive
	alert.OccurrenceCount = 1
	
	// Check for duplicates and aggregate if needed
	if am.config.EnableAggregation {
		if existingAlert := am.findSimilarAlert(alert); existingAlert != nil {
			return am.aggregateAlert(existingAlert, alert)
		}
	}
	
	// Check suppression rules
	if am.config.EnableSuppression && am.isAlertSuppressed(alert) {
		alert.Status = policy.AlertStatusSuppressed
		am.logger.WithField("alert_id", alert.ID).Info("Alert suppressed by suppression rule")
	}
	
	am.alerts[alert.ID] = alert
	am.updateMetrics()
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_created",
			Source:    "alert_manager",
			Timestamp: now,
			Metadata: map[string]interface{}{
				"alert_id":   alert.ID,
				"alert_type": alert.Type,
				"severity":   alert.Severity,
				"source":     alert.Source,
			},
		})
	}
	
	// Send notifications if not suppressed
	if alert.Status != policy.AlertStatusSuppressed && am.config.EnableNotifications {
		go am.sendAlertNotifications(alert)
	}
	
	am.logger.WithFields(logrus.Fields{
		"alert_id": alert.ID,
		"type":     alert.Type,
		"severity": alert.Severity,
	}).Info("Alert created successfully")
	
	return nil
}

// UpdateAlert updates an existing alert
func (am *RealTimeAlertManager) UpdateAlert(alertID string, updates map[string]interface{}) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	// Apply updates
	now := time.Now()
	alert.UpdatedAt = now
	
	for key, value := range updates {
		switch key {
		case "title":
			alert.Title = value.(string)
		case "description":
			alert.Description = value.(string)
		case "severity":
			alert.Severity = value.(policy.AlertSeverity)
		case "status":
			alert.Status = value.(policy.AlertStatus)
		case "assigned_to":
			alert.AssignedTo = value.(string)
		case "tags":
			alert.Tags = value.(map[string]string)
		case "metadata":
			alert.Metadata = value.(map[string]interface{})
		}
	}
	
	am.updateMetrics()
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_updated",
			Source:    "alert_manager",
			Timestamp: now,
			Metadata: map[string]interface{}{
				"alert_id": alertID,
				"updates":  updates,
			},
		})
	}
	
	am.logger.WithField("alert_id", alertID).Info("Alert updated successfully")
	return nil
}

// AcknowledgeAlert acknowledges an alert
func (am *RealTimeAlertManager) AcknowledgeAlert(alertID, acknowledgedBy string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	if alert.Status == policy.AlertStatusResolved {
		return fmt.Errorf("cannot acknowledge resolved alert: %s", alertID)
	}
	
	now := time.Now()
	alert.Status = policy.AlertStatusAcknowledged
	alert.AcknowledgedAt = &now
	alert.AcknowledgedBy = acknowledgedBy
	alert.UpdatedAt = now
	
	am.updateMetrics()
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_acknowledged",
			Source:    "alert_manager",
			Actor:     acknowledgedBy,
			Timestamp: now,
			Metadata: map[string]interface{}{
				"alert_id": alertID,
			},
		})
	}
	
	am.logger.WithFields(logrus.Fields{
		"alert_id":        alertID,
		"acknowledged_by": acknowledgedBy,
	}).Info("Alert acknowledged successfully")
	
	return nil
}

// ResolveAlert resolves an alert
func (am *RealTimeAlertManager) ResolveAlert(alertID, resolvedBy, resolution string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	now := time.Now()
	alert.Status = policy.AlertStatusResolved
	alert.ResolvedAt = &now
	alert.ResolvedBy = resolvedBy
	alert.UpdatedAt = now
	
	// Add resolution to metadata
	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	alert.Metadata["resolution"] = resolution
	alert.Metadata["resolution_time"] = now
	
	am.updateMetrics()
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_resolved",
			Source:    "alert_manager",
			Actor:     resolvedBy,
			Timestamp: now,
			Metadata: map[string]interface{}{
				"alert_id":   alertID,
				"resolution": resolution,
			},
		})
	}
	
	am.logger.WithFields(logrus.Fields{
		"alert_id":    alertID,
		"resolved_by": resolvedBy,
		"resolution":  resolution,
	}).Info("Alert resolved successfully")
	
	return nil
}

// EscalateAlert escalates an alert to the next level
func (am *RealTimeAlertManager) EscalateAlert(alertID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	if alert.Status == policy.AlertStatusResolved {
		return fmt.Errorf("cannot escalate resolved alert: %s", alertID)
	}
	
	// Find applicable alert rule for escalation levels
	rule := am.findAlertRule(alert)
	if rule == nil || !rule.EscalationEnabled {
		return fmt.Errorf("no escalation configuration found for alert: %s", alertID)
	}
	
	nextLevel := alert.EscalationLevel + 1
	if nextLevel >= len(rule.EscalationLevels) {
		return fmt.Errorf("maximum escalation level reached for alert: %s", alertID)
	}
	
	now := time.Now()
	alert.EscalationLevel = nextLevel
	alert.EscalatedAt = &now
	alert.Status = policy.AlertStatusEscalated
	alert.UpdatedAt = now
	
	// Set next escalation time if auto-escalation is enabled
	escalationLevel := rule.EscalationLevels[nextLevel]
	if escalationLevel.AutoEscalate && nextLevel+1 < len(rule.EscalationLevels) {
		nextEscalation := now.Add(escalationLevel.DelayFromPrevious)
		alert.NextEscalation = &nextEscalation
	}
	
	am.updateMetrics()
	
	// Send escalation notifications
	if am.config.EnableNotifications {
		go am.sendEscalationNotifications(alert, &escalationLevel)
	}
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_escalated",
			Source:    "alert_manager",
			Timestamp: now,
			Metadata: map[string]interface{}{
				"alert_id":        alertID,
				"escalation_level": nextLevel,
			},
		})
	}
	
	am.logger.WithFields(logrus.Fields{
		"alert_id":         alertID,
		"escalation_level": nextLevel,
	}).Info("Alert escalated successfully")
	
	return nil
}

// SuppressAlert temporarily suppresses an alert
func (am *RealTimeAlertManager) SuppressAlert(alertID string, duration time.Duration, reason string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}
	
	now := time.Now()
	alert.Status = policy.AlertStatusSuppressed
	alert.UpdatedAt = now
	
	// Add suppression metadata
	if alert.Metadata == nil {
		alert.Metadata = make(map[string]interface{})
	}
	alert.Metadata["suppression_reason"] = reason
	alert.Metadata["suppression_start"] = now
	alert.Metadata["suppression_end"] = now.Add(duration)
	
	am.updateMetrics()
	
	// Schedule auto-unsuppression
	go func() {
		time.Sleep(duration)
		am.mu.Lock()
		defer am.mu.Unlock()
		
		if currentAlert, exists := am.alerts[alertID]; exists && currentAlert.Status == policy.AlertStatusSuppressed {
			currentAlert.Status = policy.AlertStatusActive
			currentAlert.UpdatedAt = time.Now()
			delete(currentAlert.Metadata, "suppression_reason")
			delete(currentAlert.Metadata, "suppression_start")
			delete(currentAlert.Metadata, "suppression_end")
		}
	}()
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_suppressed",
			Source:    "alert_manager",
			Timestamp: now,
			Metadata: map[string]interface{}{
				"alert_id": alertID,
				"duration": duration.String(),
				"reason":   reason,
			},
		})
	}
	
	am.logger.WithFields(logrus.Fields{
		"alert_id": alertID,
		"duration": duration,
		"reason":   reason,
	}).Info("Alert suppressed successfully")
	
	return nil
}

// ===== ALERT RETRIEVAL METHODS =====

// GetAlert retrieves a specific alert by ID
func (am *RealTimeAlertManager) GetAlert(alertID string) (*policy.Alert, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	
	// Return a copy to prevent external modification
	alertCopy := *alert
	return &alertCopy, nil
}

// ListAlerts retrieves alerts based on filters
func (am *RealTimeAlertManager) ListAlerts(filters policy.AlertFilters) ([]*policy.Alert, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	var result []*policy.Alert
	
	for _, alert := range am.alerts {
		if am.matchesFilters(alert, filters) {
			alertCopy := *alert
			result = append(result, &alertCopy)
		}
	}
	
	// Apply sorting
	am.sortAlerts(result, filters.SortBy, filters.SortOrder)
	
	// Apply pagination
	if filters.Limit > 0 {
		start := filters.Offset
		end := start + filters.Limit
		
		if start >= len(result) {
			return []*policy.Alert{}, nil
		}
		
		if end > len(result) {
			end = len(result)
		}
		
		result = result[start:end]
	}
	
	return result, nil
}

// GetActiveAlerts retrieves all active alerts
func (am *RealTimeAlertManager) GetActiveAlerts() ([]*policy.Alert, error) {
	return am.ListAlerts(policy.AlertFilters{
		Statuses: []policy.AlertStatus{policy.AlertStatusActive, policy.AlertStatusEscalated},
	})
}

// GetAlertsByTenant retrieves alerts for a specific tenant
func (am *RealTimeAlertManager) GetAlertsByTenant(tenantID string) ([]*policy.Alert, error) {
	return am.ListAlerts(policy.AlertFilters{
		TenantIDs: []string{tenantID},
	})
}

// GetAlertsByType retrieves alerts by type
func (am *RealTimeAlertManager) GetAlertsByType(alertType policy.AlertType) ([]*policy.Alert, error) {
	return am.ListAlerts(policy.AlertFilters{
		Types: []policy.AlertType{alertType},
	})
}

// GetAlertsBySeverity retrieves alerts by severity
func (am *RealTimeAlertManager) GetAlertsBySeverity(severity policy.AlertSeverity) ([]*policy.Alert, error) {
	return am.ListAlerts(policy.AlertFilters{
		Severities: []policy.AlertSeverity{severity},
	})
}

// ===== ALERT RULES MANAGEMENT =====

// CreateAlertRule creates a new alert rule
func (am *RealTimeAlertManager) CreateAlertRule(rule *policy.AlertRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	
	am.alertRules[rule.ID] = rule
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_rule_created",
			Source:    "alert_manager",
			Timestamp: now,
			Metadata: map[string]interface{}{
				"rule_id":   rule.ID,
				"rule_name": rule.Name,
				"rule_type": rule.Type,
			},
		})
	}
	
	am.logger.WithFields(logrus.Fields{
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}).Info("Alert rule created successfully")
	
	return nil
}

// UpdateAlertRule updates an existing alert rule
func (am *RealTimeAlertManager) UpdateAlertRule(ruleID string, rule *policy.AlertRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	_, exists := am.alertRules[ruleID]
	if !exists {
		return fmt.Errorf("alert rule not found: %s", ruleID)
	}
	
	rule.ID = ruleID
	rule.UpdatedAt = time.Now()
	am.alertRules[ruleID] = rule
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_rule_updated",
			Source:    "alert_manager",
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"rule_id": ruleID,
			},
		})
	}
	
	am.logger.WithField("rule_id", ruleID).Info("Alert rule updated successfully")
	return nil
}

// DeleteAlertRule deletes an alert rule
func (am *RealTimeAlertManager) DeleteAlertRule(ruleID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	_, exists := am.alertRules[ruleID]
	if !exists {
		return fmt.Errorf("alert rule not found: %s", ruleID)
	}
	
	delete(am.alertRules, ruleID)
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "alert_rule_deleted",
			Source:    "alert_manager",
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"rule_id": ruleID,
			},
		})
	}
	
	am.logger.WithField("rule_id", ruleID).Info("Alert rule deleted successfully")
	return nil
}

// GetAlertRule retrieves a specific alert rule
func (am *RealTimeAlertManager) GetAlertRule(ruleID string) (*policy.AlertRule, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	rule, exists := am.alertRules[ruleID]
	if !exists {
		return nil, fmt.Errorf("alert rule not found: %s", ruleID)
	}
	
	ruleCopy := *rule
	return &ruleCopy, nil
}

// ListAlertRules retrieves all alert rules
func (am *RealTimeAlertManager) ListAlertRules() ([]*policy.AlertRule, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	var rules []*policy.AlertRule
	for _, rule := range am.alertRules {
		ruleCopy := *rule
		rules = append(rules, &ruleCopy)
	}
	
	return rules, nil
}

// EnableAlertRule enables an alert rule
func (am *RealTimeAlertManager) EnableAlertRule(ruleID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	rule, exists := am.alertRules[ruleID]
	if !exists {
		return fmt.Errorf("alert rule not found: %s", ruleID)
	}
	
	rule.Enabled = true
	rule.UpdatedAt = time.Now()
	
	am.logger.WithField("rule_id", ruleID).Info("Alert rule enabled")
	return nil
}

// DisableAlertRule disables an alert rule
func (am *RealTimeAlertManager) DisableAlertRule(ruleID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	rule, exists := am.alertRules[ruleID]
	if !exists {
		return fmt.Errorf("alert rule not found: %s", ruleID)
	}
	
	rule.Enabled = false
	rule.UpdatedAt = time.Now()
	
	am.logger.WithField("rule_id", ruleID).Info("Alert rule disabled")
	return nil
}

// ===== ALERT AGGREGATION =====

// CreateAggregationRule creates a new aggregation rule
func (am *RealTimeAlertManager) CreateAggregationRule(rule *policy.AlertAggregationRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	
	am.aggregationRules[rule.ID] = rule
	
	am.logger.WithFields(logrus.Fields{
		"rule_id":   rule.ID,
		"rule_name": rule.Name,
	}).Info("Aggregation rule created successfully")
	
	return nil
}

// UpdateAggregationRule updates an aggregation rule
func (am *RealTimeAlertManager) UpdateAggregationRule(ruleID string, rule *policy.AlertAggregationRule) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	_, exists := am.aggregationRules[ruleID]
	if !exists {
		return fmt.Errorf("aggregation rule not found: %s", ruleID)
	}
	
	rule.ID = ruleID
	rule.UpdatedAt = time.Now()
	am.aggregationRules[ruleID] = rule
	
	am.logger.WithField("rule_id", ruleID).Info("Aggregation rule updated successfully")
	return nil
}

// DeleteAggregationRule deletes an aggregation rule
func (am *RealTimeAlertManager) DeleteAggregationRule(ruleID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	_, exists := am.aggregationRules[ruleID]
	if !exists {
		return fmt.Errorf("aggregation rule not found: %s", ruleID)
	}
	
	delete(am.aggregationRules, ruleID)
	
	am.logger.WithField("rule_id", ruleID).Info("Aggregation rule deleted successfully")
	return nil
}

// ListAggregationRules retrieves all aggregation rules
func (am *RealTimeAlertManager) ListAggregationRules() ([]*policy.AlertAggregationRule, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	var rules []*policy.AlertAggregationRule
	for _, rule := range am.aggregationRules {
		ruleCopy := *rule
		rules = append(rules, &ruleCopy)
	}
	
	return rules, nil
}

// ===== ALERT SUPPRESSION =====

// CreateSuppression creates a new suppression rule
func (am *RealTimeAlertManager) CreateSuppression(suppression *policy.AlertSuppression) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if suppression.ID == "" {
		suppression.ID = uuid.New().String()
	}
	
	now := time.Now()
	suppression.CreatedAt = now
	suppression.UpdatedAt = now
	
	am.suppressions[suppression.ID] = suppression
	
	// Log audit event
	if am.auditLogger != nil {
		am.auditLogger.LogEvent(&AuditEvent{
			ID:        uuid.New().String(),
			Type:      AuditEventTypeSystem,
			Category:  "alert_management",
			Action:    "suppression_created",
			Source:    "alert_manager",
			Timestamp: now,
			Metadata: map[string]interface{}{
				"suppression_id":   suppression.ID,
				"suppression_name": suppression.Name,
				"reason":          suppression.Reason,
			},
		})
	}
	
	am.logger.WithFields(logrus.Fields{
		"suppression_id":   suppression.ID,
		"suppression_name": suppression.Name,
	}).Info("Suppression rule created successfully")
	
	return nil
}

// UpdateSuppression updates a suppression rule
func (am *RealTimeAlertManager) UpdateSuppression(suppressionID string, suppression *policy.AlertSuppression) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	_, exists := am.suppressions[suppressionID]
	if !exists {
		return fmt.Errorf("suppression rule not found: %s", suppressionID)
	}
	
	suppression.ID = suppressionID
	suppression.UpdatedAt = time.Now()
	am.suppressions[suppressionID] = suppression
	
	am.logger.WithField("suppression_id", suppressionID).Info("Suppression rule updated successfully")
	return nil
}

// DeleteSuppression deletes a suppression rule
func (am *RealTimeAlertManager) DeleteSuppression(suppressionID string) error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	_, exists := am.suppressions[suppressionID]
	if !exists {
		return fmt.Errorf("suppression rule not found: %s", suppressionID)
	}
	
	delete(am.suppressions, suppressionID)
	
	am.logger.WithField("suppression_id", suppressionID).Info("Suppression rule deleted successfully")
	return nil
}

// ListSuppressions retrieves all suppression rules
func (am *RealTimeAlertManager) ListSuppressions() ([]*policy.AlertSuppression, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	var suppressions []*policy.AlertSuppression
	for _, suppression := range am.suppressions {
		suppressionCopy := *suppression
		suppressions = append(suppressions, &suppressionCopy)
	}
	
	return suppressions, nil
}

// ===== NOTIFICATION MANAGEMENT =====

// SendNotification sends a notification for an alert
func (am *RealTimeAlertManager) SendNotification(alert *policy.Alert, channel policy.NotificationChannel, recipients []string) error {
	provider, exists := am.notificationProviders[channel]
	if !exists {
		return fmt.Errorf("notification provider not found for channel: %s", channel)
	}
	
	config := policy.NotificationConfig{
		Channel:    channel,
		Enabled:    true,
		Recipients: recipients,
	}
	
	// Record notification attempt
	now := time.Now()
	notificationRecord := policy.NotificationRecord{
		Channel:       channel,
		Recipient:     strings.Join(recipients, ","),
		SentAt:        now,
		Status:        "pending",
		AttemptNumber: 1,
	}
	
	err := provider.SendNotification(alert, config)
	if err != nil {
		notificationRecord.Status = "failed"
		notificationRecord.ErrorMessage = err.Error()
		am.metrics.NotificationsFailed++
	} else {
		notificationRecord.Status = "sent"
		am.metrics.NotificationsSent++
	}
	
	// Update notification tracking
	am.mu.Lock()
	if alert.NotificationsSent == nil {
		alert.NotificationsSent = []policy.NotificationRecord{}
	}
	alert.NotificationsSent = append(alert.NotificationsSent, notificationRecord)
	am.mu.Unlock()
	
	// Update metrics
	am.metrics.NotificationsByChannel[channel]++
	
	if err != nil {
		am.logger.WithError(err).WithFields(logrus.Fields{
			"alert_id":   alert.ID,
			"channel":    channel,
			"recipients": recipients,
		}).Error("Failed to send notification")
		return err
	}
	
	am.logger.WithFields(logrus.Fields{
		"alert_id":   alert.ID,
		"channel":    channel,
		"recipients": recipients,
	}).Info("Notification sent successfully")
	
	return nil
}

// GetNotificationHistory retrieves notification history for an alert
func (am *RealTimeAlertManager) GetNotificationHistory(alertID string) ([]policy.NotificationRecord, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alert, exists := am.alerts[alertID]
	if !exists {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	
	return alert.NotificationsSent, nil
}

// TestNotificationChannel tests a notification channel configuration
func (am *RealTimeAlertManager) TestNotificationChannel(channel policy.NotificationChannel, config policy.NotificationConfig) error {
	provider, exists := am.notificationProviders[channel]
	if !exists {
		return fmt.Errorf("notification provider not found for channel: %s", channel)
	}
	
	// Validate configuration
	if err := provider.ValidateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration for channel %s: %w", channel, err)
	}
	
	// Perform health check
	if err := provider.HealthCheck(); err != nil {
		return fmt.Errorf("health check failed for channel %s: %w", channel, err)
	}
	
	am.logger.WithField("channel", channel).Info("Notification channel test successful")
	return nil
}

// ===== ANALYTICS AND REPORTING =====

// GetAlertMetrics retrieves current alert metrics
func (am *RealTimeAlertManager) GetAlertMetrics() (*policy.AlertMetrics, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	am.updateMetrics()
	
	// Create a copy to prevent external modification
	metricsCopy := *am.metrics
	metricsCopy.AlertsBySeverity = make(map[policy.AlertSeverity]int64)
	metricsCopy.AlertsByType = make(map[policy.AlertType]int64)
	metricsCopy.NotificationsByChannel = make(map[policy.NotificationChannel]int64)
	
	for k, v := range am.metrics.AlertsBySeverity {
		metricsCopy.AlertsBySeverity[k] = v
	}
	for k, v := range am.metrics.AlertsByType {
		metricsCopy.AlertsByType[k] = v
	}
	for k, v := range am.metrics.NotificationsByChannel {
		metricsCopy.NotificationsByChannel[k] = v
	}
	
	return &metricsCopy, nil
}

// GetAlertStatistics generates alert statistics for a period
func (am *RealTimeAlertManager) GetAlertStatistics(period string) (*policy.AlertStatistics, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	var startTime time.Time
	now := time.Now()
	
	switch period {
	case "hour":
		startTime = now.Add(-1 * time.Hour)
	case "day":
		startTime = now.Add(-24 * time.Hour)
	case "week":
		startTime = now.Add(-7 * 24 * time.Hour)
	case "month":
		startTime = now.Add(-30 * 24 * time.Hour)
	default:
		startTime = now.Add(-24 * time.Hour) // Default to last 24 hours
	}
	
	stats := &policy.AlertStatistics{
		Period:           period,
		GeneratedAt:      now,
		AlertsByHour:     make(map[int]int),
		AlertsByDay:      make(map[string]int),
		AlertsBySeverity: make(map[policy.AlertSeverity]int),
		AlertsByType:     make(map[policy.AlertType]int),
		AlertsBySource:   make(map[string]int),
		AlertsByTenant:   make(map[string]int),
		TargetAckTime:    15 * time.Minute,
		TargetResolutionTime: 4 * time.Hour,
	}
	
	var totalAckTime, totalResolutionTime time.Duration
	var ackCount, resolutionCount int
	var ackTimes, resolutionTimes []time.Duration
	
	for _, alert := range am.alerts {
		if alert.CreatedAt.Before(startTime) {
			continue
		}
		
		stats.TotalAlerts++
		
		// Categorize alerts
		if alert.CreatedAt.After(startTime) {
			stats.NewAlerts++
		}
		
		if alert.Status == policy.AlertStatusResolved {
			stats.ResolvedAlerts++
		} else {
			stats.OngoingAlerts++
		}
		
		if alert.EscalationLevel > 0 {
			stats.EscalatedAlerts++
		}
		
		// Calculate response times
		if alert.AcknowledgedAt != nil {
			ackTime := alert.AcknowledgedAt.Sub(alert.CreatedAt)
			totalAckTime += ackTime
			ackTimes = append(ackTimes, ackTime)
			ackCount++
		}
		
		if alert.ResolvedAt != nil {
			resolutionTime := alert.ResolvedAt.Sub(alert.CreatedAt)
			totalResolutionTime += resolutionTime
			resolutionTimes = append(resolutionTimes, resolutionTime)
			resolutionCount++
		}
		
		// Distribution statistics
		hour := alert.CreatedAt.Hour()
		stats.AlertsByHour[hour]++
		
		day := alert.CreatedAt.Format("2006-01-02")
		stats.AlertsByDay[day]++
		
		stats.AlertsBySeverity[alert.Severity]++
		stats.AlertsByType[alert.Type]++
		stats.AlertsBySource[alert.Source]++
		
		if alert.TenantID != "" {
			stats.AlertsByTenant[alert.TenantID]++
		}
	}
	
	// Calculate averages
	if ackCount > 0 {
		stats.AverageAckTime = totalAckTime / time.Duration(ackCount)
	}
	
	if resolutionCount > 0 {
		stats.AverageResolutionTime = totalResolutionTime / time.Duration(resolutionCount)
	}
	
	// Calculate percentiles
	if len(ackTimes) > 0 {
		sort.Slice(ackTimes, func(i, j int) bool {
			return ackTimes[i] < ackTimes[j]
		})
		p95Index := int(float64(len(ackTimes)) * 0.95)
		if p95Index >= len(ackTimes) {
			p95Index = len(ackTimes) - 1
		}
		stats.P95AckTime = ackTimes[p95Index]
	}
	
	if len(resolutionTimes) > 0 {
		sort.Slice(resolutionTimes, func(i, j int) bool {
			return resolutionTimes[i] < resolutionTimes[j]
		})
		p95Index := int(float64(len(resolutionTimes)) * 0.95)
		if p95Index >= len(resolutionTimes) {
			p95Index = len(resolutionTimes) - 1
		}
		stats.P95ResolutionTime = resolutionTimes[p95Index]
	}
	
	// Calculate escalation statistics
	if stats.TotalAlerts > 0 {
		stats.EscalationRate = float64(stats.EscalatedAlerts) / float64(stats.TotalAlerts) * 100
	}
	
	// Calculate SLA compliance
	onTimeAck := 0
	onTimeResolution := 0
	
	for _, alert := range am.alerts {
		if alert.CreatedAt.Before(startTime) {
			continue
		}
		
		if alert.AcknowledgedAt != nil && alert.AcknowledgedAt.Sub(alert.CreatedAt) <= stats.TargetAckTime {
			onTimeAck++
		}
		
		if alert.ResolvedAt != nil && alert.ResolvedAt.Sub(alert.CreatedAt) <= stats.TargetResolutionTime {
			onTimeResolution++
		}
	}
	
	if ackCount > 0 {
		ackCompliance := float64(onTimeAck) / float64(ackCount) * 100
		resolutionCompliance := float64(onTimeResolution) / float64(resolutionCount) * 100
		stats.SLACompliance = (ackCompliance + resolutionCompliance) / 2
	}
	
	// Generate top lists
	stats.TopAlertTypes = am.generateTopAlertTypes(stats.AlertsByType)
	stats.TopAlertSources = am.generateTopAlertSources(stats.AlertsBySource)
	stats.MostActiveRules = am.generateMostActiveRules(startTime)
	
	// Determine trend
	if stats.TotalAlerts > 0 {
		// Simple trend calculation (could be enhanced)
		recentAlerts := 0
		olderAlerts := 0
		midpoint := startTime.Add(now.Sub(startTime) / 2)
		
		for _, alert := range am.alerts {
			if alert.CreatedAt.Before(startTime) {
				continue
			}
			
			if alert.CreatedAt.After(midpoint) {
				recentAlerts++
			} else {
				olderAlerts++
			}
		}
		
		if recentAlerts > olderAlerts {
			stats.AlertTrend = "increasing"
			if olderAlerts > 0 {
				stats.TrendPercentage = float64(recentAlerts-olderAlerts) / float64(olderAlerts) * 100
			}
		} else if recentAlerts < olderAlerts {
			stats.AlertTrend = "decreasing"
			if recentAlerts > 0 {
				stats.TrendPercentage = float64(olderAlerts-recentAlerts) / float64(recentAlerts) * 100
			}
		} else {
			stats.AlertTrend = "stable"
			stats.TrendPercentage = 0
		}
	}
	
	return stats, nil
}

// GetAlertTrends retrieves alert trends over time
func (am *RealTimeAlertManager) GetAlertTrends(duration time.Duration) (map[string]interface{}, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	startTime := time.Now().Add(-duration)
	
	trends := map[string]interface{}{
		"period":     duration.String(),
		"start_time": startTime,
		"end_time":   time.Now(),
		"data_points": []map[string]interface{}{},
	}
	
	// Generate hourly data points
	current := startTime
	for current.Before(time.Now()) {
		next := current.Add(time.Hour)
		
		hourlyStats := map[string]interface{}{
			"timestamp":      current,
			"total_alerts":   0,
			"critical_alerts": 0,
			"high_alerts":    0,
			"medium_alerts":  0,
			"low_alerts":     0,
		}
		
		for _, alert := range am.alerts {
			if alert.CreatedAt.After(current) && alert.CreatedAt.Before(next) {
				hourlyStats["total_alerts"] = hourlyStats["total_alerts"].(int) + 1
				
				switch alert.Severity {
				case policy.AlertSeverityCritical:
					hourlyStats["critical_alerts"] = hourlyStats["critical_alerts"].(int) + 1
				case policy.AlertSeverityHigh:
					hourlyStats["high_alerts"] = hourlyStats["high_alerts"].(int) + 1
				case policy.AlertSeverityMedium:
					hourlyStats["medium_alerts"] = hourlyStats["medium_alerts"].(int) + 1
				case policy.AlertSeverityLow:
					hourlyStats["low_alerts"] = hourlyStats["low_alerts"].(int) + 1
				}
			}
		}
		
		trends["data_points"] = append(trends["data_points"].([]map[string]interface{}), hourlyStats)
		current = next
	}
	
	return trends, nil
}

// ===== REAL-TIME OPERATIONS =====

// StartRealTimeProcessing starts the real-time alert processing
func (am *RealTimeAlertManager) StartRealTimeProcessing() error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if am.isProcessing {
		return fmt.Errorf("real-time processing is already running")
	}
	
	am.workerCtx, am.workerCancel = context.WithCancel(context.Background())
	
	// Start event processing workers
	for i := 0; i < am.processingWorkers; i++ {
		go am.eventProcessingWorker(i)
	}
	
	// Start background tasks
	am.escalationTicker = time.NewTicker(am.config.EscalationCheckInterval)
	go am.escalationWorker()
	
	am.cleanupTicker = time.NewTicker(am.config.CleanupInterval)
	go am.cleanupWorker()
	
	am.metricsTicker = time.NewTicker(am.config.MetricsUpdateInterval)
	go am.metricsWorker()
	
	am.isProcessing = true
	
	am.logger.Info("Real-time alert processing started")
	return nil
}

// StopRealTimeProcessing stops the real-time alert processing
func (am *RealTimeAlertManager) StopRealTimeProcessing() error {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if !am.isProcessing {
		return fmt.Errorf("real-time processing is not running")
	}
	
	// Cancel workers
	if am.workerCancel != nil {
		am.workerCancel()
	}
	
	// Stop tickers
	if am.escalationTicker != nil {
		am.escalationTicker.Stop()
	}
	if am.cleanupTicker != nil {
		am.cleanupTicker.Stop()
	}
	if am.metricsTicker != nil {
		am.metricsTicker.Stop()
	}
	
	am.isProcessing = false
	
	am.logger.Info("Real-time alert processing stopped")
	return nil
}

// GetProcessingStatus returns the current processing status
func (am *RealTimeAlertManager) GetProcessingStatus() (map[string]interface{}, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	status := map[string]interface{}{
		"is_processing":       am.isProcessing,
		"worker_count":        am.processingWorkers,
		"queue_depth":         len(am.eventQueue),
		"queue_capacity":      cap(am.eventQueue),
		"processing_errors":   am.processingErrors,
		"last_processed_event": am.lastProcessedEvent,
		"uptime":              time.Since(am.startTime),
		"total_alerts":        len(am.alerts),
		"active_rules":        len(am.alertRules),
		"active_suppressions": len(am.suppressions),
	}
	
	return status, nil
}

// ===== HEALTH AND MONITORING =====

// GetHealth returns the health status of the alert manager
func (am *RealTimeAlertManager) GetHealth() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	health := map[string]interface{}{
		"status":              "healthy",
		"uptime":              time.Since(am.startTime),
		"is_processing":       am.isProcessing,
		"queue_depth":         len(am.eventQueue),
		"queue_utilization":   float64(len(am.eventQueue)) / float64(cap(am.eventQueue)) * 100,
		"processing_errors":   am.processingErrors,
		"last_health_check":   time.Now(),
	}
	
	// Determine overall health status
	queueUtilization := health["queue_utilization"].(float64)
	if queueUtilization > 90 {
		health["status"] = "critical"
	} else if queueUtilization > 70 || am.processingErrors > 10 {
		health["status"] = "degraded"
	}
	
	// Check component health
	components := map[string]interface{}{
		"event_queue": map[string]interface{}{
			"status": "healthy",
			"depth":  len(am.eventQueue),
			"capacity": cap(am.eventQueue),
		},
		"notification_providers": map[string]interface{}{
			"status": "healthy",
			"count":  len(am.notificationProviders),
		},
		"alert_rules": map[string]interface{}{
			"status": "healthy",
			"count":  len(am.alertRules),
		},
	}
	
	health["components"] = components
	
	return health
}

// GetMetrics returns performance metrics
func (am *RealTimeAlertManager) GetMetrics() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	metrics := map[string]interface{}{
		"total_alerts":          len(am.alerts),
		"processing_errors":     am.processingErrors,
		"queue_depth":           len(am.eventQueue),
		"uptime":               time.Since(am.startTime),
		"notification_providers": len(am.notificationProviders),
		"alert_rules":          len(am.alertRules),
		"aggregation_rules":    len(am.aggregationRules),
		"suppressions":         len(am.suppressions),
		"last_processed_event": am.lastProcessedEvent,
	}
	
	return metrics
}

// ===== SHUTDOWN =====

// Shutdown gracefully shuts down the alert manager
func (am *RealTimeAlertManager) Shutdown(ctx context.Context) error {
	am.logger.Info("Shutting down alert manager...")
	
	// Stop real-time processing
	if err := am.StopRealTimeProcessing(); err != nil {
		am.logger.WithError(err).Warn("Error stopping real-time processing")
	}
	
	// Wait for remaining events to be processed
	done := make(chan bool)
	go func() {
		for len(am.eventQueue) > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		done <- true
	}()
	
	select {
	case <-done:
		am.logger.Info("All events processed")
	case <-ctx.Done():
		am.logger.Warn("Shutdown timeout reached, some events may not have been processed")
	}
	
	am.logger.Info("Alert manager shut down successfully")
	return nil
}

// ===== BACKGROUND WORKERS =====

// eventProcessingWorker processes events from the queue
func (am *RealTimeAlertManager) eventProcessingWorker(workerID int) {
	logger := am.logger.WithField("worker_id", workerID)
	logger.Info("Event processing worker started")
	
	defer func() {
		logger.Info("Event processing worker stopped")
	}()
	
	for {
		select {
		case event := <-am.eventQueue:
			am.processEvent(event)
			am.lastProcessedEvent = time.Now()
			
		case <-am.workerCtx.Done():
			return
		}
	}
}

// processEvent processes a single alert event
func (am *RealTimeAlertManager) processEvent(event *AlertEvent) {
	// Evaluate alert rules
	for _, rule := range am.alertRules {
		if !rule.Enabled {
			continue
		}
		
		if am.evaluateAlertRule(rule, event) {
			alert := am.createAlertFromEvent(event, rule)
			if err := am.CreateAlert(alert); err != nil {
				am.logger.WithError(err).Error("Failed to create alert from event")
				am.processingErrors++
			}
		}
	}
}

// evaluateAlertRule evaluates if an event matches an alert rule
func (am *RealTimeAlertManager) evaluateAlertRule(rule *policy.AlertRule, event *AlertEvent) bool {
	conditions := rule.Conditions
	
	// Check event type
	if conditions.EventType != "" && conditions.EventType != event.Type {
		return false
	}
	
	// Check event severity
	if conditions.EventSeverity != "" && conditions.EventSeverity != event.Severity {
		return false
	}
	
	// Check event source
	if conditions.EventSource != "" && conditions.EventSource != event.Source {
		return false
	}
	
	// Check event tags
	if len(conditions.EventTags) > 0 {
		for key, value := range conditions.EventTags {
			if eventValue, exists := event.Tags[key]; !exists || eventValue != value {
				return false
			}
		}
	}
	
	// Check tenant scope
	if len(rule.TenantScope) > 0 && event.TenantID != "" {
		found := false
		for _, tenantID := range rule.TenantScope {
			if tenantID == event.TenantID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check pattern matching
	if conditions.MessagePattern != "" {
		matched, err := regexp.MatchString(conditions.MessagePattern, event.Description)
		if err != nil || !matched {
			return false
		}
	}
	
	if conditions.TitlePattern != "" {
		matched, err := regexp.MatchString(conditions.TitlePattern, event.Title)
		if err != nil || !matched {
			return false
		}
	}
	
	return true
}

// createAlertFromEvent creates an alert from an event and rule
func (am *RealTimeAlertManager) createAlertFromEvent(event *AlertEvent, rule *policy.AlertRule) *policy.Alert {
	return &policy.Alert{
		Type:            rule.Type,
		Severity:        rule.Severity,
		Title:           event.Title,
		Description:     event.Description,
		Source:          event.Source,
		Tags:            event.Tags,
		Metadata:        event.Metadata,
		TenantID:        event.TenantID,
		PolicyID:        event.PolicyID,
		FirstOccurredAt: event.Timestamp,
		LastOccurredAt:  event.Timestamp,
	}
}

// escalationWorker handles alert escalations
func (am *RealTimeAlertManager) escalationWorker() {
	defer am.logger.Info("Escalation worker stopped")
	
	for {
		select {
		case <-am.escalationTicker.C:
			am.processEscalations()
			
		case <-am.workerCtx.Done():
			return
		}
	}
}

// processEscalations processes pending escalations
func (am *RealTimeAlertManager) processEscalations() {
	am.mu.RLock()
	var alertsToEscalate []*policy.Alert
	
	now := time.Now()
	for _, alert := range am.alerts {
		if alert.NextEscalation != nil && now.After(*alert.NextEscalation) {
			alertsToEscalate = append(alertsToEscalate, alert)
		}
	}
	am.mu.RUnlock()
	
	for _, alert := range alertsToEscalate {
		if err := am.EscalateAlert(alert.ID); err != nil {
			am.logger.WithError(err).WithField("alert_id", alert.ID).Error("Failed to escalate alert")
		}
	}
}

// cleanupWorker performs periodic cleanup
func (am *RealTimeAlertManager) cleanupWorker() {
	defer am.logger.Info("Cleanup worker stopped")
	
	for {
		select {
		case <-am.cleanupTicker.C:
			am.performCleanup()
			
		case <-am.workerCtx.Done():
			return
		}
	}
}

// performCleanup removes old resolved alerts
func (am *RealTimeAlertManager) performCleanup() {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	cutoff := time.Now().Add(-am.config.ResolvedAlertRetention)
	
	for alertID, alert := range am.alerts {
		if alert.Status == policy.AlertStatusResolved && 
		   alert.ResolvedAt != nil && 
		   alert.ResolvedAt.Before(cutoff) {
			delete(am.alerts, alertID)
		}
	}
	
	// Clean up expired suppressions
	for suppressionID, suppression := range am.suppressions {
		if suppression.ExpiresAt != nil && time.Now().After(*suppression.ExpiresAt) {
			delete(am.suppressions, suppressionID)
		}
	}
}

// metricsWorker updates metrics periodically
func (am *RealTimeAlertManager) metricsWorker() {
	defer am.logger.Info("Metrics worker stopped")
	
	for {
		select {
		case <-am.metricsTicker.C:
			am.mu.Lock()
			am.updateMetrics()
			am.mu.Unlock()
			
		case <-am.workerCtx.Done():
			return
		}
	}
}

// ===== HELPER METHODS FOR STATISTICS =====

// generateTopAlertTypes generates top alert types list
func (am *RealTimeAlertManager) generateTopAlertTypes(alertsByType map[policy.AlertType]int) []policy.AlertTypeCount {
	var counts []policy.AlertTypeCount
	
	for alertType, count := range alertsByType {
		counts = append(counts, policy.AlertTypeCount{
			Type:  alertType,
			Count: count,
		})
	}
	
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	
	// Return top 5
	if len(counts) > 5 {
		counts = counts[:5]
	}
	
	return counts
}

// generateTopAlertSources generates top alert sources list
func (am *RealTimeAlertManager) generateTopAlertSources(alertsBySource map[string]int) []policy.AlertSourceCount {
	var counts []policy.AlertSourceCount
	
	for source, count := range alertsBySource {
		counts = append(counts, policy.AlertSourceCount{
			Source: source,
			Count:  count,
		})
	}
	
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	
	// Return top 5
	if len(counts) > 5 {
		counts = counts[:5]
	}
	
	return counts
}

// generateMostActiveRules generates most active rules list
func (am *RealTimeAlertManager) generateMostActiveRules(since time.Time) []policy.AlertRuleStats {
	ruleStats := make(map[string]*policy.AlertRuleStats)
	
	for _, alert := range am.alerts {
		if alert.CreatedAt.Before(since) {
			continue
		}
		
		// Find the rule that created this alert
		for ruleID, rule := range am.alertRules {
			if rule.Type == alert.Type {
				if stats, exists := ruleStats[ruleID]; exists {
					stats.AlertCount++
					if alert.CreatedAt.After(stats.LastTriggered) {
						stats.LastTriggered = alert.CreatedAt
					}
				} else {
					ruleStats[ruleID] = &policy.AlertRuleStats{
						RuleID:        ruleID,
						RuleName:      rule.Name,
						AlertCount:    1,
						LastTriggered: alert.CreatedAt,
						AvgSeverity:   string(alert.Severity),
					}
				}
				break
			}
		}
	}
	
	var stats []policy.AlertRuleStats
	for _, stat := range ruleStats {
		stats = append(stats, *stat)
	}
	
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].AlertCount > stats[j].AlertCount
	})
	
	// Return top 5
	if len(stats) > 5 {
		stats = stats[:5]
	}
	
	return stats
}

// ProcessEvent is a public method to add events to the processing queue
func (am *RealTimeAlertManager) ProcessEvent(event *AlertEvent) error {
	if !am.isProcessing {
		return fmt.Errorf("real-time processing is not started")
	}
	
	select {
	case am.eventQueue <- event:
		am.queueDepth = len(am.eventQueue)
		return nil
	default:
		am.processingErrors++
		return fmt.Errorf("event queue is full")
	}
} 