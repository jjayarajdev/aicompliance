package ratelimit

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ViolationLogger handles logging of rate limit violations
type ViolationLogger struct {
	logger     *logrus.Logger
	violations map[string]*ViolationSummary
	config     *ViolationLoggerConfig
	mu         sync.RWMutex
}

// ViolationLoggerConfig holds violation logger configuration
type ViolationLoggerConfig struct {
	EnableAggregation    bool          `json:"enable_aggregation" yaml:"enable_aggregation"`
	AggregationWindow    time.Duration `json:"aggregation_window" yaml:"aggregation_window"`
	MaxViolationsPerUser int           `json:"max_violations_per_user" yaml:"max_violations_per_user"`
	AlertThreshold       int           `json:"alert_threshold" yaml:"alert_threshold"`
	CleanupInterval      time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
}

// ViolationSummary aggregates violations for a user/IP
type ViolationSummary struct {
	Identifier       string                      `json:"identifier"`
	Type             string                      `json:"type"` // "user", "ip", "org"
	FirstViolation   time.Time                   `json:"first_violation"`
	LastViolation    time.Time                   `json:"last_violation"`
	TotalViolations  int                         `json:"total_violations"`
	ViolationsByType map[string]int              `json:"violations_by_type"`
	Endpoints        map[string]int              `json:"endpoints"`
	Reasons          map[string]int              `json:"reasons"`
	Details          []*ViolationEvent           `json:"details"`
	SeverityScore    int                         `json:"severity_score"`
}

// NewViolationLogger creates a new violation logger
func NewViolationLogger(logger *logrus.Logger) *ViolationLogger {
	config := &ViolationLoggerConfig{
		EnableAggregation:    true,
		AggregationWindow:    5 * time.Minute,
		MaxViolationsPerUser: 100,
		AlertThreshold:       10,
		CleanupInterval:      30 * time.Minute,
	}
	
	vl := &ViolationLogger{
		logger:     logger,
		violations: make(map[string]*ViolationSummary),
		config:     config,
	}
	
	// Start background cleanup
	go vl.startCleanupWorker()
	
	return vl
}

// LogViolation logs a rate limit violation
func (vl *ViolationLogger) LogViolation(event *ViolationEvent) {
	// Log the individual violation
	vl.logIndividualViolation(event)
	
	// Aggregate violations if enabled
	if vl.config.EnableAggregation {
		vl.aggregateViolation(event)
	}
	
	// Check for alerts
	vl.checkForAlerts(event)
}

// logIndividualViolation logs a single violation event
func (vl *ViolationLogger) logIndividualViolation(event *ViolationEvent) {
	fields := logrus.Fields{
		"user_id":     event.UserID,
		"org_id":      event.OrgID,
		"endpoint":    event.Endpoint,
		"client_ip":   event.ClientIP,
		"reason":      event.Reason,
		"timestamp":   event.Timestamp,
		"event_type":  "rate_limit_violation",
	}
	
	// Add details from rate limit results
	if len(event.UserLimits) > 0 {
		fields["user_limit_details"] = vl.formatLimitDetails(event.UserLimits)
	}
	
	if len(event.OrgLimits) > 0 {
		fields["org_limit_details"] = vl.formatLimitDetails(event.OrgLimits)
	}
	
	if len(event.EndpointLimits) > 0 {
		fields["endpoint_limit_details"] = vl.formatLimitDetails(event.EndpointLimits)
	}
	
	vl.logger.WithFields(fields).Warn("Rate limit violation detected")
}

// aggregateViolation adds the violation to aggregated summaries
func (vl *ViolationLogger) aggregateViolation(event *ViolationEvent) {
	vl.mu.Lock()
	defer vl.mu.Unlock()
	
	// Aggregate by user
	if event.UserID != "" {
		vl.updateViolationSummary("user:"+event.UserID, "user", event)
	}
	
	// Aggregate by IP
	if event.ClientIP != "" {
		vl.updateViolationSummary("ip:"+event.ClientIP, "ip", event)
	}
	
	// Aggregate by organization
	if event.OrgID != "" {
		vl.updateViolationSummary("org:"+event.OrgID, "org", event)
	}
}

// updateViolationSummary updates or creates a violation summary
func (vl *ViolationLogger) updateViolationSummary(key, summaryType string, event *ViolationEvent) {
	summary, exists := vl.violations[key]
	if !exists {
		summary = &ViolationSummary{
			Identifier:       key,
			Type:             summaryType,
			FirstViolation:   event.Timestamp,
			ViolationsByType: make(map[string]int),
			Endpoints:        make(map[string]int),
			Reasons:          make(map[string]int),
			Details:          make([]*ViolationEvent, 0),
		}
		vl.violations[key] = summary
	}
	
	// Update summary
	summary.LastViolation = event.Timestamp
	summary.TotalViolations++
	summary.ViolationsByType[event.Reason]++
	summary.Endpoints[event.Endpoint]++
	summary.Reasons[event.Reason]++
	
	// Add to details (with limit)
	if len(summary.Details) < vl.config.MaxViolationsPerUser {
		summary.Details = append(summary.Details, event)
	} else {
		// Remove oldest and add newest
		summary.Details = summary.Details[1:]
		summary.Details = append(summary.Details, event)
	}
	
	// Calculate severity score
	summary.SeverityScore = vl.calculateSeverityScore(summary)
}

// calculateSeverityScore calculates a severity score for a violation summary
func (vl *ViolationLogger) calculateSeverityScore(summary *ViolationSummary) int {
	score := 0
	
	// Base score from total violations
	score += summary.TotalViolations
	
	// Frequency factor
	duration := summary.LastViolation.Sub(summary.FirstViolation)
	if duration > 0 {
		violationsPerMinute := float64(summary.TotalViolations) / duration.Minutes()
		score += int(violationsPerMinute * 10) // 10 points per violation per minute
	}
	
	// Endpoint diversity factor
	score += len(summary.Endpoints) * 2
	
	// Reason diversity factor
	score += len(summary.Reasons) * 3
	
	// Recent activity boost
	if time.Since(summary.LastViolation) < 5*time.Minute {
		score += 20
	}
	
	return score
}

// checkForAlerts checks if an alert should be triggered
func (vl *ViolationLogger) checkForAlerts(event *ViolationEvent) {
	vl.mu.RLock()
	defer vl.mu.RUnlock()
	
	// Check user violations
	if event.UserID != "" {
		userKey := "user:" + event.UserID
		if summary, exists := vl.violations[userKey]; exists {
			if summary.TotalViolations >= vl.config.AlertThreshold {
				vl.triggerAlert("user_threshold_exceeded", summary)
			}
			
			if summary.SeverityScore > 100 {
				vl.triggerAlert("high_severity_violations", summary)
			}
		}
	}
	
	// Check IP violations
	if event.ClientIP != "" {
		ipKey := "ip:" + event.ClientIP
		if summary, exists := vl.violations[ipKey]; exists {
			if summary.TotalViolations >= vl.config.AlertThreshold {
				vl.triggerAlert("ip_threshold_exceeded", summary)
			}
		}
	}
}

// triggerAlert triggers an alert for suspicious activity
func (vl *ViolationLogger) triggerAlert(alertType string, summary *ViolationSummary) {
	alertData, _ := json.Marshal(summary)
	
	vl.logger.WithFields(logrus.Fields{
		"alert_type":      alertType,
		"identifier":      summary.Identifier,
		"total_violations": summary.TotalViolations,
		"severity_score":  summary.SeverityScore,
		"first_violation": summary.FirstViolation,
		"last_violation":  summary.LastViolation,
		"summary_data":    string(alertData),
	}).Error("Rate limit violation alert triggered")
}

// formatLimitDetails formats rate limit details for logging
func (vl *ViolationLogger) formatLimitDetails(limits map[string]*RateLimitResult) map[string]interface{} {
	details := make(map[string]interface{})
	
	for window, result := range limits {
		details[window] = map[string]interface{}{
			"allowed":       result.Allowed,
			"current_count": result.CurrentCount,
			"limit":         result.Limit,
			"remaining":     result.Remaining,
			"window_usage":  result.WindowUsage,
			"retry_after":   result.RetryAfter.Seconds(),
		}
	}
	
	return details
}

// GetViolationSummary returns violation summary for an identifier
func (vl *ViolationLogger) GetViolationSummary(identifier string) *ViolationSummary {
	vl.mu.RLock()
	defer vl.mu.RUnlock()
	
	if summary, exists := vl.violations[identifier]; exists {
		// Return a copy to avoid race conditions
		summaryCopy := *summary
		return &summaryCopy
	}
	
	return nil
}

// GetAllViolationSummaries returns all violation summaries
func (vl *ViolationLogger) GetAllViolationSummaries() map[string]*ViolationSummary {
	vl.mu.RLock()
	defer vl.mu.RUnlock()
	
	summaries := make(map[string]*ViolationSummary)
	for key, summary := range vl.violations {
		summaryCopy := *summary
		summaries[key] = &summaryCopy
	}
	
	return summaries
}

// GetTopViolators returns the top violators by severity score
func (vl *ViolationLogger) GetTopViolators(limit int) []*ViolationSummary {
	vl.mu.RLock()
	defer vl.mu.RUnlock()
	
	summaries := make([]*ViolationSummary, 0, len(vl.violations))
	for _, summary := range vl.violations {
		summaryCopy := *summary
		summaries = append(summaries, &summaryCopy)
	}
	
	// Sort by severity score (simple bubble sort for small datasets)
	for i := 0; i < len(summaries)-1; i++ {
		for j := 0; j < len(summaries)-i-1; j++ {
			if summaries[j].SeverityScore < summaries[j+1].SeverityScore {
				summaries[j], summaries[j+1] = summaries[j+1], summaries[j]
			}
		}
	}
	
	if limit > 0 && limit < len(summaries) {
		summaries = summaries[:limit]
	}
	
	return summaries
}

// ClearViolations clears all violation data
func (vl *ViolationLogger) ClearViolations() {
	vl.mu.Lock()
	defer vl.mu.Unlock()
	
	vl.violations = make(map[string]*ViolationSummary)
	vl.logger.Info("Violation data cleared")
}

// startCleanupWorker starts the background cleanup worker
func (vl *ViolationLogger) startCleanupWorker() {
	ticker := time.NewTicker(vl.config.CleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		vl.performCleanup()
	}
}

// performCleanup removes old violation data
func (vl *ViolationLogger) performCleanup() {
	vl.mu.Lock()
	defer vl.mu.Unlock()
	
	cutoff := time.Now().Add(-vl.config.AggregationWindow * 2)
	cleanupCount := 0
	
	for key, summary := range vl.violations {
		if summary.LastViolation.Before(cutoff) {
			delete(vl.violations, key)
			cleanupCount++
		}
	}
	
	if cleanupCount > 0 {
		vl.logger.WithField("cleaned_summaries", cleanupCount).Info("Violation cleanup completed")
	}
} 