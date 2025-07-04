package cache

import (
	"sort"
	"strings"
	"time"
)

// TTLPolicyManager manages advanced TTL calculation and configuration
type TTLPolicyManager struct {
	config         *TTLPolicyConfig
	dynamicRules   []*DynamicTTLRule
	userPolicies   map[string]*UserTTLPolicy
	orgPolicies    map[string]*OrgTTLPolicy
	timeBasedRules []*TimeBasedTTLRule
}

// TTLPolicyConfig holds comprehensive TTL configuration
type TTLPolicyConfig struct {
	// Base TTL policies
	BasePolicies           map[string]time.Duration `json:"base_policies" yaml:"base_policies"`
	DefaultTTL             time.Duration            `json:"default_ttl" yaml:"default_ttl"`
	
	// Dynamic TTL features
	DynamicTTLEnabled      bool                     `json:"dynamic_ttl_enabled" yaml:"dynamic_ttl_enabled"`
	ConfidenceBasedTTL     *ConfidenceTTLConfig     `json:"confidence_based_ttl" yaml:"confidence_based_ttl"`
	SensitivityBasedTTL    *SensitivityTTLConfig    `json:"sensitivity_based_ttl" yaml:"sensitivity_based_ttl"`
	SizeBasedTTL          *SizeTTLConfig           `json:"size_based_ttl" yaml:"size_based_ttl"`
	
	// User/Organization specific
	UserSpecificEnabled    bool                     `json:"user_specific_enabled" yaml:"user_specific_enabled"`
	OrgSpecificEnabled     bool                     `json:"org_specific_enabled" yaml:"org_specific_enabled"`
	
	// Time-based TTL
	TimeBasedEnabled       bool                     `json:"time_based_enabled" yaml:"time_based_enabled"`
	BusinessHours          *BusinessHoursConfig     `json:"business_hours" yaml:"business_hours"`
	PeakHours             *PeakHoursConfig         `json:"peak_hours" yaml:"peak_hours"`
	
	// Adaptive TTL
	AdaptiveTTLEnabled     bool                     `json:"adaptive_ttl_enabled" yaml:"adaptive_ttl_enabled"`
	UsageBasedAdjustment   *UsageBasedConfig        `json:"usage_based_adjustment" yaml:"usage_based_adjustment"`
	
	// TTL bounds
	MinTTL                 time.Duration            `json:"min_ttl" yaml:"min_ttl"`
	MaxTTL                 time.Duration            `json:"max_ttl" yaml:"max_ttl"`
}

// ConfidenceTTLConfig defines confidence-based TTL rules
type ConfidenceTTLConfig struct {
	Enabled          bool          `json:"enabled" yaml:"enabled"`
	HighConfidence   float64       `json:"high_confidence" yaml:"high_confidence"`     // > 0.9
	MediumConfidence float64       `json:"medium_confidence" yaml:"medium_confidence"` // 0.7-0.9
	LowConfidence    float64       `json:"low_confidence" yaml:"low_confidence"`       // < 0.7
	HighTTLMultiplier    float64   `json:"high_ttl_multiplier" yaml:"high_ttl_multiplier"`       // 2.0x
	MediumTTLMultiplier  float64   `json:"medium_ttl_multiplier" yaml:"medium_ttl_multiplier"`   // 1.0x
	LowTTLMultiplier     float64   `json:"low_ttl_multiplier" yaml:"low_ttl_multiplier"`         // 0.5x
}

// SensitivityTTLConfig defines sensitivity-based TTL rules
type SensitivityTTLConfig struct {
	Enabled     bool                         `json:"enabled" yaml:"enabled"`
	LevelTTL    map[string]time.Duration     `json:"level_ttl" yaml:"level_ttl"`
	PIIMultiplier float64                    `json:"pii_multiplier" yaml:"pii_multiplier"` // Reduce TTL for PII
}

// SizeTTLConfig defines size-based TTL rules
type SizeTTLConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	SmallResponse   int64         `json:"small_response" yaml:"small_response"`     // < 1KB
	MediumResponse  int64         `json:"medium_response" yaml:"medium_response"`   // 1KB-100KB
	LargeResponse   int64         `json:"large_response" yaml:"large_response"`     // > 100KB
	SmallTTLMultiplier  float64   `json:"small_ttl_multiplier" yaml:"small_ttl_multiplier"`   // 1.5x
	MediumTTLMultiplier float64   `json:"medium_ttl_multiplier" yaml:"medium_ttl_multiplier"` // 1.0x
	LargeTTLMultiplier  float64   `json:"large_ttl_multiplier" yaml:"large_ttl_multiplier"`   // 0.8x
}

// BusinessHoursConfig defines business hours TTL adjustments
type BusinessHoursConfig struct {
	Enabled           bool          `json:"enabled" yaml:"enabled"`
	StartHour         int           `json:"start_hour" yaml:"start_hour"`         // 9 AM
	EndHour           int           `json:"end_hour" yaml:"end_hour"`             // 5 PM
	Timezone          string        `json:"timezone" yaml:"timezone"`            // "UTC"
	BusinessTTLMultiplier float64   `json:"business_ttl_multiplier" yaml:"business_ttl_multiplier"` // 1.0x
	OffHoursTTLMultiplier float64   `json:"off_hours_ttl_multiplier" yaml:"off_hours_ttl_multiplier"` // 2.0x (cache longer)
	WeekendTTLMultiplier  float64   `json:"weekend_ttl_multiplier" yaml:"weekend_ttl_multiplier"`   // 3.0x
}

// PeakHoursConfig defines peak usage hours
type PeakHoursConfig struct {
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	PeakPeriods     []PeakPeriod  `json:"peak_periods" yaml:"peak_periods"`
	PeakTTLMultiplier   float64   `json:"peak_ttl_multiplier" yaml:"peak_ttl_multiplier"`     // 0.5x (shorter cache)
	OffPeakTTLMultiplier float64  `json:"off_peak_ttl_multiplier" yaml:"off_peak_ttl_multiplier"` // 1.5x
}

// PeakPeriod defines a peak usage period
type PeakPeriod struct {
	StartHour int    `json:"start_hour" yaml:"start_hour"`
	EndHour   int    `json:"end_hour" yaml:"end_hour"`
	Days      []int  `json:"days" yaml:"days"` // 0=Sunday, 1=Monday, etc.
}

// UsageBasedConfig defines adaptive TTL based on usage patterns
type UsageBasedConfig struct {
	Enabled            bool          `json:"enabled" yaml:"enabled"`
	HighUsageThreshold int64         `json:"high_usage_threshold" yaml:"high_usage_threshold"`   // > 100 hits/hour
	LowUsageThreshold  int64         `json:"low_usage_threshold" yaml:"low_usage_threshold"`     // < 10 hits/hour
	HighUsageTTLMultiplier float64   `json:"high_usage_ttl_multiplier" yaml:"high_usage_ttl_multiplier"` // 2.0x
	LowUsageTTLMultiplier  float64   `json:"low_usage_ttl_multiplier" yaml:"low_usage_ttl_multiplier"`   // 0.5x
	AdaptationInterval     time.Duration `json:"adaptation_interval" yaml:"adaptation_interval"`      // 1 hour
}

// DynamicTTLRule defines a dynamic TTL calculation rule
type DynamicTTLRule struct {
	ID          string                 `json:"id" yaml:"id"`
	Name        string                 `json:"name" yaml:"name"`
	Enabled     bool                   `json:"enabled" yaml:"enabled"`
	Priority    int                    `json:"priority" yaml:"priority"`
	Conditions  []*TTLCondition        `json:"conditions" yaml:"conditions"`
	TTLModifier *TTLModifier           `json:"ttl_modifier" yaml:"ttl_modifier"`
	Description string                 `json:"description" yaml:"description"`
}

// TTLCondition defines conditions for TTL rule application
type TTLCondition struct {
	Field     string      `json:"field" yaml:"field"`         // request_type, user_id, org_id, content_type, etc.
	Operator  string      `json:"operator" yaml:"operator"`   // equals, contains, matches, greater_than, etc.
	Value     interface{} `json:"value" yaml:"value"`
	Negate    bool        `json:"negate" yaml:"negate"`
}

// TTLModifier defines how to modify TTL
type TTLModifier struct {
	Type       string        `json:"type" yaml:"type"`           // set, multiply, add, percentage
	Value      interface{}   `json:"value" yaml:"value"`         // specific duration, multiplier, etc.
	MinTTL     time.Duration `json:"min_ttl" yaml:"min_ttl"`
	MaxTTL     time.Duration `json:"max_ttl" yaml:"max_ttl"`
}

// UserTTLPolicy defines user-specific TTL policies
type UserTTLPolicy struct {
	UserID          string                   `json:"user_id" yaml:"user_id"`
	CustomTTLs      map[string]time.Duration `json:"custom_ttls" yaml:"custom_ttls"`
	GlobalMultiplier float64                 `json:"global_multiplier" yaml:"global_multiplier"`
	Enabled         bool                     `json:"enabled" yaml:"enabled"`
	ExpiresAt       *time.Time               `json:"expires_at" yaml:"expires_at"`
}

// OrgTTLPolicy defines organization-specific TTL policies
type OrgTTLPolicy struct {
	OrgID           string                   `json:"org_id" yaml:"org_id"`
	CustomTTLs      map[string]time.Duration `json:"custom_ttls" yaml:"custom_ttls"`
	GlobalMultiplier float64                 `json:"global_multiplier" yaml:"global_multiplier"`
	Enabled         bool                     `json:"enabled" yaml:"enabled"`
	ExpiresAt       *time.Time               `json:"expires_at" yaml:"expires_at"`
}

// TimeBasedTTLRule defines time-based TTL adjustments
type TimeBasedTTLRule struct {
	ID          string                `json:"id" yaml:"id"`
	Name        string                `json:"name" yaml:"name"`
	Enabled     bool                  `json:"enabled" yaml:"enabled"`
	Schedule    *TTLSchedule          `json:"schedule" yaml:"schedule"`
	TTLModifier *TTLModifier          `json:"ttl_modifier" yaml:"ttl_modifier"`
	Description string                `json:"description" yaml:"description"`
}

// TTLSchedule defines when a time-based rule applies
type TTLSchedule struct {
	Type        string   `json:"type" yaml:"type"`         // daily, weekly, monthly, custom
	Days        []int    `json:"days" yaml:"days"`         // Days of week (0=Sunday)
	Hours       []int    `json:"hours" yaml:"hours"`       // Hours of day
	StartTime   string   `json:"start_time" yaml:"start_time"` // "09:00"
	EndTime     string   `json:"end_time" yaml:"end_time"`     // "17:00"
	Timezone    string   `json:"timezone" yaml:"timezone"`
	Dates       []string `json:"dates" yaml:"dates"`       // Specific dates "2024-01-01"
}

// TTLCalculationContext holds context for TTL calculation
type TTLCalculationContext struct {
	Request         *CacheRequest      `json:"request"`
	Response        *CacheResponse     `json:"response"`
	ContentAnalysis *ContentAnalysis   `json:"content_analysis"`
	UserInfo        *UserInfo          `json:"user_info"`
	OrgInfo         *OrgInfo           `json:"org_info"`
	CurrentTime     time.Time          `json:"current_time"`
	UsageStats      *UsageStats        `json:"usage_stats"`
}

// ContentAnalysis holds content analysis results for TTL calculation
type ContentAnalysis struct {
	Confidence      float64 `json:"confidence"`
	Sensitivity     string  `json:"sensitivity"`      // public, internal, confidential, restricted
	HasPII          bool    `json:"has_pii"`
	ContentType     string  `json:"content_type"`
	Language        string  `json:"language"`
	TopicCategories []string `json:"topic_categories"`
}

// UserInfo holds user information for TTL calculation
type UserInfo struct {
	ID           string            `json:"id"`
	Role         string            `json:"role"`
	Permissions  []string          `json:"permissions"`
	UsagePattern *UserUsagePattern `json:"usage_pattern"`
	Preferences  map[string]interface{} `json:"preferences"`
}

// OrgInfo holds organization information for TTL calculation
type OrgInfo struct {
	ID             string               `json:"id"`
	Tier           string               `json:"tier"`           // free, pro, enterprise
	CacheQuota     int64                `json:"cache_quota"`
	UsagePattern   *OrgUsagePattern     `json:"usage_pattern"`
	PolicySettings map[string]interface{} `json:"policy_settings"`
}

// UserUsagePattern tracks user usage patterns
type UserUsagePattern struct {
	AverageRequestsPerHour float64                `json:"average_requests_per_hour"`
	PeakHours             []int                  `json:"peak_hours"`
	RequestTypeDistribution map[string]float64   `json:"request_type_distribution"`
	CacheHitRate          float64                `json:"cache_hit_rate"`
}

// OrgUsagePattern tracks organization usage patterns
type OrgUsagePattern struct {
	AverageRequestsPerHour float64              `json:"average_requests_per_hour"`
	PeakHours             []int                `json:"peak_hours"`
	RequestTypeDistribution map[string]float64 `json:"request_type_distribution"`
	CacheHitRate          float64              `json:"cache_hit_rate"`
	ActiveUsers           int                  `json:"active_users"`
}

// UsageStats holds current usage statistics
type UsageStats struct {
	RequestsLastHour     int64     `json:"requests_last_hour"`
	CacheHitsLastHour    int64     `json:"cache_hits_last_hour"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
	PopularContent       []string  `json:"popular_content"`
}

// NewTTLPolicyManager creates a new TTL policy manager
func NewTTLPolicyManager(config *TTLPolicyConfig) *TTLPolicyManager {
	if config == nil {
		config = getDefaultTTLPolicyConfig()
	}
	
	return &TTLPolicyManager{
		config:         config,
		dynamicRules:   []*DynamicTTLRule{},
		userPolicies:   make(map[string]*UserTTLPolicy),
		orgPolicies:    make(map[string]*OrgTTLPolicy),
		timeBasedRules: []*TimeBasedTTLRule{},
	}
}

// CalculateTTL calculates the optimal TTL for a request using advanced policies
func (tpm *TTLPolicyManager) CalculateTTL(ctx *TTLCalculationContext) (time.Duration, error) {
	// Start with base TTL
	baseTTL := tpm.getBaseTTL(ctx.Request.RequestType)
	
	// Apply dynamic rules in priority order
	if tpm.config.DynamicTTLEnabled {
		baseTTL = tpm.applyDynamicRules(baseTTL, ctx)
	}
	
	// Apply confidence-based adjustment
	if tpm.config.ConfidenceBasedTTL != nil && tpm.config.ConfidenceBasedTTL.Enabled {
		baseTTL = tpm.applyConfidenceBasedTTL(baseTTL, ctx)
	}
	
	// Apply sensitivity-based adjustment
	if tpm.config.SensitivityBasedTTL != nil && tpm.config.SensitivityBasedTTL.Enabled {
		baseTTL = tpm.applySensitivityBasedTTL(baseTTL, ctx)
	}
	
	// Apply size-based adjustment
	if tpm.config.SizeBasedTTL != nil && tpm.config.SizeBasedTTL.Enabled {
		baseTTL = tpm.applySizeBasedTTL(baseTTL, ctx)
	}
	
	// Apply user-specific policies
	if tpm.config.UserSpecificEnabled {
		baseTTL = tpm.applyUserSpecificTTL(baseTTL, ctx)
	}
	
	// Apply organization-specific policies
	if tpm.config.OrgSpecificEnabled {
		baseTTL = tpm.applyOrgSpecificTTL(baseTTL, ctx)
	}
	
	// Apply time-based adjustments
	if tpm.config.TimeBasedEnabled {
		baseTTL = tpm.applyTimeBasedTTL(baseTTL, ctx)
	}
	
	// Apply adaptive adjustments
	if tpm.config.AdaptiveTTLEnabled {
		baseTTL = tpm.applyAdaptiveTTL(baseTTL, ctx)
	}
	
	// Enforce bounds
	if baseTTL < tpm.config.MinTTL {
		baseTTL = tpm.config.MinTTL
	}
	if baseTTL > tpm.config.MaxTTL {
		baseTTL = tpm.config.MaxTTL
	}
	
	return baseTTL, nil
}

// getBaseTTL returns the base TTL for a request type
func (tpm *TTLPolicyManager) getBaseTTL(requestType string) time.Duration {
	if ttl, exists := tpm.config.BasePolicies[requestType]; exists {
		return ttl
	}
	return tpm.config.DefaultTTL
}

// applyConfidenceBasedTTL adjusts TTL based on content analysis confidence
func (tpm *TTLPolicyManager) applyConfidenceBasedTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if ctx.ContentAnalysis == nil {
		return baseTTL
	}
	
	config := tpm.config.ConfidenceBasedTTL
	confidence := ctx.ContentAnalysis.Confidence
	
	var multiplier float64 = 1.0
	
	if confidence >= config.HighConfidence {
		multiplier = config.HighTTLMultiplier
	} else if confidence >= config.MediumConfidence {
		multiplier = config.MediumTTLMultiplier
	} else {
		multiplier = config.LowTTLMultiplier
	}
	
	return time.Duration(float64(baseTTL) * multiplier)
}

// applySensitivityBasedTTL adjusts TTL based on content sensitivity
func (tpm *TTLPolicyManager) applySensitivityBasedTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if ctx.ContentAnalysis == nil {
		return baseTTL
	}
	
	config := tpm.config.SensitivityBasedTTL
	sensitivity := ctx.ContentAnalysis.Sensitivity
	
	// Apply sensitivity-specific TTL if configured
	if ttl, exists := config.LevelTTL[sensitivity]; exists {
		baseTTL = ttl
	}
	
	// Reduce TTL for PII content
	if ctx.ContentAnalysis.HasPII {
		baseTTL = time.Duration(float64(baseTTL) * config.PIIMultiplier)
	}
	
	return baseTTL
}

// applySizeBasedTTL adjusts TTL based on response size
func (tpm *TTLPolicyManager) applySizeBasedTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if ctx.Response == nil {
		return baseTTL
	}
	
	config := tpm.config.SizeBasedTTL
	responseSize := int64(len(ctx.Response.Body))
	
	var multiplier float64 = 1.0
	
	if responseSize <= config.SmallResponse {
		multiplier = config.SmallTTLMultiplier
	} else if responseSize <= config.MediumResponse {
		multiplier = config.MediumTTLMultiplier
	} else {
		multiplier = config.LargeTTLMultiplier
	}
	
	return time.Duration(float64(baseTTL) * multiplier)
}

// applyDynamicRules applies dynamic TTL rules in priority order
func (tpm *TTLPolicyManager) applyDynamicRules(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if len(tpm.dynamicRules) == 0 {
		return baseTTL
	}
	
	// Sort rules by priority
	sortedRules := make([]*DynamicTTLRule, len(tpm.dynamicRules))
	copy(sortedRules, tpm.dynamicRules)
	sort.Slice(sortedRules, func(i, j int) bool {
		return sortedRules[i].Priority < sortedRules[j].Priority
	})
	
	currentTTL := baseTTL
	
	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}
		
		// Check if rule conditions are met
		if tpm.evaluateRuleConditions(rule.Conditions, ctx) {
			currentTTL = tpm.applyTTLModifier(currentTTL, rule.TTLModifier)
		}
	}
	
	return currentTTL
}

// applyUserSpecificTTL applies user-specific TTL policies
func (tpm *TTLPolicyManager) applyUserSpecificTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if ctx.UserInfo == nil {
		return baseTTL
	}
	
	userPolicy, exists := tpm.userPolicies[ctx.UserInfo.ID]
	if !exists || !userPolicy.Enabled {
		return baseTTL
	}
	
	// Check if policy has expired
	if userPolicy.ExpiresAt != nil && time.Now().After(*userPolicy.ExpiresAt) {
		return baseTTL
	}
	
	// Apply user-specific TTL for request type if available
	if ctx.Request != nil {
		if customTTL, exists := userPolicy.CustomTTLs[ctx.Request.RequestType]; exists {
			baseTTL = customTTL
		}
	}
	
	// Apply global multiplier
	if userPolicy.GlobalMultiplier > 0 {
		baseTTL = time.Duration(float64(baseTTL) * userPolicy.GlobalMultiplier)
	}
	
	return baseTTL
}

// applyOrgSpecificTTL applies organization-specific TTL policies
func (tpm *TTLPolicyManager) applyOrgSpecificTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if ctx.OrgInfo == nil {
		return baseTTL
	}
	
	orgPolicy, exists := tpm.orgPolicies[ctx.OrgInfo.ID]
	if !exists || !orgPolicy.Enabled {
		return baseTTL
	}
	
	// Check if policy has expired
	if orgPolicy.ExpiresAt != nil && time.Now().After(*orgPolicy.ExpiresAt) {
		return baseTTL
	}
	
	// Apply org-specific TTL for request type if available
	if ctx.Request != nil {
		if customTTL, exists := orgPolicy.CustomTTLs[ctx.Request.RequestType]; exists {
			baseTTL = customTTL
		}
	}
	
	// Apply global multiplier
	if orgPolicy.GlobalMultiplier > 0 {
		baseTTL = time.Duration(float64(baseTTL) * orgPolicy.GlobalMultiplier)
	}
	
	return baseTTL
}

// applyTimeBasedTTL applies time-based TTL adjustments
func (tpm *TTLPolicyManager) applyTimeBasedTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	currentTime := ctx.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	
	// Apply business hours adjustments
	if tpm.config.BusinessHours != nil && tpm.config.BusinessHours.Enabled {
		baseTTL = tpm.applyBusinessHoursTTL(baseTTL, currentTime)
	}
	
	// Apply peak hours adjustments
	if tpm.config.PeakHours != nil && tpm.config.PeakHours.Enabled {
		baseTTL = tpm.applyPeakHoursTTL(baseTTL, currentTime)
	}
	
	// Apply time-based rules
	for _, rule := range tpm.timeBasedRules {
		if !rule.Enabled {
			continue
		}
		
		if tpm.isTimeRuleActive(rule, currentTime) {
			baseTTL = tpm.applyTTLModifier(baseTTL, rule.TTLModifier)
		}
	}
	
	return baseTTL
}

// applyAdaptiveTTL applies adaptive TTL based on usage patterns
func (tpm *TTLPolicyManager) applyAdaptiveTTL(baseTTL time.Duration, ctx *TTLCalculationContext) time.Duration {
	if tpm.config.UsageBasedAdjustment == nil || !tpm.config.UsageBasedAdjustment.Enabled {
		return baseTTL
	}
	
	config := tpm.config.UsageBasedAdjustment
	
	// Use usage stats if available
	if ctx.UsageStats != nil {
		if ctx.UsageStats.RequestsLastHour >= config.HighUsageThreshold {
			baseTTL = time.Duration(float64(baseTTL) * config.HighUsageTTLMultiplier)
		} else if ctx.UsageStats.RequestsLastHour <= config.LowUsageThreshold {
			baseTTL = time.Duration(float64(baseTTL) * config.LowUsageTTLMultiplier)
		}
	}
	
	// Use user usage patterns if available
	if ctx.UserInfo != nil && ctx.UserInfo.UsagePattern != nil {
		if ctx.UserInfo.UsagePattern.AverageRequestsPerHour >= float64(config.HighUsageThreshold) {
			baseTTL = time.Duration(float64(baseTTL) * config.HighUsageTTLMultiplier)
		} else if ctx.UserInfo.UsagePattern.AverageRequestsPerHour <= float64(config.LowUsageThreshold) {
			baseTTL = time.Duration(float64(baseTTL) * config.LowUsageTTLMultiplier)
		}
	}
	
	return baseTTL
}

// Helper methods for TTL policy calculations

// evaluateRuleConditions evaluates if dynamic rule conditions are met
func (tpm *TTLPolicyManager) evaluateRuleConditions(conditions []*TTLCondition, ctx *TTLCalculationContext) bool {
	for _, condition := range conditions {
		if !tpm.evaluateTTLCondition(condition, ctx) {
			return false
		}
	}
	return true
}

// evaluateTTLCondition evaluates a single TTL condition
func (tpm *TTLPolicyManager) evaluateTTLCondition(condition *TTLCondition, ctx *TTLCalculationContext) bool {
	fieldValue := tpm.getTTLFieldValue(condition.Field, ctx)
	result := false
	
	switch condition.Operator {
	case "equals":
		result = fieldValue == condition.Value
	case "contains":
		if strValue, ok := fieldValue.(string); ok {
			if strCondition, ok := condition.Value.(string); ok {
				result = strings.Contains(strValue, strCondition)
			}
		}
	case "greater_than":
		// Handle numeric comparisons
		result = false
	default:
		result = false
	}
	
	if condition.Negate {
		result = !result
	}
	
	return result
}

// getTTLFieldValue gets field value from TTL calculation context
func (tpm *TTLPolicyManager) getTTLFieldValue(field string, ctx *TTLCalculationContext) interface{} {
	switch field {
	case "request_type":
		if ctx.Request != nil {
			return ctx.Request.RequestType
		}
	case "user_id":
		if ctx.UserInfo != nil {
			return ctx.UserInfo.ID
		}
	case "org_id":
		if ctx.OrgInfo != nil {
			return ctx.OrgInfo.ID
		}
	case "sensitivity":
		if ctx.ContentAnalysis != nil {
			return ctx.ContentAnalysis.Sensitivity
		}
	case "confidence":
		if ctx.ContentAnalysis != nil {
			return ctx.ContentAnalysis.Confidence
		}
	}
	return nil
}

// applyTTLModifier applies a TTL modifier to the base TTL
func (tpm *TTLPolicyManager) applyTTLModifier(baseTTL time.Duration, modifier *TTLModifier) time.Duration {
	if modifier == nil {
		return baseTTL
	}
	
	var newTTL time.Duration
	
	switch modifier.Type {
	case "set":
		if duration, ok := modifier.Value.(time.Duration); ok {
			newTTL = duration
		}
	case "multiply":
		if multiplier, ok := modifier.Value.(float64); ok {
			newTTL = time.Duration(float64(baseTTL) * multiplier)
		}
	case "add":
		if addition, ok := modifier.Value.(time.Duration); ok {
			newTTL = baseTTL + addition
		}
	case "percentage":
		if percentage, ok := modifier.Value.(float64); ok {
			newTTL = time.Duration(float64(baseTTL) * (1.0 + percentage/100.0))
		}
	default:
		newTTL = baseTTL
	}
	
	// Apply bounds
	if modifier.MinTTL > 0 && newTTL < modifier.MinTTL {
		newTTL = modifier.MinTTL
	}
	if modifier.MaxTTL > 0 && newTTL > modifier.MaxTTL {
		newTTL = modifier.MaxTTL
	}
	
	return newTTL
}

// applyBusinessHoursTTL applies business hours TTL adjustments
func (tpm *TTLPolicyManager) applyBusinessHoursTTL(baseTTL time.Duration, currentTime time.Time) time.Duration {
	config := tpm.config.BusinessHours
	hour := currentTime.Hour()
	weekday := currentTime.Weekday()
	
	// Check if it's weekend
	if weekday == time.Saturday || weekday == time.Sunday {
		return time.Duration(float64(baseTTL) * config.WeekendTTLMultiplier)
	}
	
	// Check if it's business hours
	if hour >= config.StartHour && hour < config.EndHour {
		return time.Duration(float64(baseTTL) * config.BusinessTTLMultiplier)
	}
	
	// Off hours
	return time.Duration(float64(baseTTL) * config.OffHoursTTLMultiplier)
}

// applyPeakHoursTTL applies peak hours TTL adjustments
func (tpm *TTLPolicyManager) applyPeakHoursTTL(baseTTL time.Duration, currentTime time.Time) time.Duration {
	config := tpm.config.PeakHours
	hour := currentTime.Hour()
	weekday := int(currentTime.Weekday())
	
	// Check if current time is in any peak period
	for _, period := range config.PeakPeriods {
		if tpm.isInPeakPeriod(period, hour, weekday) {
			return time.Duration(float64(baseTTL) * config.PeakTTLMultiplier)
		}
	}
	
	// Off-peak hours
	return time.Duration(float64(baseTTL) * config.OffPeakTTLMultiplier)
}

// isInPeakPeriod checks if current time is in peak period
func (tpm *TTLPolicyManager) isInPeakPeriod(period PeakPeriod, hour, weekday int) bool {
	// Check if weekday matches
	dayMatches := false
	for _, day := range period.Days {
		if day == weekday {
			dayMatches = true
			break
		}
	}
	
	if !dayMatches {
		return false
	}
	
	// Check if hour is in range
	return hour >= period.StartHour && hour < period.EndHour
}

// isTimeRuleActive checks if a time-based rule is currently active
func (tpm *TTLPolicyManager) isTimeRuleActive(rule *TimeBasedTTLRule, currentTime time.Time) bool {
	if rule.Schedule == nil {
		return false
	}
	
	switch rule.Schedule.Type {
	case "daily":
		// Simple daily check - could be enhanced with time parsing
		return true
	case "weekly":
		// Simple weekly check - could be enhanced
		return true
	case "interval":
		// For intervals, assume it's always active (would need state tracking for proper implementation)
		return true
	default:
		return false
	}
}

// Management methods for TTL policies

// AddDynamicRule adds a dynamic TTL rule
func (tpm *TTLPolicyManager) AddDynamicRule(rule *DynamicTTLRule) error {
	tpm.dynamicRules = append(tpm.dynamicRules, rule)
	return nil
}

// AddUserPolicy adds a user-specific TTL policy
func (tpm *TTLPolicyManager) AddUserPolicy(policy *UserTTLPolicy) error {
	tpm.userPolicies[policy.UserID] = policy
	return nil
}

// AddOrgPolicy adds an organization-specific TTL policy
func (tpm *TTLPolicyManager) AddOrgPolicy(policy *OrgTTLPolicy) error {
	tpm.orgPolicies[policy.OrgID] = policy
	return nil
}

// AddTimeBasedRule adds a time-based TTL rule
func (tpm *TTLPolicyManager) AddTimeBasedRule(rule *TimeBasedTTLRule) error {
	tpm.timeBasedRules = append(tpm.timeBasedRules, rule)
	return nil
}

// RemoveDynamicRule removes a dynamic TTL rule by ID
func (tpm *TTLPolicyManager) RemoveDynamicRule(ruleID string) error {
	for i, rule := range tpm.dynamicRules {
		if rule.ID == ruleID {
			tpm.dynamicRules = append(tpm.dynamicRules[:i], tpm.dynamicRules[i+1:]...)
			return nil
		}
	}
	return nil
}

// RemoveUserPolicy removes a user-specific TTL policy
func (tpm *TTLPolicyManager) RemoveUserPolicy(userID string) error {
	delete(tpm.userPolicies, userID)
	return nil
}

// RemoveOrgPolicy removes an organization-specific TTL policy
func (tpm *TTLPolicyManager) RemoveOrgPolicy(orgID string) error {
	delete(tpm.orgPolicies, orgID)
	return nil
}

// GetDynamicRules returns all dynamic TTL rules
func (tpm *TTLPolicyManager) GetDynamicRules() []*DynamicTTLRule {
	return tpm.dynamicRules
}

// GetUserPolicies returns all user-specific TTL policies
func (tpm *TTLPolicyManager) GetUserPolicies() map[string]*UserTTLPolicy {
	return tpm.userPolicies
}

// GetOrgPolicies returns all organization-specific TTL policies
func (tpm *TTLPolicyManager) GetOrgPolicies() map[string]*OrgTTLPolicy {
	return tpm.orgPolicies
}

// getDefaultTTLPolicyConfig returns default TTL policy configuration
func getDefaultTTLPolicyConfig() *TTLPolicyConfig {
	return &TTLPolicyConfig{
		BasePolicies: map[string]time.Duration{
			"chat":       15 * time.Minute,
			"completion": 30 * time.Minute,
			"embedding":  2 * time.Hour,
			"image":      1 * time.Hour,
			"default":    1 * time.Hour,
		},
		DefaultTTL:            1 * time.Hour,
		DynamicTTLEnabled:     true,
		UserSpecificEnabled:   true,
		OrgSpecificEnabled:    true,
		TimeBasedEnabled:      true,
		AdaptiveTTLEnabled:    true,
		MinTTL:               1 * time.Minute,
		MaxTTL:               24 * time.Hour,
		ConfidenceBasedTTL: &ConfidenceTTLConfig{
			Enabled:             true,
			HighConfidence:      0.9,
			MediumConfidence:    0.7,
			LowConfidence:       0.5,
			HighTTLMultiplier:   2.0,
			MediumTTLMultiplier: 1.0,
			LowTTLMultiplier:    0.5,
		},
		SensitivityBasedTTL: &SensitivityTTLConfig{
			Enabled: true,
			LevelTTL: map[string]time.Duration{
				"public":       2 * time.Hour,
				"internal":     1 * time.Hour,
				"confidential": 30 * time.Minute,
				"restricted":   10 * time.Minute,
			},
			PIIMultiplier: 0.3,
		},
		SizeBasedTTL: &SizeTTLConfig{
			Enabled:             true,
			SmallResponse:       1024,      // 1KB
			MediumResponse:      102400,    // 100KB
			LargeResponse:       1048576,   // 1MB
			SmallTTLMultiplier:  1.5,
			MediumTTLMultiplier: 1.0,
			LargeTTLMultiplier:  0.8,
		},
		BusinessHours: &BusinessHoursConfig{
			Enabled:               true,
			StartHour:             9,
			EndHour:               17,
			Timezone:              "UTC",
			BusinessTTLMultiplier: 1.0,
			OffHoursTTLMultiplier: 2.0,
			WeekendTTLMultiplier:  3.0,
		},
		UsageBasedAdjustment: &UsageBasedConfig{
			Enabled:                true,
			HighUsageThreshold:     100,
			LowUsageThreshold:      10,
			HighUsageTTLMultiplier: 2.0,
			LowUsageTTLMultiplier:  0.5,
			AdaptationInterval:     1 * time.Hour,
		},
	}
} 