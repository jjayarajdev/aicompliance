package ratelimit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// RateLimitManager coordinates all rate limiting functionality
type RateLimitManager struct {
	slidingWindow   *SlidingWindowRateLimiter
	config          *RateLimitConfig
	logger          *logrus.Logger
	quotaStore      *QuotaStore
	violationLogger *ViolationLogger
	analytics       interface{} // Analytics placeholder - removed for now
	mu              sync.RWMutex
}

// RateLimitConfig holds comprehensive rate limiting configuration
type RateLimitConfig struct {
	// Core settings
	Enabled              bool                    `json:"enabled" yaml:"enabled"`
	DefaultUserLimits    *UserRateLimits        `json:"default_user_limits" yaml:"default_user_limits"`
	DefaultOrgLimits     *OrgRateLimits         `json:"default_org_limits" yaml:"default_org_limits"`
	PerEndpointLimits    map[string]*EndpointLimits `json:"per_endpoint_limits" yaml:"per_endpoint_limits"`
	
	// Sliding window settings
	SlidingWindowConfig  *SlidingWindowConfig   `json:"sliding_window" yaml:"sliding_window"`
	
	// Advanced features
	BurstAllowance       float64                `json:"burst_allowance" yaml:"burst_allowance"`
	GracePeriod          time.Duration          `json:"grace_period" yaml:"grace_period"`
	BackoffMultiplier    float64                `json:"backoff_multiplier" yaml:"backoff_multiplier"`
	MaxBackoff           time.Duration          `json:"max_backoff" yaml:"max_backoff"`
	
	// Monitoring
	EnableAnalytics      bool                   `json:"enable_analytics" yaml:"enable_analytics"`
	AnalyticsRetention   time.Duration          `json:"analytics_retention" yaml:"analytics_retention"`
	AlertThresholds      *AlertThresholds       `json:"alert_thresholds" yaml:"alert_thresholds"`
	
	// Storage
	Redis                *RedisConfig           `json:"redis" yaml:"redis"`
}

// UserRateLimits defines rate limits for a user across different time windows
type UserRateLimits struct {
	RequestsPerSecond    int64   `json:"requests_per_second" yaml:"requests_per_second"`
	RequestsPerMinute    int64   `json:"requests_per_minute" yaml:"requests_per_minute"`
	RequestsPerHour      int64   `json:"requests_per_hour" yaml:"requests_per_hour"`
	RequestsPerDay       int64   `json:"requests_per_day" yaml:"requests_per_day"`
	TokensPerMinute      int64   `json:"tokens_per_minute" yaml:"tokens_per_minute"`
	TokensPerHour        int64   `json:"tokens_per_hour" yaml:"tokens_per_hour"`
	TokensPerDay         int64   `json:"tokens_per_day" yaml:"tokens_per_day"`
	ConcurrentRequests   int     `json:"concurrent_requests" yaml:"concurrent_requests"`
	UserTier             string  `json:"user_tier" yaml:"user_tier"`
}

// OrgRateLimits defines organization-wide rate limits
type OrgRateLimits struct {
	RequestsPerSecond    int64   `json:"requests_per_second" yaml:"requests_per_second"`
	RequestsPerMinute    int64   `json:"requests_per_minute" yaml:"requests_per_minute"`
	RequestsPerHour      int64   `json:"requests_per_hour" yaml:"requests_per_hour"`
	RequestsPerDay       int64   `json:"requests_per_day" yaml:"requests_per_day"`
	TokensPerMinute      int64   `json:"tokens_per_minute" yaml:"tokens_per_minute"`
	TokensPerHour        int64   `json:"tokens_per_hour" yaml:"tokens_per_hour"`
	TokensPerDay         int64   `json:"tokens_per_day" yaml:"tokens_per_day"`
	ConcurrentRequests   int     `json:"concurrent_requests" yaml:"concurrent_requests"`
	MaxUsersPerOrg       int     `json:"max_users_per_org" yaml:"max_users_per_org"`
	OrgTier              string  `json:"org_tier" yaml:"org_tier"`
}

// EndpointLimits defines per-endpoint rate limits
type EndpointLimits struct {
	RequestsPerSecond    int64   `json:"requests_per_second" yaml:"requests_per_second"`
	RequestsPerMinute    int64   `json:"requests_per_minute" yaml:"requests_per_minute"`
	RequestsPerHour      int64   `json:"requests_per_hour" yaml:"requests_per_hour"`
	TokensPerMinute      int64   `json:"tokens_per_minute" yaml:"tokens_per_minute"`
	ConcurrentRequests   int     `json:"concurrent_requests" yaml:"concurrent_requests"`
	CostMultiplier       float64 `json:"cost_multiplier" yaml:"cost_multiplier"`
}

// AlertThresholds defines when to trigger alerts
type AlertThresholds struct {
	WarningThreshold     float64 `json:"warning_threshold" yaml:"warning_threshold"`     // 80%
	CriticalThreshold    float64 `json:"critical_threshold" yaml:"critical_threshold"` // 95%
	ViolationCount       int     `json:"violation_count" yaml:"violation_count"`       // 10 violations
	ViolationWindow      time.Duration `json:"violation_window" yaml:"violation_window"` // 5 minutes
}

// RedisConfig holds Redis-specific configuration
type RedisConfig struct {
	Address              string        `json:"address" yaml:"address"`
	Password             string        `json:"password" yaml:"password"`
	DB                   int           `json:"db" yaml:"db"`
	PoolSize             int           `json:"pool_size" yaml:"pool_size"`
	ReadTimeout          time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout         time.Duration `json:"write_timeout" yaml:"write_timeout"`
	DialTimeout          time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	MaxRetries           int           `json:"max_retries" yaml:"max_retries"`
}

// RateLimitCheckRequest represents a complete rate limit check
type RateLimitCheckRequest struct {
	UserID       string            `json:"user_id"`
	OrgID        string            `json:"org_id"`
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	ClientIP     string            `json:"client_ip"`
	UserAgent    string            `json:"user_agent"`
	TokenCount   int64             `json:"token_count"`
	Headers      map[string]string `json:"headers"`
	Metadata     map[string]string `json:"metadata"`
	Timestamp    time.Time         `json:"timestamp"`
}

// RateLimitCheckResponse represents the comprehensive response
type RateLimitCheckResponse struct {
	Allowed              bool                      `json:"allowed"`
	DenialReason         string                    `json:"denial_reason,omitempty"`
	
	// Per-window results
	UserLimits           map[string]*RateLimitResult `json:"user_limits"`
	OrgLimits            map[string]*RateLimitResult `json:"org_limits"`
	EndpointLimits       map[string]*RateLimitResult `json:"endpoint_limits"`
	IPLimits             map[string]*RateLimitResult `json:"ip_limits"`
	
	// Quota information
	UserQuota            *QuotaStatus              `json:"user_quota"`
	OrgQuota             *QuotaStatus              `json:"org_quota"`
	
	// Response headers for client
	RateLimitHeaders     map[string]string         `json:"rate_limit_headers"`
	
	// Performance
	CheckLatency         time.Duration             `json:"check_latency"`
	ProcessingDetails    map[string]interface{}    `json:"processing_details"`
}

// QuotaStatus represents current quota usage
type QuotaStatus struct {
	Used                 int64     `json:"used"`
	Limit                int64     `json:"limit"`
	Remaining            int64     `json:"remaining"`
	ResetTime            time.Time `json:"reset_time"`
	Period               string    `json:"period"`
	PercentageUsed       float64   `json:"percentage_used"`
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager(redisClient *redis.Client, config *RateLimitConfig, logger *logrus.Logger) (*RateLimitManager, error) {
	if config == nil {
		config = getDefaultRateLimitConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	// Initialize sliding window rate limiter
	slidingWindow := NewSlidingWindowRateLimiter(redisClient, config.SlidingWindowConfig, logger)
	
	// Initialize quota store
	quotaStore, err := NewQuotaStore(redisClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize quota store: %w", err)
	}
	
	// Initialize violation logger
	violationLogger := NewViolationLogger(logger)
	
	// Initialize analytics
	var analytics interface{} // Analytics placeholder - removed for now
	
	return &RateLimitManager{
		slidingWindow:   slidingWindow,
		config:          config,
		logger:          logger,
		quotaStore:      quotaStore,
		violationLogger: violationLogger,
		analytics:       analytics,
	}, nil
}

// CheckRateLimit performs comprehensive rate limit checking
func (rlm *RateLimitManager) CheckRateLimit(ctx context.Context, request *RateLimitCheckRequest) (*RateLimitCheckResponse, error) {
	start := time.Now()
	
	if !rlm.config.Enabled {
		return &RateLimitCheckResponse{
			Allowed:           true,
			CheckLatency:      time.Since(start),
			ProcessingDetails: map[string]interface{}{"rate_limiting": "disabled"},
		}, nil
	}
	
	response := &RateLimitCheckResponse{
		UserLimits:        make(map[string]*RateLimitResult),
		OrgLimits:         make(map[string]*RateLimitResult),
		EndpointLimits:    make(map[string]*RateLimitResult),
		IPLimits:          make(map[string]*RateLimitResult),
		RateLimitHeaders:  make(map[string]string),
		ProcessingDetails: make(map[string]interface{}),
		Allowed:           true,
	}
	
	// Check user-level rate limits across multiple time windows
	userLimits := rlm.getUserLimits(request.UserID)
	userAllowed, err := rlm.checkUserRateLimits(ctx, request, userLimits, response)
	if err != nil {
		return nil, fmt.Errorf("user rate limit check failed: %w", err)
	}
	
	// Check organization-level rate limits
	orgLimits := rlm.getOrgLimits(request.OrgID)
	orgAllowed, err := rlm.checkOrgRateLimits(ctx, request, orgLimits, response)
	if err != nil {
		return nil, fmt.Errorf("org rate limit check failed: %w", err)
	}
	
	// Check endpoint-specific rate limits
	endpointLimits := rlm.getEndpointLimits(request.Endpoint)
	endpointAllowed, err := rlm.checkEndpointRateLimits(ctx, request, endpointLimits, response)
	if err != nil {
		return nil, fmt.Errorf("endpoint rate limit check failed: %w", err)
	}
	
	// Check IP-based rate limits (for DDoS protection)
	ipAllowed, err := rlm.checkIPRateLimits(ctx, request, response)
	if err != nil {
		return nil, fmt.Errorf("IP rate limit check failed: %w", err)
	}
	
	// Overall decision
	response.Allowed = userAllowed && orgAllowed && endpointAllowed && ipAllowed
	
	// Get quota status
	response.UserQuota, _ = rlm.quotaStore.GetUserQuotaStatus(ctx, request.UserID)
	response.OrgQuota, _ = rlm.quotaStore.GetOrgQuotaStatus(ctx, request.OrgID)
	
	// Generate rate limit headers for HTTP responses
	rlm.generateRateLimitHeaders(response)
	
	// Log violations and update analytics
	if !response.Allowed {
		rlm.logViolation(request, response)
	}
	
	response.CheckLatency = time.Since(start)
	return response, nil
}

// checkUserRateLimits checks rate limits for a specific user
func (rlm *RateLimitManager) checkUserRateLimits(ctx context.Context, request *RateLimitCheckRequest, limits *UserRateLimits, response *RateLimitCheckResponse) (bool, error) {
	allowed := true
	
	// Check per-second limit
	if limits.RequestsPerSecond > 0 {
		rateLimitRequest := &RateLimitRequest{
			Key:        fmt.Sprintf("user:%s:second", request.UserID),
			UserID:     request.UserID,
			OrgID:      request.OrgID,
			Endpoint:   request.Endpoint,
			Method:     request.Method,
			ClientIP:   request.ClientIP,
			TokenCount: request.TokenCount,
			Timestamp:  request.Timestamp,
		}
		
		// Use 1-second window for per-second limits
		windowConfig := &SlidingWindowConfig{
			RedisKeyPrefix: rlm.config.SlidingWindowConfig.RedisKeyPrefix,
			WindowSize:     1 * time.Second,
			SubWindowCount: 4, // 250ms sub-windows
			KeyTTL:         10 * time.Second,
		}
		
		limiter := NewSlidingWindowRateLimiter(rlm.slidingWindow.redisClient, windowConfig, rlm.logger)
		result, err := limiter.CheckRateLimit(ctx, rateLimitRequest, limits.RequestsPerSecond)
		if err != nil {
			return false, err
		}
		
		response.UserLimits["per_second"] = result
		if !result.Allowed {
			allowed = false
			response.DenialReason = "User per-second rate limit exceeded"
		}
	}
	
	// Check per-minute limit
	if limits.RequestsPerMinute > 0 {
		rateLimitRequest := &RateLimitRequest{
			Key:        fmt.Sprintf("user:%s:minute", request.UserID),
			UserID:     request.UserID,
			OrgID:      request.OrgID,
			Endpoint:   request.Endpoint,
			Method:     request.Method,
			ClientIP:   request.ClientIP,
			TokenCount: request.TokenCount,
			Timestamp:  request.Timestamp,
		}
		
		result, err := rlm.slidingWindow.CheckRateLimit(ctx, rateLimitRequest, limits.RequestsPerMinute)
		if err != nil {
			return false, err
		}
		
		response.UserLimits["per_minute"] = result
		if !result.Allowed {
			allowed = false
			if response.DenialReason == "" {
				response.DenialReason = "User per-minute rate limit exceeded"
			}
		}
	}
	
	// Check per-hour limit
	if limits.RequestsPerHour > 0 {
		rateLimitRequest := &RateLimitRequest{
			Key:        fmt.Sprintf("user:%s:hour", request.UserID),
			UserID:     request.UserID,
			OrgID:      request.OrgID,
			Endpoint:   request.Endpoint,
			Method:     request.Method,
			ClientIP:   request.ClientIP,
			TokenCount: request.TokenCount,
			Timestamp:  request.Timestamp,
		}
		
		// Use 1-hour window
		windowConfig := &SlidingWindowConfig{
			RedisKeyPrefix: rlm.config.SlidingWindowConfig.RedisKeyPrefix,
			WindowSize:     1 * time.Hour,
			SubWindowCount: 12, // 5-minute sub-windows
			KeyTTL:         3 * time.Hour,
		}
		
		limiter := NewSlidingWindowRateLimiter(rlm.slidingWindow.redisClient, windowConfig, rlm.logger)
		result, err := limiter.CheckRateLimit(ctx, rateLimitRequest, limits.RequestsPerHour)
		if err != nil {
			return false, err
		}
		
		response.UserLimits["per_hour"] = result
		if !result.Allowed {
			allowed = false
			if response.DenialReason == "" {
				response.DenialReason = "User per-hour rate limit exceeded"
			}
		}
	}
	
	// Check per-day limit
	if limits.RequestsPerDay > 0 {
		rateLimitRequest := &RateLimitRequest{
			Key:        fmt.Sprintf("user:%s:day", request.UserID),
			UserID:     request.UserID,
			OrgID:      request.OrgID,
			Endpoint:   request.Endpoint,
			Method:     request.Method,
			ClientIP:   request.ClientIP,
			TokenCount: request.TokenCount,
			Timestamp:  request.Timestamp,
		}
		
		// Use 24-hour window
		windowConfig := &SlidingWindowConfig{
			RedisKeyPrefix: rlm.config.SlidingWindowConfig.RedisKeyPrefix,
			WindowSize:     24 * time.Hour,
			SubWindowCount: 24, // 1-hour sub-windows
			KeyTTL:         48 * time.Hour,
		}
		
		limiter := NewSlidingWindowRateLimiter(rlm.slidingWindow.redisClient, windowConfig, rlm.logger)
		result, err := limiter.CheckRateLimit(ctx, rateLimitRequest, limits.RequestsPerDay)
		if err != nil {
			return false, err
		}
		
		response.UserLimits["per_day"] = result
		if !result.Allowed {
			allowed = false
			if response.DenialReason == "" {
				response.DenialReason = "User per-day rate limit exceeded"
			}
		}
	}
	
	return allowed, nil
}

// checkOrgRateLimits checks organization-level rate limits
func (rlm *RateLimitManager) checkOrgRateLimits(ctx context.Context, request *RateLimitCheckRequest, limits *OrgRateLimits, response *RateLimitCheckResponse) (bool, error) {
	allowed := true
	
	// Similar implementation to user limits but for organization
	if limits.RequestsPerMinute > 0 {
		rateLimitRequest := &RateLimitRequest{
			Key:        fmt.Sprintf("org:%s:minute", request.OrgID),
			UserID:     request.UserID,
			OrgID:      request.OrgID,
			Endpoint:   request.Endpoint,
			Method:     request.Method,
			ClientIP:   request.ClientIP,
			TokenCount: request.TokenCount,
			Timestamp:  request.Timestamp,
		}
		
		result, err := rlm.slidingWindow.CheckRateLimit(ctx, rateLimitRequest, limits.RequestsPerMinute)
		if err != nil {
			return false, err
		}
		
		response.OrgLimits["per_minute"] = result
		if !result.Allowed {
			allowed = false
			if response.DenialReason == "" {
				response.DenialReason = "Organization per-minute rate limit exceeded"
			}
		}
	}
	
	return allowed, nil
}

// checkEndpointRateLimits checks endpoint-specific rate limits
func (rlm *RateLimitManager) checkEndpointRateLimits(ctx context.Context, request *RateLimitCheckRequest, limits *EndpointLimits, response *RateLimitCheckResponse) (bool, error) {
	if limits == nil {
		return true, nil
	}
	
	allowed := true
	
	if limits.RequestsPerMinute > 0 {
		rateLimitRequest := &RateLimitRequest{
			Key:        fmt.Sprintf("endpoint:%s:user:%s:minute", request.Endpoint, request.UserID),
			UserID:     request.UserID,
			OrgID:      request.OrgID,
			Endpoint:   request.Endpoint,
			Method:     request.Method,
			ClientIP:   request.ClientIP,
			TokenCount: int64(float64(request.TokenCount) * limits.CostMultiplier),
			Timestamp:  request.Timestamp,
		}
		
		result, err := rlm.slidingWindow.CheckRateLimit(ctx, rateLimitRequest, limits.RequestsPerMinute)
		if err != nil {
			return false, err
		}
		
		response.EndpointLimits["per_minute"] = result
		if !result.Allowed {
			allowed = false
			if response.DenialReason == "" {
				response.DenialReason = fmt.Sprintf("Endpoint %s rate limit exceeded", request.Endpoint)
			}
		}
	}
	
	return allowed, nil
}

// checkIPRateLimits checks IP-based rate limits for DDoS protection
func (rlm *RateLimitManager) checkIPRateLimits(ctx context.Context, request *RateLimitCheckRequest, response *RateLimitCheckResponse) (bool, error) {
	// Basic IP rate limiting - 1000 requests per minute per IP
	rateLimitRequest := &RateLimitRequest{
		Key:        fmt.Sprintf("ip:%s:minute", request.ClientIP),
		UserID:     request.UserID,
		OrgID:      request.OrgID,
		Endpoint:   request.Endpoint,
		Method:     request.Method,
		ClientIP:   request.ClientIP,
		TokenCount: request.TokenCount,
		Timestamp:  request.Timestamp,
	}
	
	result, err := rlm.slidingWindow.CheckRateLimit(ctx, rateLimitRequest, 1000)
	if err != nil {
		return false, err
	}
	
	response.IPLimits["per_minute"] = result
	if !result.Allowed {
		response.DenialReason = "IP rate limit exceeded - potential DDoS detected"
		return false, nil
	}
	
	return true, nil
}

// Helper methods for getting limits

func (rlm *RateLimitManager) getUserLimits(userID string) *UserRateLimits {
	// In production, this would fetch from database/cache based on user tier
	// For now, return default limits
	return rlm.config.DefaultUserLimits
}

func (rlm *RateLimitManager) getOrgLimits(orgID string) *OrgRateLimits {
	// In production, this would fetch from database/cache based on org tier
	// For now, return default limits
	return rlm.config.DefaultOrgLimits
}

func (rlm *RateLimitManager) getEndpointLimits(endpoint string) *EndpointLimits {
	// Clean endpoint path for lookup
	cleanEndpoint := strings.Split(endpoint, "?")[0] // Remove query params
	return rlm.config.PerEndpointLimits[cleanEndpoint]
}

// generateRateLimitHeaders generates HTTP headers for rate limiting
func (rlm *RateLimitManager) generateRateLimitHeaders(response *RateLimitCheckResponse) {
	if len(response.UserLimits) > 0 {
		// Use per-minute limits as primary headers
		if minuteLimit, exists := response.UserLimits["per_minute"]; exists {
			response.RateLimitHeaders["X-RateLimit-Limit"] = fmt.Sprintf("%d", minuteLimit.Limit)
			response.RateLimitHeaders["X-RateLimit-Remaining"] = fmt.Sprintf("%d", minuteLimit.Remaining)
			response.RateLimitHeaders["X-RateLimit-Reset"] = fmt.Sprintf("%d", minuteLimit.ResetTime.Unix())
			
			if !minuteLimit.Allowed {
				response.RateLimitHeaders["Retry-After"] = fmt.Sprintf("%.0f", minuteLimit.RetryAfter.Seconds())
			}
		}
	}
}

// logViolation logs rate limit violations
func (rlm *RateLimitManager) logViolation(request *RateLimitCheckRequest, response *RateLimitCheckResponse) {
	rlm.violationLogger.LogViolation(&ViolationEvent{
		UserID:       request.UserID,
		OrgID:        request.OrgID,
		Endpoint:     request.Endpoint,
		ClientIP:     request.ClientIP,
		Reason:       response.DenialReason,
		Timestamp:    time.Now(),
		UserLimits:   response.UserLimits,
		OrgLimits:    response.OrgLimits,
		EndpointLimits: response.EndpointLimits,
	})
}

// GetMetrics returns comprehensive rate limiting metrics
func (rlm *RateLimitManager) GetMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})
	
	// Sliding window metrics
	if swMetrics := rlm.slidingWindow.GetMetrics(); swMetrics != nil {
		metrics["sliding_window"] = swMetrics
	}
	
	// Analytics metrics
	// Temporarily commented out analytics integration
	// if rlm.analytics != nil {
	//     metrics["analytics"] = rlm.analytics.GetMetrics()
	// }
	
	// Quota metrics
	if quotaMetrics := rlm.quotaStore.GetMetrics(); quotaMetrics != nil {
		metrics["quota"] = quotaMetrics
	}
	
	return metrics
}

// getDefaultRateLimitConfig returns default configuration
func getDefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled: true,
		DefaultUserLimits: &UserRateLimits{
			RequestsPerSecond: 10,
			RequestsPerMinute: 100,
			RequestsPerHour:   1000,
			RequestsPerDay:    10000,
			TokensPerMinute:   50000,
			TokensPerHour:     500000,
			TokensPerDay:      5000000,
			ConcurrentRequests: 10,
			UserTier:          "free",
		},
		DefaultOrgLimits: &OrgRateLimits{
			RequestsPerSecond: 100,
			RequestsPerMinute: 1000,
			RequestsPerHour:   10000,
			RequestsPerDay:    100000,
			TokensPerMinute:   500000,
			TokensPerHour:     5000000,
			TokensPerDay:      50000000,
			ConcurrentRequests: 100,
			MaxUsersPerOrg:    50,
			OrgTier:           "standard",
		},
		PerEndpointLimits: map[string]*EndpointLimits{
			"/v1/chat/completions": {
				RequestsPerSecond:  5,
				RequestsPerMinute:  50,
				RequestsPerHour:    500,
				TokensPerMinute:    25000,
				ConcurrentRequests: 5,
				CostMultiplier:     1.0,
			},
			"/v1/completions": {
				RequestsPerSecond:  10,
				RequestsPerMinute:  100,
				RequestsPerHour:    1000,
				TokensPerMinute:    50000,
				ConcurrentRequests: 10,
				CostMultiplier:     0.8,
			},
			"/v1/embeddings": {
				RequestsPerSecond:  20,
				RequestsPerMinute:  200,
				RequestsPerHour:    2000,
				TokensPerMinute:    100000,
				ConcurrentRequests: 15,
				CostMultiplier:     0.5,
			},
		},
		SlidingWindowConfig: getDefaultSlidingWindowConfig(),
		BurstAllowance:      1.5,
		GracePeriod:         30 * time.Second,
		BackoffMultiplier:   2.0,
		MaxBackoff:          5 * time.Minute,
		EnableAnalytics:     true,
		AnalyticsRetention:  30 * 24 * time.Hour, // 30 days
		AlertThresholds: &AlertThresholds{
			WarningThreshold:  80.0,
			CriticalThreshold: 95.0,
			ViolationCount:    10,
			ViolationWindow:   5 * time.Minute,
		},
	}
} 