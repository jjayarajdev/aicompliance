package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// QuotaStore manages user and organization quotas
type QuotaStore struct {
	redisClient *redis.Client
	logger      *logrus.Logger
	config      *QuotaStoreConfig
	metrics     *QuotaMetrics
	mu          sync.RWMutex
}

// QuotaStoreConfig holds quota store configuration
type QuotaStoreConfig struct {
	RedisKeyPrefix    string        `json:"redis_key_prefix" yaml:"redis_key_prefix"`
	DefaultTTL        time.Duration `json:"default_ttl" yaml:"default_ttl"`
	CleanupInterval   time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	EnableMetrics     bool          `json:"enable_metrics" yaml:"enable_metrics"`
}

// QuotaMetrics tracks quota store performance
type QuotaMetrics struct {
	TotalQueries      int64         `json:"total_queries"`
	CacheHits         int64         `json:"cache_hits"`
	CacheMisses       int64         `json:"cache_misses"`
	UpdateOperations  int64         `json:"update_operations"`
	AverageLatency    time.Duration `json:"average_latency"`
	RedisErrors       int64         `json:"redis_errors"`
	
	mu sync.RWMutex
}

// UserQuota represents a user's quota information
type UserQuota struct {
	UserID              string            `json:"user_id"`
	OrgID               string            `json:"org_id"`
	Tier                string            `json:"tier"`
	RequestsPerSecond   int64             `json:"requests_per_second"`
	RequestsPerMinute   int64             `json:"requests_per_minute"`
	RequestsPerHour     int64             `json:"requests_per_hour"`
	RequestsPerDay      int64             `json:"requests_per_day"`
	TokensPerMinute     int64             `json:"tokens_per_minute"`
	TokensPerHour       int64             `json:"tokens_per_hour"`
	TokensPerDay        int64             `json:"tokens_per_day"`
	CustomLimits        map[string]int64  `json:"custom_limits"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	ExpiresAt           *time.Time        `json:"expires_at,omitempty"`
}

// OrgQuota represents an organization's quota information
type OrgQuota struct {
	OrgID               string            `json:"org_id"`
	Tier                string            `json:"tier"`
	RequestsPerSecond   int64             `json:"requests_per_second"`
	RequestsPerMinute   int64             `json:"requests_per_minute"`
	RequestsPerHour     int64             `json:"requests_per_hour"`
	RequestsPerDay      int64             `json:"requests_per_day"`
	TokensPerMinute     int64             `json:"tokens_per_minute"`
	TokensPerHour       int64             `json:"tokens_per_hour"`
	TokensPerDay        int64             `json:"tokens_per_day"`
	MaxUsers            int               `json:"max_users"`
	CustomLimits        map[string]int64  `json:"custom_limits"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
	ExpiresAt           *time.Time        `json:"expires_at,omitempty"`
}

// QuotaUsage tracks actual usage for a quota period
type QuotaUsage struct {
	Period            string    `json:"period"`         // "minute", "hour", "day"
	StartTime         time.Time `json:"start_time"`
	EndTime           time.Time `json:"end_time"`
	RequestCount      int64     `json:"request_count"`
	TokenCount        int64     `json:"token_count"`
	LastUpdated       time.Time `json:"last_updated"`
}

// ViolationEvent represents a rate limit violation
type ViolationEvent struct {
	UserID         string                       `json:"user_id"`
	OrgID          string                       `json:"org_id"`
	Endpoint       string                       `json:"endpoint"`
	ClientIP       string                       `json:"client_ip"`
	Reason         string                       `json:"reason"`
	Timestamp      time.Time                    `json:"timestamp"`
	UserLimits     map[string]*RateLimitResult  `json:"user_limits"`
	OrgLimits      map[string]*RateLimitResult  `json:"org_limits"`
	EndpointLimits map[string]*RateLimitResult  `json:"endpoint_limits"`
}

// NewQuotaStore creates a new quota store
func NewQuotaStore(redisClient *redis.Client, logger *logrus.Logger) (*QuotaStore, error) {
	config := &QuotaStoreConfig{
		RedisKeyPrefix:  "ai_gateway:quota:",
		DefaultTTL:      24 * time.Hour,
		CleanupInterval: 1 * time.Hour,
		EnableMetrics:   true,
	}
	
	qs := &QuotaStore{
		redisClient: redisClient,
		logger:      logger,
		config:      config,
		metrics:     &QuotaMetrics{},
	}
	
	// Start background cleanup
	go qs.startCleanupWorker()
	
	return qs, nil
}

// GetUserQuota retrieves user quota information
func (qs *QuotaStore) GetUserQuota(ctx context.Context, userID string) (*UserQuota, error) {
	start := time.Now()
	defer qs.updateMetrics(time.Since(start))
	
	key := fmt.Sprintf("%suser:%s", qs.config.RedisKeyPrefix, userID)
	
	data, err := qs.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			qs.recordCacheMiss()
			return qs.getDefaultUserQuota(userID), nil
		}
		qs.recordError()
		return nil, fmt.Errorf("failed to get user quota: %w", err)
	}
	
	qs.recordCacheHit()
	
	var quota UserQuota
	if err := json.Unmarshal([]byte(data), &quota); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user quota: %w", err)
	}
	
	return &quota, nil
}

// SetUserQuota stores user quota information
func (qs *QuotaStore) SetUserQuota(ctx context.Context, quota *UserQuota) error {
	start := time.Now()
	defer qs.updateMetrics(time.Since(start))
	
	quota.UpdatedAt = time.Now()
	
	data, err := json.Marshal(quota)
	if err != nil {
		return fmt.Errorf("failed to marshal user quota: %w", err)
	}
	
	key := fmt.Sprintf("%suser:%s", qs.config.RedisKeyPrefix, quota.UserID)
	
	ttl := qs.config.DefaultTTL
	if quota.ExpiresAt != nil {
		ttl = quota.ExpiresAt.Sub(time.Now())
		if ttl <= 0 {
			ttl = qs.config.DefaultTTL
		}
	}
	
	err = qs.redisClient.Set(ctx, key, data, ttl).Err()
	if err != nil {
		qs.recordError()
		return fmt.Errorf("failed to set user quota: %w", err)
	}
	
	qs.recordUpdate()
	return nil
}

// GetOrgQuota retrieves organization quota information
func (qs *QuotaStore) GetOrgQuota(ctx context.Context, orgID string) (*OrgQuota, error) {
	start := time.Now()
	defer qs.updateMetrics(time.Since(start))
	
	key := fmt.Sprintf("%sorg:%s", qs.config.RedisKeyPrefix, orgID)
	
	data, err := qs.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			qs.recordCacheMiss()
			return qs.getDefaultOrgQuota(orgID), nil
		}
		qs.recordError()
		return nil, fmt.Errorf("failed to get org quota: %w", err)
	}
	
	qs.recordCacheHit()
	
	var quota OrgQuota
	if err := json.Unmarshal([]byte(data), &quota); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org quota: %w", err)
	}
	
	return &quota, nil
}

// SetOrgQuota stores organization quota information
func (qs *QuotaStore) SetOrgQuota(ctx context.Context, quota *OrgQuota) error {
	start := time.Now()
	defer qs.updateMetrics(time.Since(start))
	
	quota.UpdatedAt = time.Now()
	
	data, err := json.Marshal(quota)
	if err != nil {
		return fmt.Errorf("failed to marshal org quota: %w", err)
	}
	
	key := fmt.Sprintf("%sorg:%s", qs.config.RedisKeyPrefix, quota.OrgID)
	
	ttl := qs.config.DefaultTTL
	if quota.ExpiresAt != nil {
		ttl = quota.ExpiresAt.Sub(time.Now())
		if ttl <= 0 {
			ttl = qs.config.DefaultTTL
		}
	}
	
	err = qs.redisClient.Set(ctx, key, data, ttl).Err()
	if err != nil {
		qs.recordError()
		return fmt.Errorf("failed to set org quota: %w", err)
	}
	
	qs.recordUpdate()
	return nil
}

// GetUserQuotaStatus returns current quota status for a user
func (qs *QuotaStore) GetUserQuotaStatus(ctx context.Context, userID string) (*QuotaStatus, error) {
	quota, err := qs.GetUserQuota(ctx, userID)
	if err != nil {
		return nil, err
	}
	
	// Get current usage for the minute
	usage, err := qs.getUserUsage(ctx, userID, "minute")
	if err != nil {
		return nil, err
	}
	
	remaining := quota.RequestsPerMinute - usage.RequestCount
	if remaining < 0 {
		remaining = 0
	}
	
	percentageUsed := float64(usage.RequestCount) / float64(quota.RequestsPerMinute) * 100
	if percentageUsed > 100 {
		percentageUsed = 100
	}
	
	return &QuotaStatus{
		Used:           usage.RequestCount,
		Limit:          quota.RequestsPerMinute,
		Remaining:      remaining,
		ResetTime:      usage.EndTime,
		Period:         "minute",
		PercentageUsed: percentageUsed,
	}, nil
}

// GetOrgQuotaStatus returns current quota status for an organization
func (qs *QuotaStore) GetOrgQuotaStatus(ctx context.Context, orgID string) (*QuotaStatus, error) {
	quota, err := qs.GetOrgQuota(ctx, orgID)
	if err != nil {
		return nil, err
	}
	
	// Get current usage for the minute
	usage, err := qs.getOrgUsage(ctx, orgID, "minute")
	if err != nil {
		return nil, err
	}
	
	remaining := quota.RequestsPerMinute - usage.RequestCount
	if remaining < 0 {
		remaining = 0
	}
	
	percentageUsed := float64(usage.RequestCount) / float64(quota.RequestsPerMinute) * 100
	if percentageUsed > 100 {
		percentageUsed = 100
	}
	
	return &QuotaStatus{
		Used:           usage.RequestCount,
		Limit:          quota.RequestsPerMinute,
		Remaining:      remaining,
		ResetTime:      usage.EndTime,
		Period:         "minute",
		PercentageUsed: percentageUsed,
	}, nil
}

// getUserUsage gets current usage for a user in a specific period
func (qs *QuotaStore) getUserUsage(ctx context.Context, userID, period string) (*QuotaUsage, error) {
	now := time.Now()
	var startTime, endTime time.Time
	
	switch period {
	case "minute":
		startTime = now.Truncate(time.Minute)
		endTime = startTime.Add(time.Minute)
	case "hour":
		startTime = now.Truncate(time.Hour)
		endTime = startTime.Add(time.Hour)
	case "day":
		startTime = now.Truncate(24 * time.Hour)
		endTime = startTime.Add(24 * time.Hour)
	default:
		return nil, fmt.Errorf("invalid period: %s", period)
	}
	
	key := fmt.Sprintf("%susage:user:%s:%s:%d", qs.config.RedisKeyPrefix, userID, period, startTime.Unix())
	
	data, err := qs.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			// No usage data, return empty usage
			return &QuotaUsage{
				Period:       period,
				StartTime:    startTime,
				EndTime:      endTime,
				RequestCount: 0,
				TokenCount:   0,
				LastUpdated:  now,
			}, nil
		}
		return nil, fmt.Errorf("failed to get usage data: %w", err)
	}
	
	var usage QuotaUsage
	if err := json.Unmarshal([]byte(data), &usage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal usage data: %w", err)
	}
	
	return &usage, nil
}

// getOrgUsage gets current usage for an organization in a specific period
func (qs *QuotaStore) getOrgUsage(ctx context.Context, orgID, period string) (*QuotaUsage, error) {
	now := time.Now()
	var startTime, endTime time.Time
	
	switch period {
	case "minute":
		startTime = now.Truncate(time.Minute)
		endTime = startTime.Add(time.Minute)
	case "hour":
		startTime = now.Truncate(time.Hour)
		endTime = startTime.Add(time.Hour)
	case "day":
		startTime = now.Truncate(24 * time.Hour)
		endTime = startTime.Add(24 * time.Hour)
	default:
		return nil, fmt.Errorf("invalid period: %s", period)
	}
	
	key := fmt.Sprintf("%susage:org:%s:%s:%d", qs.config.RedisKeyPrefix, orgID, period, startTime.Unix())
	
	data, err := qs.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			// No usage data, return empty usage
			return &QuotaUsage{
				Period:       period,
				StartTime:    startTime,
				EndTime:      endTime,
				RequestCount: 0,
				TokenCount:   0,
				LastUpdated:  now,
			}, nil
		}
		return nil, fmt.Errorf("failed to get usage data: %w", err)
	}
	
	var usage QuotaUsage
	if err := json.Unmarshal([]byte(data), &usage); err != nil {
		return nil, fmt.Errorf("failed to unmarshal usage data: %w", err)
	}
	
	return &usage, nil
}

// GetMetrics returns quota store metrics
func (qs *QuotaStore) GetMetrics() *QuotaMetrics {
	qs.metrics.mu.RLock()
	defer qs.metrics.mu.RUnlock()
	
	metricsCopy := *qs.metrics
	return &metricsCopy
}

// Helper methods

func (qs *QuotaStore) getDefaultUserQuota(userID string) *UserQuota {
	return &UserQuota{
		UserID:            userID,
		Tier:              "free",
		RequestsPerSecond: 10,
		RequestsPerMinute: 100,
		RequestsPerHour:   1000,
		RequestsPerDay:    10000,
		TokensPerMinute:   50000,
		TokensPerHour:     500000,
		TokensPerDay:      5000000,
		CustomLimits:      make(map[string]int64),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
}

func (qs *QuotaStore) getDefaultOrgQuota(orgID string) *OrgQuota {
	return &OrgQuota{
		OrgID:             orgID,
		Tier:              "standard",
		RequestsPerSecond: 100,
		RequestsPerMinute: 1000,
		RequestsPerHour:   10000,
		RequestsPerDay:    100000,
		TokensPerMinute:   500000,
		TokensPerHour:     5000000,
		TokensPerDay:      50000000,
		MaxUsers:          50,
		CustomLimits:      make(map[string]int64),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
}

func (qs *QuotaStore) updateMetrics(latency time.Duration) {
	if !qs.config.EnableMetrics {
		return
	}
	
	qs.metrics.mu.Lock()
	defer qs.metrics.mu.Unlock()
	
	qs.metrics.TotalQueries++
	
	// Update average latency
	if qs.metrics.TotalQueries == 1 {
		qs.metrics.AverageLatency = latency
	} else {
		totalTime := time.Duration(qs.metrics.TotalQueries-1) * qs.metrics.AverageLatency
		qs.metrics.AverageLatency = (totalTime + latency) / time.Duration(qs.metrics.TotalQueries)
	}
}

func (qs *QuotaStore) recordCacheHit() {
	if !qs.config.EnableMetrics {
		return
	}
	
	qs.metrics.mu.Lock()
	qs.metrics.CacheHits++
	qs.metrics.mu.Unlock()
}

func (qs *QuotaStore) recordCacheMiss() {
	if !qs.config.EnableMetrics {
		return
	}
	
	qs.metrics.mu.Lock()
	qs.metrics.CacheMisses++
	qs.metrics.mu.Unlock()
}

func (qs *QuotaStore) recordUpdate() {
	if !qs.config.EnableMetrics {
		return
	}
	
	qs.metrics.mu.Lock()
	qs.metrics.UpdateOperations++
	qs.metrics.mu.Unlock()
}

func (qs *QuotaStore) recordError() {
	if !qs.config.EnableMetrics {
		return
	}
	
	qs.metrics.mu.Lock()
	qs.metrics.RedisErrors++
	qs.metrics.mu.Unlock()
}

func (qs *QuotaStore) startCleanupWorker() {
	ticker := time.NewTicker(qs.config.CleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		qs.performCleanup()
	}
}

func (qs *QuotaStore) performCleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Clean expired quota and usage data
	pattern := qs.config.RedisKeyPrefix + "*"
	keys, err := qs.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		qs.logger.WithError(err).Error("Failed to get keys for quota cleanup")
		return
	}
	
	cleanupCount := 0
	for _, key := range keys {
		ttl := qs.redisClient.TTL(ctx, key).Val()
		if ttl == -1 { // Key has no expiration
			// Set default TTL for keys without expiration
			qs.redisClient.Expire(ctx, key, qs.config.DefaultTTL)
		} else if ttl == -2 { // Key doesn't exist or expired
			cleanupCount++
		}
	}
	
	if cleanupCount > 0 {
		qs.logger.WithField("cleaned_keys", cleanupCount).Info("Quota cleanup completed")
	}
} 