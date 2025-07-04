package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// ResponseCacheManager manages multi-level response caching with Redis
type ResponseCacheManager struct {
	redisClient       *redis.Client
	memoryCache       *MemoryCache
	config            *CacheConfig
	logger            *logrus.Logger
	metrics           *CacheMetrics
	mu                sync.RWMutex
	healthStatus      HealthStatus
	
	// Advanced TTL and invalidation
	ttlManager        *TTLPolicyManager
	invalidationManager *InvalidationManager
	advancedFeaturesEnabled bool
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	// Redis configuration
	RedisKeyPrefix        string        `json:"redis_key_prefix" yaml:"redis_key_prefix"`
	DefaultTTL            time.Duration `json:"default_ttl" yaml:"default_ttl"`
	MaxRequestSize        int64         `json:"max_request_size" yaml:"max_request_size"`
	MaxResponseSize       int64         `json:"max_response_size" yaml:"max_response_size"`
	CompressionThreshold  int64         `json:"compression_threshold" yaml:"compression_threshold"`
	CompressionEnabled    bool          `json:"compression_enabled" yaml:"compression_enabled"`
	
	// Memory cache (L1) configuration
	MemoryCacheEnabled    bool          `json:"memory_cache_enabled" yaml:"memory_cache_enabled"`
	MemoryCacheSize       int           `json:"memory_cache_size" yaml:"memory_cache_size"`
	MemoryCacheTTL        time.Duration `json:"memory_cache_ttl" yaml:"memory_cache_ttl"`
	
	// TTL policies by request type
	TTLPolicies           map[string]time.Duration `json:"ttl_policies" yaml:"ttl_policies"`
	
	// Cache invalidation
	InvalidationPatterns  []string      `json:"invalidation_patterns" yaml:"invalidation_patterns"`
	InvalidationEnabled   bool          `json:"invalidation_enabled" yaml:"invalidation_enabled"`
	
	// Performance settings
	CacheKeyMaxLength     int           `json:"cache_key_max_length" yaml:"cache_key_max_length"`
	BatchSize             int           `json:"batch_size" yaml:"batch_size"`
	PipelineEnabled       bool          `json:"pipeline_enabled" yaml:"pipeline_enabled"`
	
	// Monitoring
	MetricsEnabled        bool          `json:"metrics_enabled" yaml:"metrics_enabled"`
	HealthCheckInterval   time.Duration `json:"health_check_interval" yaml:"health_check_interval"`
	
	// Advanced features
	AdvancedFeaturesEnabled bool                   `json:"advanced_features_enabled" yaml:"advanced_features_enabled"`
	TTLPolicyConfig        *TTLPolicyConfig       `json:"ttl_policy_config" yaml:"ttl_policy_config"`
	InvalidationConfig     *InvalidationConfig    `json:"invalidation_config" yaml:"invalidation_config"`
}

// CacheRequest represents a request to be cached
type CacheRequest struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	UserID          string            `json:"user_id"`
	OrganizationID  string            `json:"organization_id"`
	RequestType     string            `json:"request_type"`
	Timestamp       time.Time         `json:"timestamp"`
	ClientIP        string            `json:"client_ip"`
	
	// Advanced features
	Tags         []string `json:"tags,omitempty"`         // Tags for invalidation
	Dependencies []string `json:"dependencies,omitempty"` // Cache dependencies
	Priority     int      `json:"priority,omitempty"`     // Cache priority
}

// CacheResponse represents a cached response
type CacheResponse struct {
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	ContentType     string            `json:"content_type"`
	ContentLength   int64             `json:"content_length"`
	CachedAt        time.Time         `json:"cached_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	HitCount        int64             `json:"hit_count"`
	LastAccessed    time.Time         `json:"last_accessed"`
	Compressed      bool              `json:"compressed"`
	RequestHash     string            `json:"request_hash"`
	TTL             time.Duration     `json:"ttl"`
}

// CacheEntry represents a complete cache entry
type CacheEntry struct {
	Key         string         `json:"key"`
	Request     *CacheRequest  `json:"request"`
	Response    *CacheResponse `json:"response"`
	Metadata    *CacheMetadata `json:"metadata"`
}

// CacheMetadata holds additional cache metadata
type CacheMetadata struct {
	Version         string            `json:"version"`
	Tags            []string          `json:"tags"`
	Dependencies    []string          `json:"dependencies"`
	CreatedBy       string            `json:"created_by"`
	LastModified    time.Time         `json:"last_modified"`
	AccessCount     int64             `json:"access_count"`
	Size            int64             `json:"size"`
	CompressionRatio float64          `json:"compression_ratio"`
	Annotations     map[string]string `json:"annotations"`
}

// MemoryCache represents L1 in-memory cache
type MemoryCache struct {
	data     map[string]*CacheResponse
	mu       sync.RWMutex
	maxSize  int
	ttl      time.Duration
	stats    *MemoryCacheStats
}

// MemoryCacheStats tracks memory cache statistics
type MemoryCacheStats struct {
	Hits        int64     `json:"hits"`
	Misses      int64     `json:"misses"`
	Evictions   int64     `json:"evictions"`
	Size        int       `json:"size"`
	LastCleanup time.Time `json:"last_cleanup"`
}

// CacheMetrics tracks cache performance metrics
type CacheMetrics struct {
	// Hit/Miss statistics
	RedisHits          int64 `json:"redis_hits"`
	RedisMisses        int64 `json:"redis_misses"`
	MemoryHits         int64 `json:"memory_hits"`
	MemoryMisses       int64 `json:"memory_misses"`
	
	// Performance metrics
	AverageGetLatency  time.Duration `json:"average_get_latency"`
	AverageSetLatency  time.Duration `json:"average_set_latency"`
	TotalRequests      int64         `json:"total_requests"`
	
	// Storage metrics
	TotalEntries       int64 `json:"total_entries"`
	TotalSizeBytes     int64 `json:"total_size_bytes"`
	CompressionSaved   int64 `json:"compression_saved"`
	
	// Error metrics
	Errors             int64 `json:"errors"`
	Timeouts           int64 `json:"timeouts"`
	CompressionErrors  int64 `json:"compression_errors"`
	
	// TTL metrics
	Expirations        int64 `json:"expirations"`
	Invalidations      int64 `json:"invalidations"`
	
	mu sync.RWMutex
}

// HealthStatus represents cache health status
type HealthStatus struct {
	RedisConnected     bool      `json:"redis_connected"`
	MemoryCacheActive  bool      `json:"memory_cache_active"`
	LastHealthCheck    time.Time `json:"last_health_check"`
	ErrorCount         int64     `json:"error_count"`
	Status             string    `json:"status"`
}

// NewResponseCacheManager creates a new response cache manager
func NewResponseCacheManager(redisClient *redis.Client, config *CacheConfig, logger *logrus.Logger) (*ResponseCacheManager, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}
	
	if config == nil {
		config = getDefaultCacheConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	// Initialize memory cache if enabled
	var memCache *MemoryCache
	if config.MemoryCacheEnabled {
		memCache = &MemoryCache{
			data:    make(map[string]*CacheResponse),
			maxSize: config.MemoryCacheSize,
			ttl:     config.MemoryCacheTTL,
			stats:   &MemoryCacheStats{},
		}
	}
	
	manager := &ResponseCacheManager{
		redisClient:  redisClient,
		memoryCache:  memCache,
		config:       config,
		logger:       logger,
		metrics:      &CacheMetrics{},
		healthStatus: HealthStatus{Status: "initializing"},
		advancedFeaturesEnabled: config.AdvancedFeaturesEnabled,
	}
	
	// Initialize advanced features if enabled
	if config.AdvancedFeaturesEnabled {
		// Initialize TTL policy manager
		ttlConfig := config.TTLPolicyConfig
		if ttlConfig == nil {
			ttlConfig = getDefaultTTLPolicyConfig()
		}
		manager.ttlManager = NewTTLPolicyManager(ttlConfig)
		
		// Initialize invalidation manager
		invalidationConfig := config.InvalidationConfig
		if invalidationConfig == nil {
			invalidationConfig = getDefaultInvalidationConfig()
		}
		manager.invalidationManager = NewInvalidationManager(redisClient, invalidationConfig, logger)
		
		logger.Info("Advanced cache features (TTL policies and invalidation) enabled")
	}
	
	// Start background processes
	go manager.startHealthChecker()
	if config.MemoryCacheEnabled {
		go manager.startMemoryCacheCleanup()
	}
	
	return manager, nil
}

// Get retrieves a response from cache
func (rcm *ResponseCacheManager) Get(ctx context.Context, request *CacheRequest) (*CacheResponse, error) {
	start := time.Now()
	defer func() {
		rcm.metrics.mu.Lock()
		rcm.metrics.TotalRequests++
		latency := time.Since(start)
		if rcm.metrics.TotalRequests == 1 {
			rcm.metrics.AverageGetLatency = latency
		} else {
			rcm.metrics.AverageGetLatency = (rcm.metrics.AverageGetLatency + latency) / 2
		}
		rcm.metrics.mu.Unlock()
	}()
	
	if request == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	
	// Generate cache key
	cacheKey, err := rcm.generateCacheKey(request)
	if err != nil {
		rcm.recordError()
		return nil, fmt.Errorf("failed to generate cache key: %w", err)
	}
	
	// Try L1 cache first (memory)
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
		if response := rcm.memoryCache.get(cacheKey); response != nil {
			rcm.recordMemoryHit()
			rcm.updateResponseAccess(response)
			return response, nil
		}
		rcm.recordMemoryMiss()
	}
	
	// Try L2 cache (Redis)
	response, err := rcm.getFromRedis(ctx, cacheKey)
	if err != nil {
		rcm.recordError()
		return nil, fmt.Errorf("failed to get from Redis: %w", err)
	}
	
	if response != nil {
		rcm.recordRedisHit()
		
		// Store in L1 cache for faster future access
		if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
			rcm.memoryCache.set(cacheKey, response)
		}
		
		rcm.updateResponseAccess(response)
		return response, nil
	}
	
	rcm.recordRedisMiss()
	return nil, nil
}

// Set stores a response in cache
func (rcm *ResponseCacheManager) Set(ctx context.Context, request *CacheRequest, response *CacheResponse) error {
	start := time.Now()
	defer func() {
		rcm.metrics.mu.Lock()
		latency := time.Since(start)
		if rcm.metrics.TotalRequests == 1 {
			rcm.metrics.AverageSetLatency = latency
		} else {
			rcm.metrics.AverageSetLatency = (rcm.metrics.AverageSetLatency + latency) / 2
		}
		rcm.metrics.mu.Unlock()
	}()
	
	if request == nil || response == nil {
		return fmt.Errorf("request and response cannot be nil")
	}
	
	// Check size limits
	if err := rcm.validateSizeLimits(request, response); err != nil {
		return fmt.Errorf("size validation failed: %w", err)
	}
	
	// Generate cache key
	cacheKey, err := rcm.generateCacheKey(request)
	if err != nil {
		rcm.recordError()
		return fmt.Errorf("failed to generate cache key: %w", err)
	}
	
	// Set TTL based on request type
	ttl := rcm.getTTLForRequest(request)
	response.TTL = ttl
	response.ExpiresAt = time.Now().Add(ttl)
	response.CachedAt = time.Now()
	response.RequestHash = cacheKey
	
	// Compress if enabled and threshold exceeded
	if rcm.config.CompressionEnabled && int64(len(response.Body)) > rcm.config.CompressionThreshold {
		compressed, ratio, err := rcm.compressResponse(response)
		if err != nil {
			rcm.recordCompressionError()
			rcm.logger.WithError(err).Warn("Failed to compress response")
		} else {
			response.Body = compressed
			response.Compressed = true
			rcm.recordCompressionSaved(int64(float64(len(response.Body)) * (1 - ratio)))
		}
	}
	
	// Store in Redis
	if err := rcm.setInRedis(ctx, cacheKey, response, ttl); err != nil {
		rcm.recordError()
		return fmt.Errorf("failed to set in Redis: %w", err)
	}
	
	// Store in memory cache
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
		rcm.memoryCache.set(cacheKey, response)
	}
	
	rcm.recordCacheSet(response)
	return nil
}

// SetAdvanced stores a response in cache using advanced TTL policies
func (rcm *ResponseCacheManager) SetAdvanced(ctx context.Context, request *CacheRequest, response *CacheResponse, analysisCtx *TTLCalculationContext) error {
	start := time.Now()
	defer func() {
		rcm.metrics.mu.Lock()
		latency := time.Since(start)
		if rcm.metrics.TotalRequests == 1 {
			rcm.metrics.AverageSetLatency = latency
		} else {
			rcm.metrics.AverageSetLatency = (rcm.metrics.AverageSetLatency + latency) / 2
		}
		rcm.metrics.mu.Unlock()
	}()
	
	if request == nil || response == nil {
		return fmt.Errorf("request and response cannot be nil")
	}
	
	// Check size limits
	if err := rcm.validateSizeLimits(request, response); err != nil {
		return fmt.Errorf("size validation failed: %w", err)
	}
	
	// Generate cache key
	cacheKey, err := rcm.generateCacheKey(request)
	if err != nil {
		rcm.recordError()
		return fmt.Errorf("failed to generate cache key: %w", err)
	}
	
	// Calculate TTL using advanced policies
	var ttl time.Duration
	if rcm.advancedFeaturesEnabled && rcm.ttlManager != nil && analysisCtx != nil {
		analysisCtx.Request = request
		analysisCtx.Response = response
		analysisCtx.CurrentTime = time.Now()
		
		calculatedTTL, err := rcm.ttlManager.CalculateTTL(analysisCtx)
		if err != nil {
			rcm.logger.WithError(err).Warn("Failed to calculate advanced TTL, using fallback")
			ttl = rcm.getTTLForRequest(request)
		} else {
			ttl = calculatedTTL
		}
	} else {
		ttl = rcm.getTTLForRequest(request)
	}
	
	response.TTL = ttl
	response.ExpiresAt = time.Now().Add(ttl)
	response.CachedAt = time.Now()
	response.RequestHash = cacheKey
	
	// Compress if enabled and threshold exceeded
	if rcm.config.CompressionEnabled && int64(len(response.Body)) > rcm.config.CompressionThreshold {
		compressed, ratio, err := rcm.compressResponse(response)
		if err != nil {
			rcm.recordCompressionError()
			rcm.logger.WithError(err).Warn("Failed to compress response")
		} else {
			response.Body = compressed
			response.Compressed = true
			rcm.recordCompressionSaved(int64(float64(len(response.Body)) * (1 - ratio)))
		}
	}
	
	// Store in Redis
	if err := rcm.setInRedis(ctx, cacheKey, response, ttl); err != nil {
		rcm.recordError()
		return fmt.Errorf("failed to set in Redis: %w", err)
	}
	
	// Store in memory cache
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
		rcm.memoryCache.set(cacheKey, response)
	}
	
	// Add tags for invalidation if specified
	if rcm.advancedFeaturesEnabled && rcm.invalidationManager != nil && len(request.Tags) > 0 {
		err := rcm.invalidationManager.AddTags(cacheKey, request.Tags)
		if err != nil {
			rcm.logger.WithError(err).Warn("Failed to add cache tags")
		}
	}
	
	// Add dependencies if specified
	if rcm.advancedFeaturesEnabled && rcm.invalidationManager != nil && len(request.Dependencies) > 0 {
		for _, dep := range request.Dependencies {
			dependency := &Dependency{
				ID:        fmt.Sprintf("%s->%s", cacheKey, dep),
				SourceKey: cacheKey,
				TargetKey: dep,
				Type:      "strong",
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}
			err := rcm.invalidationManager.AddDependency(dependency)
			if err != nil {
				rcm.logger.WithError(err).Warn("Failed to add cache dependency")
			}
		}
	}
	
	rcm.recordCacheSet(response)
	return nil
}

// Delete removes entries from cache
func (rcm *ResponseCacheManager) Delete(ctx context.Context, request *CacheRequest) error {
	cacheKey, err := rcm.generateCacheKey(request)
	if err != nil {
		return fmt.Errorf("failed to generate cache key: %w", err)
	}
	
	// Delete from Redis
	if err := rcm.redisClient.Del(ctx, cacheKey).Err(); err != nil {
		return fmt.Errorf("failed to delete from Redis: %w", err)
	}
	
	// Delete from memory cache
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
		rcm.memoryCache.delete(cacheKey)
	}
	
	return nil
}

// Invalidate removes entries matching patterns
func (rcm *ResponseCacheManager) Invalidate(ctx context.Context, patterns []string) error {
	if !rcm.config.InvalidationEnabled {
		return nil
	}
	
	for _, pattern := range patterns {
		keys, err := rcm.redisClient.Keys(ctx, fmt.Sprintf("%s%s", rcm.config.RedisKeyPrefix, pattern)).Result()
		if err != nil {
			return fmt.Errorf("failed to find keys for pattern %s: %w", pattern, err)
		}
		
		if len(keys) > 0 {
			if err := rcm.redisClient.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("failed to delete keys: %w", err)
			}
			
			rcm.metrics.mu.Lock()
			rcm.metrics.Invalidations += int64(len(keys))
			rcm.metrics.mu.Unlock()
		}
	}
	
	// Invalidate memory cache entries
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
		rcm.memoryCache.invalidateByPatterns(patterns)
	}
	
	return nil
}

// InvalidateByPattern invalidates cache entries matching patterns
func (rcm *ResponseCacheManager) InvalidateByPattern(ctx context.Context, patterns []string) (*InvalidationResult, error) {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		return rcm.invalidateBySimplePattern(ctx, patterns)
	}
	
	return rcm.invalidationManager.InvalidateByPattern(ctx, patterns)
}

// InvalidateByTags invalidates cache entries with specific tags
func (rcm *ResponseCacheManager) InvalidateByTags(ctx context.Context, tags []string) (*InvalidationResult, error) {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		return nil, fmt.Errorf("advanced invalidation features not enabled")
	}
	
	return rcm.invalidationManager.InvalidateByTags(ctx, tags)
}

// InvalidateByUser invalidates all cache entries for a specific user
func (rcm *ResponseCacheManager) InvalidateByUser(ctx context.Context, userID string) (*InvalidationResult, error) {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		// Fallback to simple pattern
		pattern := fmt.Sprintf("*:user:%s:*", userID)
		return rcm.invalidateBySimplePattern(ctx, []string{pattern})
	}
	
	return rcm.invalidationManager.InvalidateByUser(ctx, userID)
}

// InvalidateByOrganization invalidates all cache entries for a specific organization
func (rcm *ResponseCacheManager) InvalidateByOrganization(ctx context.Context, orgID string) (*InvalidationResult, error) {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		// Fallback to simple pattern
		pattern := fmt.Sprintf("*:org:%s:*", orgID)
		return rcm.invalidateBySimplePattern(ctx, []string{pattern})
	}
	
	return rcm.invalidationManager.InvalidateByOrganization(ctx, orgID)
}

// InvalidateByEvent processes an invalidation event
func (rcm *ResponseCacheManager) InvalidateByEvent(event *InvalidationEvent) error {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		return fmt.Errorf("event-driven invalidation not enabled")
	}
	
	return rcm.invalidationManager.InvalidateByEvent(event)
}

// AddEventListener registers an event listener for cache invalidation
func (rcm *ResponseCacheManager) AddEventListener(listener *EventListener) error {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		return fmt.Errorf("event-driven invalidation not enabled")
	}
	
	return rcm.invalidationManager.AddEventListener(listener)
}

// AddScheduledInvalidation adds a scheduled invalidation task
func (rcm *ResponseCacheManager) AddScheduledInvalidation(schedule *ScheduledInvalidation) error {
	if !rcm.advancedFeaturesEnabled || rcm.invalidationManager == nil {
		return fmt.Errorf("scheduled invalidation not enabled")
	}
	
	return rcm.invalidationManager.AddScheduledInvalidation(schedule)
}

// GetTTLPolicyManager returns the TTL policy manager
func (rcm *ResponseCacheManager) GetTTLPolicyManager() *TTLPolicyManager {
	return rcm.ttlManager
}

// GetInvalidationManager returns the invalidation manager
func (rcm *ResponseCacheManager) GetInvalidationManager() *InvalidationManager {
	return rcm.invalidationManager
}

// GetMetrics returns cache performance metrics
func (rcm *ResponseCacheManager) GetMetrics() *CacheMetrics {
	rcm.metrics.mu.RLock()
	defer rcm.metrics.mu.RUnlock()
	
	metrics := *rcm.metrics
	return &metrics
}

// GetHealthStatus returns cache health status
func (rcm *ResponseCacheManager) GetHealthStatus() HealthStatus {
	rcm.mu.RLock()
	defer rcm.mu.RUnlock()
	
	return rcm.healthStatus
}

// generateCacheKey creates a consistent cache key for a request
func (rcm *ResponseCacheManager) generateCacheKey(request *CacheRequest) (string, error) {
	// Create a deterministic hash of the request
	hasher := sha256.New()
	
	// Include key request fields
	hasher.Write([]byte(request.Method))
	hasher.Write([]byte(request.URL))
	hasher.Write([]byte(request.Body))
	hasher.Write([]byte(request.UserID))
	hasher.Write([]byte(request.OrganizationID))
	hasher.Write([]byte(request.RequestType))
	
	// Include normalized headers (sorted)
	var headerKeys []string
	for key := range request.Headers {
		headerKeys = append(headerKeys, key)
	}
	
	for _, key := range headerKeys {
		hasher.Write([]byte(key + ":" + request.Headers[key]))
	}
	
	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	cacheKey := fmt.Sprintf("%s%s", rcm.config.RedisKeyPrefix, hash)
	
	// Truncate if too long
	if len(cacheKey) > rcm.config.CacheKeyMaxLength {
		cacheKey = cacheKey[:rcm.config.CacheKeyMaxLength]
	}
	
	return cacheKey, nil
}

// getFromRedis retrieves a response from Redis
func (rcm *ResponseCacheManager) getFromRedis(ctx context.Context, key string) (*CacheResponse, error) {
	data, err := rcm.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Key doesn't exist
		}
		return nil, fmt.Errorf("redis get error: %w", err)
	}
	
	var response CacheResponse
	if err := json.Unmarshal([]byte(data), &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}
	
	// Check if expired
	if time.Now().After(response.ExpiresAt) {
		// Delete expired entry
		rcm.redisClient.Del(ctx, key)
		rcm.metrics.mu.Lock()
		rcm.metrics.Expirations++
		rcm.metrics.mu.Unlock()
		return nil, nil
	}
	
	// Decompress if needed
	if response.Compressed {
		decompressed, err := rcm.decompressResponse(&response)
		if err != nil {
			rcm.recordCompressionError()
			return nil, fmt.Errorf("failed to decompress response: %w", err)
		}
		response.Body = decompressed
		response.Compressed = false
	}
	
	return &response, nil
}

// setInRedis stores a response in Redis
func (rcm *ResponseCacheManager) setInRedis(ctx context.Context, key string, response *CacheResponse, ttl time.Duration) error {
	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	
	if err := rcm.redisClient.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("redis set error: %w", err)
	}
	
	return nil
}

// compressResponse compresses response body using gzip
func (rcm *ResponseCacheManager) compressResponse(response *CacheResponse) (string, float64, error) {
	original := []byte(response.Body)
	
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	
	if _, err := writer.Write(original); err != nil {
		return "", 0, fmt.Errorf("gzip write error: %w", err)
	}
	
	if err := writer.Close(); err != nil {
		return "", 0, fmt.Errorf("gzip close error: %w", err)
	}
	
	compressed := buf.Bytes()
	compressionRatio := float64(len(compressed)) / float64(len(original))
	
	return string(compressed), compressionRatio, nil
}

// decompressResponse decompresses response body using gzip
func (rcm *ResponseCacheManager) decompressResponse(response *CacheResponse) (string, error) {
	compressed := []byte(response.Body)
	
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", fmt.Errorf("gzip reader error: %w", err)
	}
	defer reader.Close()
	
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("gzip read error: %w", err)
	}
	
	return string(decompressed), nil
}

// Memory cache operations
func (mc *MemoryCache) get(key string) *CacheResponse {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	response, exists := mc.data[key]
	if !exists {
		mc.stats.Misses++
		return nil
	}
	
	// Check TTL
	if time.Now().After(response.ExpiresAt) {
		delete(mc.data, key)
		mc.stats.Evictions++
		mc.stats.Misses++
		return nil
	}
	
	mc.stats.Hits++
	return response
}

func (mc *MemoryCache) set(key string, response *CacheResponse) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	// Evict if at capacity
	if len(mc.data) >= mc.maxSize {
		mc.evictOldest()
	}
	
	// Create a copy for memory cache
	memoryCopy := *response
	memoryCopy.ExpiresAt = time.Now().Add(mc.ttl)
	
	mc.data[key] = &memoryCopy
	mc.stats.Size = len(mc.data)
}

func (mc *MemoryCache) delete(key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	if _, exists := mc.data[key]; exists {
		delete(mc.data, key)
		mc.stats.Size = len(mc.data)
		mc.stats.Evictions++
	}
}

func (mc *MemoryCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time = time.Now()
	
	for key, response := range mc.data {
		if response.LastAccessed.Before(oldestTime) {
			oldestTime = response.LastAccessed
			oldestKey = key
		}
	}
	
	if oldestKey != "" {
		delete(mc.data, oldestKey)
		mc.stats.Evictions++
	}
}

func (mc *MemoryCache) invalidateByPatterns(patterns []string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	for key := range mc.data {
		for _, pattern := range patterns {
			if mc.matchesPattern(key, pattern) {
				delete(mc.data, key)
				mc.stats.Evictions++
				break
			}
		}
	}
	
	mc.stats.Size = len(mc.data)
}

func (mc *MemoryCache) matchesPattern(key, pattern string) bool {
	// Simple pattern matching (asterisk wildcard)
	if pattern == "*" {
		return true
	}
	
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(key, parts[0]) && strings.HasSuffix(key, parts[1])
		}
	}
	
	return key == pattern
}

// Validation and utility methods
func (rcm *ResponseCacheManager) validateSizeLimits(request *CacheRequest, response *CacheResponse) error {
	if int64(len(request.Body)) > rcm.config.MaxRequestSize {
		return fmt.Errorf("request body too large: %d bytes (max: %d)", len(request.Body), rcm.config.MaxRequestSize)
	}
	
	if int64(len(response.Body)) > rcm.config.MaxResponseSize {
		return fmt.Errorf("response body too large: %d bytes (max: %d)", len(response.Body), rcm.config.MaxResponseSize)
	}
	
	return nil
}

func (rcm *ResponseCacheManager) getTTLForRequest(request *CacheRequest) time.Duration {
	if ttl, exists := rcm.config.TTLPolicies[request.RequestType]; exists {
		return ttl
	}
	
	if ttl, exists := rcm.config.TTLPolicies["default"]; exists {
		return ttl
	}
	
	return rcm.config.DefaultTTL
}

func (rcm *ResponseCacheManager) updateResponseAccess(response *CacheResponse) {
	response.HitCount++
	response.LastAccessed = time.Now()
}

// Metrics recording methods
func (rcm *ResponseCacheManager) recordRedisHit() {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.RedisHits++
}

func (rcm *ResponseCacheManager) recordRedisMiss() {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.RedisMisses++
}

func (rcm *ResponseCacheManager) recordMemoryHit() {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.MemoryHits++
}

func (rcm *ResponseCacheManager) recordMemoryMiss() {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.MemoryMisses++
}

func (rcm *ResponseCacheManager) recordError() {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.Errors++
}

func (rcm *ResponseCacheManager) recordCompressionError() {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.CompressionErrors++
}

func (rcm *ResponseCacheManager) recordCompressionSaved(bytes int64) {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.CompressionSaved += bytes
}

func (rcm *ResponseCacheManager) recordCacheSet(response *CacheResponse) {
	rcm.metrics.mu.Lock()
	defer rcm.metrics.mu.Unlock()
	rcm.metrics.TotalEntries++
	rcm.metrics.TotalSizeBytes += int64(len(response.Body))
}

// Background processes
func (rcm *ResponseCacheManager) startHealthChecker() {
	ticker := time.NewTicker(rcm.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		rcm.performHealthCheck()
	}
}

func (rcm *ResponseCacheManager) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	rcm.mu.Lock()
	defer rcm.mu.Unlock()
	
	// Check Redis connection
	redisHealthy := true
	if err := rcm.redisClient.Ping(ctx).Err(); err != nil {
		redisHealthy = false
		rcm.healthStatus.ErrorCount++
		rcm.logger.WithError(err).Error("Redis health check failed")
	}
	
	// Check memory cache
	memoryHealthy := true
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache == nil {
		memoryHealthy = false
	}
	
	// Update health status
	rcm.healthStatus.RedisConnected = redisHealthy
	rcm.healthStatus.MemoryCacheActive = memoryHealthy
	rcm.healthStatus.LastHealthCheck = time.Now()
	
	if redisHealthy && memoryHealthy {
		rcm.healthStatus.Status = "healthy"
	} else if redisHealthy || memoryHealthy {
		rcm.healthStatus.Status = "degraded"
	} else {
		rcm.healthStatus.Status = "unhealthy"
	}
}

func (rcm *ResponseCacheManager) startMemoryCacheCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		rcm.cleanupMemoryCache()
	}
}

func (rcm *ResponseCacheManager) cleanupMemoryCache() {
	if rcm.memoryCache == nil {
		return
	}
	
	rcm.memoryCache.mu.Lock()
	defer rcm.memoryCache.mu.Unlock()
	
	now := time.Now()
	for key, response := range rcm.memoryCache.data {
		if now.After(response.ExpiresAt) {
			delete(rcm.memoryCache.data, key)
			rcm.memoryCache.stats.Evictions++
		}
	}
	
	rcm.memoryCache.stats.Size = len(rcm.memoryCache.data)
	rcm.memoryCache.stats.LastCleanup = now
}

// GetCacheStatistics returns comprehensive cache statistics
func (rcm *ResponseCacheManager) GetCacheStatistics(ctx context.Context) (*CacheStatistics, error) {
	stats := &CacheStatistics{
		Metrics: rcm.GetMetrics(),
		Health:  rcm.GetHealthStatus(),
	}
	
	// Calculate overall hit ratio
	totalHits := stats.Metrics.RedisHits + stats.Metrics.MemoryHits
	totalMisses := stats.Metrics.RedisMisses + stats.Metrics.MemoryMisses
	if totalHits+totalMisses > 0 {
		stats.OverallHitRatio = float64(totalHits) / float64(totalHits+totalMisses)
	}
	stats.TotalHits = totalHits
	stats.TotalMisses = totalMisses
	
	// Get Redis info if connected
	if rcm.healthStatus.RedisConnected {
		info, err := rcm.redisClient.Info(ctx, "memory").Result()
		if err == nil {
			stats.RedisInfo = parseRedisInfo(info)
		}
	}
	
	// Get memory cache info
	if rcm.config.MemoryCacheEnabled && rcm.memoryCache != nil {
		rcm.memoryCache.mu.RLock()
		hitRatio := 0.0
		if rcm.memoryCache.stats.Hits+rcm.memoryCache.stats.Misses > 0 {
			hitRatio = float64(rcm.memoryCache.stats.Hits) / float64(rcm.memoryCache.stats.Hits+rcm.memoryCache.stats.Misses)
		}
		stats.MemoryCacheInfo = &MemoryCacheInfo{
			Size:     rcm.memoryCache.stats.Size,
			MaxSize:  rcm.memoryCache.maxSize,
			Stats:    *rcm.memoryCache.stats,
			HitRatio: hitRatio,
		}
		rcm.memoryCache.mu.RUnlock()
	}
	
	return stats, nil
}

// CacheStatistics aggregates all cache statistics
type CacheStatistics struct {
	Metrics         *CacheMetrics      `json:"metrics"`
	Health          HealthStatus       `json:"health"`
	RedisInfo       map[string]string  `json:"redis_info,omitempty"`
	MemoryCacheInfo *MemoryCacheInfo   `json:"memory_cache_info,omitempty"`
	OverallHitRatio float64           `json:"overall_hit_ratio"`
	TotalHits       int64             `json:"total_hits"`
	TotalMisses     int64             `json:"total_misses"`
}

// MemoryCacheInfo provides memory cache information
type MemoryCacheInfo struct {
	Size     int               `json:"size"`
	MaxSize  int               `json:"max_size"`
	Stats    MemoryCacheStats  `json:"stats"`
	HitRatio float64           `json:"hit_ratio"`
}

func parseRedisInfo(info string) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(info, "\r\n")
	
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result[parts[0]] = parts[1]
			}
		}
	}
	
	return result
}

// getDefaultCacheConfig returns default cache configuration
func getDefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		RedisKeyPrefix:        "ai_gateway:cache:",
		DefaultTTL:            1 * time.Hour,
		MaxRequestSize:        1024 * 1024,     // 1MB
		MaxResponseSize:       10 * 1024 * 1024, // 10MB
		CompressionThreshold:  1024,            // 1KB
		CompressionEnabled:    true,
		MemoryCacheEnabled:    true,
		MemoryCacheSize:       1000,
		MemoryCacheTTL:        5 * time.Minute,
		TTLPolicies: map[string]time.Duration{
			"chat":      15 * time.Minute,
			"completion": 30 * time.Minute,
			"embedding":  2 * time.Hour,
			"image":      1 * time.Hour,
			"default":    1 * time.Hour,
		},
		InvalidationPatterns:  []string{"*"},
		InvalidationEnabled:   true,
		CacheKeyMaxLength:     250,
		BatchSize:             100,
		PipelineEnabled:       true,
		MetricsEnabled:        true,
		HealthCheckInterval:   30 * time.Second,
		
		// Advanced features
		AdvancedFeaturesEnabled: true,
		TTLPolicyConfig:        getDefaultTTLPolicyConfig(),
		InvalidationConfig:     getDefaultInvalidationConfig(),
	}
}

// AdvancedCacheMetrics includes metrics for advanced features
type AdvancedCacheMetrics struct {
	BaseMetrics             *CacheMetrics        `json:"base_metrics"`
	AdvancedFeaturesEnabled bool                 `json:"advanced_features_enabled"`
	InvalidationMetrics     *InvalidationMetrics `json:"invalidation_metrics,omitempty"`
	TTLPolicyMetrics        *TTLPolicyMetrics    `json:"ttl_policy_metrics,omitempty"`
}

// TTLPolicyMetrics tracks TTL policy performance
type TTLPolicyMetrics struct {
	DynamicTTLCalculations   int64         `json:"dynamic_ttl_calculations"`
	ConfidenceAdjustments    int64         `json:"confidence_adjustments"`
	SensitivityAdjustments   int64         `json:"sensitivity_adjustments"`
	UserSpecificAdjustments  int64         `json:"user_specific_adjustments"`
	OrgSpecificAdjustments   int64         `json:"org_specific_adjustments"`
	TimeBasedAdjustments     int64         `json:"time_based_adjustments"`
	AdaptiveAdjustments      int64         `json:"adaptive_adjustments"`
	AverageTTLCalculationTime time.Duration `json:"average_ttl_calculation_time"`
	
	mu sync.RWMutex
}

// Helper method for simple pattern invalidation (fallback)
func (rcm *ResponseCacheManager) invalidateBySimplePattern(ctx context.Context, patterns []string) (*InvalidationResult, error) {
	start := time.Now()
	result := &InvalidationResult{
		Patterns:    patterns,
		StartTime:   start,
		KeysRemoved: 0,
		Errors:      []string{},
	}
	
	for _, pattern := range patterns {
		keys, err := rcm.redisClient.Keys(ctx, pattern).Result()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("pattern %s: %v", pattern, err))
			continue
		}
		
		if len(keys) > 0 {
			removed, err := rcm.redisClient.Del(ctx, keys...).Result()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("delete keys for %s: %v", pattern, err))
			} else {
				result.KeysRemoved += removed
			}
		}
	}
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	return result, nil
} 