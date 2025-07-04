package cache

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// InvalidationManager manages advanced cache invalidation strategies
type InvalidationManager struct {
	redisClient    *redis.Client
	config         *InvalidationConfig
	logger         *logrus.Logger
	
	// Event-driven invalidation
	eventListeners map[string][]*EventListener
	eventQueue     chan *InvalidationEvent
	
	// Dependency tracking
	dependencies   map[string][]*Dependency
	dependencyMu   sync.RWMutex
	
	// Tag-based invalidation
	tagIndex       map[string]map[string]bool // tag -> set of cache keys
	tagMu          sync.RWMutex
	
	// Scheduled invalidation
	schedules      []*ScheduledInvalidation
	scheduleMu     sync.RWMutex
	
	// Metrics
	metrics        *InvalidationMetrics
	mu             sync.RWMutex
	
	// Background workers
	stopChan       chan struct{}
	wg             sync.WaitGroup
}

// InvalidationConfig holds invalidation configuration
type InvalidationConfig struct {
	// Event-driven invalidation
	EventDrivenEnabled    bool                  `json:"event_driven_enabled" yaml:"event_driven_enabled"`
	EventQueueSize        int                   `json:"event_queue_size" yaml:"event_queue_size"`
	EventProcessorWorkers int                   `json:"event_processor_workers" yaml:"event_processor_workers"`
	
	// Dependency invalidation
	DependencyEnabled     bool                  `json:"dependency_enabled" yaml:"dependency_enabled"`
	MaxDependencyDepth    int                   `json:"max_dependency_depth" yaml:"max_dependency_depth"`
	DependencyTTL         time.Duration         `json:"dependency_ttl" yaml:"dependency_ttl"`
	
	// Tag-based invalidation
	TagBasedEnabled       bool                  `json:"tag_based_enabled" yaml:"tag_based_enabled"`
	MaxTagsPerEntry       int                   `json:"max_tags_per_entry" yaml:"max_tags_per_entry"`
	TagIndexTTL          time.Duration         `json:"tag_index_ttl" yaml:"tag_index_ttl"`
	
	// Scheduled invalidation
	ScheduledEnabled      bool                  `json:"scheduled_enabled" yaml:"scheduled_enabled"`
	ScheduleCheckInterval time.Duration         `json:"schedule_check_interval" yaml:"schedule_check_interval"`
	
	// Pattern invalidation
	PatternEnabled        bool                  `json:"pattern_enabled" yaml:"pattern_enabled"`
	RegexSupport         bool                  `json:"regex_support" yaml:"regex_support"`
	WildcardSupport      bool                  `json:"wildcard_support" yaml:"wildcard_support"`
	
	// User/Org specific
	UserSpecificEnabled   bool                  `json:"user_specific_enabled" yaml:"user_specific_enabled"`
	OrgSpecificEnabled    bool                  `json:"org_specific_enabled" yaml:"org_specific_enabled"`
	
	// Performance settings
	BatchSize            int                   `json:"batch_size" yaml:"batch_size"`
	MaxConcurrentOps     int                   `json:"max_concurrent_ops" yaml:"max_concurrent_ops"`
	InvalidationTimeout  time.Duration         `json:"invalidation_timeout" yaml:"invalidation_timeout"`
	
	// Cascade invalidation
	CascadeEnabled       bool                  `json:"cascade_enabled" yaml:"cascade_enabled"`
	MaxCascadeDepth      int                   `json:"max_cascade_depth" yaml:"max_cascade_depth"`
}

// InvalidationEvent represents an event that triggers cache invalidation
type InvalidationEvent struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`         // policy_change, user_update, org_update, content_change
	Source       string                 `json:"source"`       // service that generated the event
	Timestamp    time.Time              `json:"timestamp"`
	Data         map[string]interface{} `json:"data"`
	Priority     int                    `json:"priority"`     // 1=highest, 5=lowest
	Correlation  string                 `json:"correlation"`  // correlation ID for tracking
}

// EventListener defines how to handle specific events
type EventListener struct {
	ID              string                    `json:"id"`
	EventType       string                    `json:"event_type"`
	Patterns        []string                  `json:"patterns"`       // cache key patterns to invalidate
	Dependencies    []string                  `json:"dependencies"`   // dependency keys to check
	Tags            []string                  `json:"tags"`           // tags to invalidate
	Conditions      []*InvalidationCondition  `json:"conditions"`     // conditions for invalidation
	Handler         func(*InvalidationEvent) error `json:"-"`
	Enabled         bool                      `json:"enabled"`
	Priority        int                       `json:"priority"`
}

// InvalidationCondition defines conditions for invalidation
type InvalidationCondition struct {
	Field     string      `json:"field"`        // event data field
	Operator  string      `json:"operator"`     // equals, contains, matches, etc.
	Value     interface{} `json:"value"`
	Negate    bool        `json:"negate"`
}

// Dependency represents a cache dependency relationship
type Dependency struct {
	ID           string    `json:"id"`
	SourceKey    string    `json:"source_key"`     // key that depends on target
	TargetKey    string    `json:"target_key"`     // key that source depends on
	Type         string    `json:"type"`           // weak, strong, cascade
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ScheduledInvalidation represents a scheduled invalidation task
type ScheduledInvalidation struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Enabled     bool                  `json:"enabled"`
	Schedule    *InvalidationSchedule `json:"schedule"`
	Patterns    []string              `json:"patterns"`
	Tags        []string              `json:"tags"`
	Conditions  []*InvalidationCondition `json:"conditions"`
	NextRun     time.Time             `json:"next_run"`
	LastRun     *time.Time            `json:"last_run"`
	RunCount    int64                 `json:"run_count"`
	Description string                `json:"description"`
}

// InvalidationSchedule defines when scheduled invalidation runs
type InvalidationSchedule struct {
	Type        string   `json:"type"`         // cron, interval, daily, weekly
	Expression  string   `json:"expression"`   // cron expression or interval
	Timezone    string   `json:"timezone"`
	StartDate   string   `json:"start_date"`
	EndDate     string   `json:"end_date"`
	MaxRuns     int64    `json:"max_runs"`
}

// InvalidationMetrics tracks invalidation performance
type InvalidationMetrics struct {
	// Event metrics
	EventsProcessed       int64 `json:"events_processed"`
	EventsQueued          int64 `json:"events_queued"`
	EventProcessingErrors int64 `json:"event_processing_errors"`
	
	// Pattern metrics
	PatternInvalidations  int64 `json:"pattern_invalidations"`
	RegexInvalidations    int64 `json:"regex_invalidations"`
	WildcardInvalidations int64 `json:"wildcard_invalidations"`
	
	// Dependency metrics
	DependencyInvalidations int64 `json:"dependency_invalidations"`
	CascadeInvalidations    int64 `json:"cascade_invalidations"`
	
	// Tag metrics
	TagInvalidations      int64 `json:"tag_invalidations"`
	TagsProcessed         int64 `json:"tags_processed"`
	
	// Scheduled metrics
	ScheduledRuns         int64 `json:"scheduled_runs"`
	ScheduledErrors       int64 `json:"scheduled_errors"`
	
	// Performance metrics
	AverageInvalidationTime time.Duration `json:"average_invalidation_time"`
	TotalKeysInvalidated    int64         `json:"total_keys_invalidated"`
	
	// Error metrics
	InvalidationErrors    int64 `json:"invalidation_errors"`
	TimeoutErrors         int64 `json:"timeout_errors"`
	
	mu sync.RWMutex
}

// NewInvalidationManager creates a new invalidation manager
func NewInvalidationManager(redisClient *redis.Client, config *InvalidationConfig, logger *logrus.Logger) *InvalidationManager {
	if config == nil {
		config = getDefaultInvalidationConfig()
	}
	
	if logger == nil {
		logger = logrus.New()
	}
	
	im := &InvalidationManager{
		redisClient:    redisClient,
		config:         config,
		logger:         logger,
		eventListeners: make(map[string][]*EventListener),
		eventQueue:     make(chan *InvalidationEvent, config.EventQueueSize),
		dependencies:   make(map[string][]*Dependency),
		tagIndex:       make(map[string]map[string]bool),
		schedules:      []*ScheduledInvalidation{},
		metrics:        &InvalidationMetrics{},
		stopChan:       make(chan struct{}),
	}
	
	// Start background workers
	im.startBackgroundWorkers()
	
	return im
}

// InvalidateByPattern invalidates cache entries matching patterns
func (im *InvalidationManager) InvalidateByPattern(ctx context.Context, patterns []string) (*InvalidationResult, error) {
	start := time.Now()
	result := &InvalidationResult{
		Patterns:    patterns,
		StartTime:   start,
		KeysRemoved: 0,
		Errors:      []string{},
	}
	
	for _, pattern := range patterns {
		keys, err := im.findKeysForPattern(ctx, pattern)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("pattern %s: %v", pattern, err))
			continue
		}
		
		if len(keys) > 0 {
			removed, err := im.deleteKeys(ctx, keys)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("delete keys for %s: %v", pattern, err))
			} else {
				result.KeysRemoved += removed
			}
		}
	}
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	// Update metrics
	im.updatePatternMetrics(len(patterns), result.KeysRemoved)
	
	return result, nil
}

// InvalidateByTags invalidates cache entries with specific tags
func (im *InvalidationManager) InvalidateByTags(ctx context.Context, tags []string) (*InvalidationResult, error) {
	if !im.config.TagBasedEnabled {
		return nil, fmt.Errorf("tag-based invalidation is disabled")
	}
	
	start := time.Now()
	result := &InvalidationResult{
		Tags:        tags,
		StartTime:   start,
		KeysRemoved: 0,
		Errors:      []string{},
	}
	
	im.tagMu.RLock()
	var allKeys []string
	for _, tag := range tags {
		if keys, exists := im.tagIndex[tag]; exists {
			for key := range keys {
				allKeys = append(allKeys, key)
			}
		}
	}
	im.tagMu.RUnlock()
	
	if len(allKeys) > 0 {
		// Remove duplicates
		uniqueKeys := removeDuplicateStrings(allKeys)
		
		removed, err := im.deleteKeys(ctx, uniqueKeys)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("delete keys: %v", err))
		} else {
			result.KeysRemoved = removed
		}
		
		// Update tag index
		im.removeKeysFromTagIndex(uniqueKeys)
	}
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	// Update metrics
	im.updateTagMetrics(len(tags), result.KeysRemoved)
	
	return result, nil
}

// InvalidateByEvent processes an invalidation event
func (im *InvalidationManager) InvalidateByEvent(event *InvalidationEvent) error {
	if !im.config.EventDrivenEnabled {
		return fmt.Errorf("event-driven invalidation is disabled")
	}
	
	// Queue event for processing
	select {
	case im.eventQueue <- event:
		im.metrics.mu.Lock()
		im.metrics.EventsQueued++
		im.metrics.mu.Unlock()
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("event queue is full")
	}
}

// InvalidateByDependency invalidates cache entries based on dependencies
func (im *InvalidationManager) InvalidateByDependency(ctx context.Context, targetKey string) (*InvalidationResult, error) {
	if !im.config.DependencyEnabled {
		return nil, fmt.Errorf("dependency-based invalidation is disabled")
	}
	
	start := time.Now()
	result := &InvalidationResult{
		Dependencies: []string{targetKey},
		StartTime:    start,
		KeysRemoved:  0,
		Errors:       []string{},
	}
	
	// Find all keys that depend on this target
	dependentKeys := im.findDependentKeys(targetKey)
	
	if len(dependentKeys) > 0 {
		removed, err := im.deleteKeys(ctx, dependentKeys)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("delete dependent keys: %v", err))
		} else {
			result.KeysRemoved = removed
		}
		
		// Remove dependencies
		im.removeDependencies(targetKey)
		
		// Handle cascade invalidation
		if im.config.CascadeEnabled {
			im.cascadeInvalidation(ctx, dependentKeys, 1, result)
		}
	}
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	
	// Update metrics
	im.updateDependencyMetrics(result.KeysRemoved)
	
	return result, nil
}

// InvalidateByUser invalidates all cache entries for a specific user
func (im *InvalidationManager) InvalidateByUser(ctx context.Context, userID string) (*InvalidationResult, error) {
	if !im.config.UserSpecificEnabled {
		return nil, fmt.Errorf("user-specific invalidation is disabled")
	}
	
	pattern := fmt.Sprintf("*:user:%s:*", userID)
	return im.InvalidateByPattern(ctx, []string{pattern})
}

// InvalidateByOrganization invalidates all cache entries for a specific organization
func (im *InvalidationManager) InvalidateByOrganization(ctx context.Context, orgID string) (*InvalidationResult, error) {
	if !im.config.OrgSpecificEnabled {
		return nil, fmt.Errorf("organization-specific invalidation is disabled")
	}
	
	pattern := fmt.Sprintf("*:org:%s:*", orgID)
	return im.InvalidateByPattern(ctx, []string{pattern})
}

// AddDependency adds a cache dependency relationship
func (im *InvalidationManager) AddDependency(dependency *Dependency) error {
	if !im.config.DependencyEnabled {
		return fmt.Errorf("dependency tracking is disabled")
	}
	
	im.dependencyMu.Lock()
	defer im.dependencyMu.Unlock()
	
	if im.dependencies[dependency.TargetKey] == nil {
		im.dependencies[dependency.TargetKey] = []*Dependency{}
	}
	
	im.dependencies[dependency.TargetKey] = append(im.dependencies[dependency.TargetKey], dependency)
	
	return nil
}

// AddTags associates tags with a cache key
func (im *InvalidationManager) AddTags(cacheKey string, tags []string) error {
	if !im.config.TagBasedEnabled {
		return fmt.Errorf("tag-based invalidation is disabled")
	}
	
	if len(tags) > im.config.MaxTagsPerEntry {
		return fmt.Errorf("too many tags: %d (max: %d)", len(tags), im.config.MaxTagsPerEntry)
	}
	
	im.tagMu.Lock()
	defer im.tagMu.Unlock()
	
	for _, tag := range tags {
		if im.tagIndex[tag] == nil {
			im.tagIndex[tag] = make(map[string]bool)
		}
		im.tagIndex[tag][cacheKey] = true
	}
	
	return nil
}

// AddEventListener registers an event listener for invalidation
func (im *InvalidationManager) AddEventListener(listener *EventListener) error {
	if !im.config.EventDrivenEnabled {
		return fmt.Errorf("event-driven invalidation is disabled")
	}
	
	if im.eventListeners[listener.EventType] == nil {
		im.eventListeners[listener.EventType] = []*EventListener{}
	}
	
	im.eventListeners[listener.EventType] = append(im.eventListeners[listener.EventType], listener)
	
	return nil
}

// AddScheduledInvalidation adds a scheduled invalidation task
func (im *InvalidationManager) AddScheduledInvalidation(schedule *ScheduledInvalidation) error {
	if !im.config.ScheduledEnabled {
		return fmt.Errorf("scheduled invalidation is disabled")
	}
	
	// Calculate next run time
	nextRun, err := im.calculateNextRun(schedule.Schedule)
	if err != nil {
		return fmt.Errorf("invalid schedule: %v", err)
	}
	
	schedule.NextRun = nextRun
	
	im.scheduleMu.Lock()
	im.schedules = append(im.schedules, schedule)
	im.scheduleMu.Unlock()
	
	return nil
}

// InvalidationResult holds the result of an invalidation operation
type InvalidationResult struct {
	Patterns     []string      `json:"patterns,omitempty"`
	Tags         []string      `json:"tags,omitempty"`
	Dependencies []string      `json:"dependencies,omitempty"`
	UserID       string        `json:"user_id,omitempty"`
	OrgID        string        `json:"org_id,omitempty"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	KeysRemoved  int64         `json:"keys_removed"`
	Errors       []string      `json:"errors"`
}

// Helper methods and background workers continue...
// [Implementation continues with background workers, metrics, and utility functions]

func getDefaultInvalidationConfig() *InvalidationConfig {
	return &InvalidationConfig{
		EventDrivenEnabled:    true,
		EventQueueSize:        1000,
		EventProcessorWorkers: 5,
		DependencyEnabled:     true,
		MaxDependencyDepth:    5,
		DependencyTTL:         24 * time.Hour,
		TagBasedEnabled:       true,
		MaxTagsPerEntry:       20,
		TagIndexTTL:          24 * time.Hour,
		ScheduledEnabled:      true,
		ScheduleCheckInterval: 1 * time.Minute,
		PatternEnabled:        true,
		RegexSupport:         true,
		WildcardSupport:      true,
		UserSpecificEnabled:   true,
		OrgSpecificEnabled:    true,
		BatchSize:            100,
		MaxConcurrentOps:     10,
		InvalidationTimeout:  30 * time.Second,
		CascadeEnabled:       true,
		MaxCascadeDepth:      3,
	}
}

func (im *InvalidationManager) updatePatternMetrics(patterns int, keysRemoved int64) {
	im.metrics.mu.Lock()
	defer im.metrics.mu.Unlock()
	
	im.metrics.PatternInvalidations += int64(patterns)
	im.metrics.TotalKeysInvalidated += keysRemoved
} 