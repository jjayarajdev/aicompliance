package analysis

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// PatternManager manages custom detection patterns for organizations
type PatternManager struct {
	patterns       map[string]*CustomPattern
	patternsByOrg  map[string][]*CustomPattern
	patternsByType map[string][]*CustomPattern
	mu             sync.RWMutex
	validator      *PatternValidator
	versioning     *PatternVersioning
}

// CustomPattern represents an organization-specific detection pattern
type CustomPattern struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Pattern      string                 `json:"pattern"`
	PIIType      string                 `json:"pii_type"`
	Organization string                 `json:"organization"`
	CreatedBy    string                 `json:"created_by"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	IsActive     bool                   `json:"is_active"`
	Priority     int                    `json:"priority"`
	Tags         []string               `json:"tags"`
	Metadata     map[string]interface{} `json:"metadata"`
	
	// Pattern properties
	CaseSensitive bool    `json:"case_sensitive"`
	Confidence    float64 `json:"confidence"`
	ValidatedBy   string  `json:"validated_by"`
	ValidatedAt   *time.Time `json:"validated_at"`
	
	// Performance metrics
	MatchCount      int64   `json:"match_count"`
	FalsePositives  int64   `json:"false_positives"`
	LastMatched     *time.Time `json:"last_matched"`
	PerformanceScore float64 `json:"performance_score"`
	
	// Compiled regex (not serialized)
	compiledRegex *regexp.Regexp `json:"-"`
}

// PatternTestResult represents the result of pattern testing
type PatternTestResult struct {
	PatternID    string             `json:"pattern_id"`
	TestInputs   []PatternTestCase  `json:"test_inputs"`
	IsValid      bool               `json:"is_valid"`
	Errors       []string           `json:"errors"`
	Warnings     []string           `json:"warnings"`
	Performance  PatternPerformance `json:"performance"`
	Suggestions  []string           `json:"suggestions"`
}

// PatternTestCase represents a single test case for pattern validation
type PatternTestCase struct {
	Input          string `json:"input"`
	ShouldMatch    bool   `json:"should_match"`
	ExpectedMatch  string `json:"expected_match,omitempty"`
	ActualMatch    string `json:"actual_match,omitempty"`
	Passed         bool   `json:"passed"`
	ExecutionTime  int64  `json:"execution_time_ns"`
}

// PatternPerformance contains performance metrics for a pattern
type PatternPerformance struct {
	AverageExecutionTime int64   `json:"average_execution_time_ns"`
	MaxExecutionTime     int64   `json:"max_execution_time_ns"`
	MinExecutionTime     int64   `json:"min_execution_time_ns"`
	ThroughputPerSecond  float64 `json:"throughput_per_second"`
	ComplexityScore      int     `json:"complexity_score"`
}

// PatternValidator handles pattern validation and testing
type PatternValidator struct {
	maxExecutionTime time.Duration
	maxPatternLength int
	bannedPatterns   []*regexp.Regexp
}

// PatternVersioning manages pattern versions and rollback capabilities
type PatternVersioning struct {
	versions map[string][]*PatternVersion
	mu       sync.RWMutex
}

// PatternVersion represents a historical version of a pattern
type PatternVersion struct {
	Version     int                    `json:"version"`
	Pattern     *CustomPattern         `json:"pattern"`
	ChangedBy   string                 `json:"changed_by"`
	ChangedAt   time.Time              `json:"changed_at"`
	ChangeType  string                 `json:"change_type"` // created, updated, deleted, activated, deactivated
	Reason      string                 `json:"reason"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PatternManagerConfig configures the pattern manager
type PatternManagerConfig struct {
	MaxPatternsPerOrg    int           `mapstructure:"max_patterns_per_org"`
	MaxPatternLength     int           `mapstructure:"max_pattern_length"`
	MaxExecutionTime     time.Duration `mapstructure:"max_execution_time"`
	EnableVersioning     bool          `mapstructure:"enable_versioning"`
	MaxVersionsPerPattern int          `mapstructure:"max_versions_per_pattern"`
	RequireValidation    bool          `mapstructure:"require_validation"`
	AutoDeactivateOnErrors bool        `mapstructure:"auto_deactivate_on_errors"`
	PerformanceTracking  bool          `mapstructure:"performance_tracking"`
}

// NewPatternManager creates a new pattern manager
func NewPatternManager(config PatternManagerConfig) *PatternManager {
	validator := &PatternValidator{
		maxExecutionTime: config.MaxExecutionTime,
		maxPatternLength: config.MaxPatternLength,
		bannedPatterns:   createBannedPatterns(),
	}
	
	versioning := &PatternVersioning{
		versions: make(map[string][]*PatternVersion),
	}
	
	return &PatternManager{
		patterns:       make(map[string]*CustomPattern),
		patternsByOrg:  make(map[string][]*CustomPattern),
		patternsByType: make(map[string][]*CustomPattern),
		validator:      validator,
		versioning:     versioning,
	}
}

// AddPattern adds a new custom pattern
func (pm *PatternManager) AddPattern(ctx context.Context, pattern *CustomPattern) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Validate pattern
	if err := pm.validatePattern(pattern); err != nil {
		return fmt.Errorf("pattern validation failed: %w", err)
	}
	
	// Compile regex
	var regex *regexp.Regexp
	var err error
	
	if pattern.CaseSensitive {
		regex, err = regexp.Compile(pattern.Pattern)
	} else {
		regex, err = regexp.Compile("(?i)" + pattern.Pattern)
	}
	
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}
	
	pattern.compiledRegex = regex
	pattern.CreatedAt = time.Now()
	pattern.UpdatedAt = time.Now()
	
	// Store pattern
	pm.patterns[pattern.ID] = pattern
	pm.patternsByOrg[pattern.Organization] = append(pm.patternsByOrg[pattern.Organization], pattern)
	pm.patternsByType[pattern.PIIType] = append(pm.patternsByType[pattern.PIIType], pattern)
	
	// Add to version history
	if pm.versioning != nil {
		pm.versioning.addVersion(pattern.ID, &PatternVersion{
			Version:    1,
			Pattern:    pattern,
			ChangedBy:  pattern.CreatedBy,
			ChangedAt:  time.Now(),
			ChangeType: "created",
			Reason:     "Initial pattern creation",
		})
	}
	
	return nil
}

// UpdatePattern updates an existing pattern
func (pm *PatternManager) UpdatePattern(ctx context.Context, patternID string, updates *CustomPattern, changedBy, reason string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	existing, exists := pm.patterns[patternID]
	if !exists {
		return fmt.Errorf("pattern not found: %s", patternID)
	}
	
	// Create updated pattern
	updated := *existing
	if updates.Name != "" {
		updated.Name = updates.Name
	}
	if updates.Description != "" {
		updated.Description = updates.Description
	}
	if updates.Pattern != "" {
		updated.Pattern = updates.Pattern
		// Recompile regex
		var regex *regexp.Regexp
		var err error
		
		if updated.CaseSensitive {
			regex, err = regexp.Compile(updated.Pattern)
		} else {
			regex, err = regexp.Compile("(?i)" + updated.Pattern)
		}
		
		if err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
		updated.compiledRegex = regex
	}
	if updates.Priority != 0 {
		updated.Priority = updates.Priority
	}
	if updates.Confidence != 0 {
		updated.Confidence = updates.Confidence
	}
	if updates.Tags != nil {
		updated.Tags = updates.Tags
	}
	if updates.Metadata != nil {
		updated.Metadata = updates.Metadata
	}
	
	updated.UpdatedAt = time.Now()
	
	// Validate updated pattern
	if err := pm.validatePattern(&updated); err != nil {
		return fmt.Errorf("updated pattern validation failed: %w", err)
	}
	
	// Store updated pattern
	pm.patterns[patternID] = &updated
	
	// Update organization and type indexes
	pm.rebuildIndexes()
	
	// Add to version history
	if pm.versioning != nil {
		version := pm.versioning.getNextVersion(patternID)
		pm.versioning.addVersion(patternID, &PatternVersion{
			Version:    version,
			Pattern:    &updated,
			ChangedBy:  changedBy,
			ChangedAt:  time.Now(),
			ChangeType: "updated",
			Reason:     reason,
		})
	}
	
	return nil
}

// DeletePattern removes a pattern
func (pm *PatternManager) DeletePattern(ctx context.Context, patternID, deletedBy, reason string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pattern, exists := pm.patterns[patternID]
	if !exists {
		return fmt.Errorf("pattern not found: %s", patternID)
	}
	
	// Add to version history before deletion
	if pm.versioning != nil {
		version := pm.versioning.getNextVersion(patternID)
		pm.versioning.addVersion(patternID, &PatternVersion{
			Version:    version,
			Pattern:    pattern,
			ChangedBy:  deletedBy,
			ChangedAt:  time.Now(),
			ChangeType: "deleted",
			Reason:     reason,
		})
	}
	
	// Remove from all indexes
	delete(pm.patterns, patternID)
	pm.rebuildIndexes()
	
	return nil
}

// GetPattern retrieves a pattern by ID
func (pm *PatternManager) GetPattern(patternID string) (*CustomPattern, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	pattern, exists := pm.patterns[patternID]
	if !exists {
		return nil, fmt.Errorf("pattern not found: %s", patternID)
	}
	
	return pattern, nil
}

// GetPatternsByOrganization retrieves all patterns for an organization
func (pm *PatternManager) GetPatternsByOrganization(org string) []*CustomPattern {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	patterns := pm.patternsByOrg[org]
	result := make([]*CustomPattern, len(patterns))
	copy(result, patterns)
	
	// Sort by priority (higher priority first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority > result[j].Priority
	})
	
	return result
}

// GetPatternsByType retrieves all patterns for a PII type
func (pm *PatternManager) GetPatternsByType(piiType string) []*CustomPattern {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	patterns := pm.patternsByType[piiType]
	result := make([]*CustomPattern, len(patterns))
	copy(result, patterns)
	
	return result
}

// TestPattern tests a pattern against sample inputs
func (pm *PatternManager) TestPattern(ctx context.Context, pattern *CustomPattern, testCases []PatternTestCase) (*PatternTestResult, error) {
	result := &PatternTestResult{
		PatternID:  pattern.ID,
		TestInputs: make([]PatternTestCase, len(testCases)),
		IsValid:    true,
		Errors:     []string{},
		Warnings:   []string{},
		Performance: PatternPerformance{},
		Suggestions: []string{},
	}
	
	// Validate pattern first
	if err := pm.validator.validateRegex(pattern.Pattern); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid regex: %v", err))
		return result, nil
	}
	
	// Compile regex for testing
	var regex *regexp.Regexp
	var err error
	
	if pattern.CaseSensitive {
		regex, err = regexp.Compile(pattern.Pattern)
	} else {
		regex, err = regexp.Compile("(?i)" + pattern.Pattern)
	}
	
	if err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Regex compilation failed: %v", err))
		return result, nil
	}
	
	// Run test cases
	var totalExecutionTime int64
	maxTime := int64(0)
	minTime := int64(^uint64(0) >> 1) // Max int64
	
	for i, testCase := range testCases {
		start := time.Now()
		
		match := regex.FindString(testCase.Input)
		
		executionTime := time.Since(start).Nanoseconds()
		totalExecutionTime += executionTime
		
		if executionTime > maxTime {
			maxTime = executionTime
		}
		if executionTime < minTime {
			minTime = executionTime
		}
		
		result.TestInputs[i] = PatternTestCase{
			Input:         testCase.Input,
			ShouldMatch:   testCase.ShouldMatch,
			ExpectedMatch: testCase.ExpectedMatch,
			ActualMatch:   match,
			ExecutionTime: executionTime,
		}
		
		// Check if test passed
		if testCase.ShouldMatch {
			result.TestInputs[i].Passed = match != ""
			if testCase.ExpectedMatch != "" && match != testCase.ExpectedMatch {
				result.TestInputs[i].Passed = false
			}
		} else {
			result.TestInputs[i].Passed = match == ""
		}
		
		if !result.TestInputs[i].Passed {
			result.IsValid = false
		}
	}
	
	// Calculate performance metrics
	if len(testCases) > 0 {
		result.Performance.AverageExecutionTime = totalExecutionTime / int64(len(testCases))
		result.Performance.MaxExecutionTime = maxTime
		result.Performance.MinExecutionTime = minTime
		result.Performance.ThroughputPerSecond = float64(time.Second) / float64(result.Performance.AverageExecutionTime)
		result.Performance.ComplexityScore = pm.calculateComplexityScore(pattern.Pattern)
	}
	
	// Generate suggestions
	result.Suggestions = pm.generateSuggestions(pattern, result)
	
	// Check for warnings
	if result.Performance.ComplexityScore > 100 {
		result.Warnings = append(result.Warnings, "Pattern has high complexity and may impact performance")
	}
	
	if result.Performance.AverageExecutionTime > pm.validator.maxExecutionTime.Nanoseconds() {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Pattern execution time exceeds limit (%v)", pm.validator.maxExecutionTime))
	}
	
	return result, nil
}

// ActivatePattern activates a pattern
func (pm *PatternManager) ActivatePattern(ctx context.Context, patternID, activatedBy, reason string) error {
	return pm.togglePatternStatus(ctx, patternID, true, activatedBy, reason)
}

// DeactivatePattern deactivates a pattern
func (pm *PatternManager) DeactivatePattern(ctx context.Context, patternID, deactivatedBy, reason string) error {
	return pm.togglePatternStatus(ctx, patternID, false, deactivatedBy, reason)
}

// togglePatternStatus toggles pattern active status
func (pm *PatternManager) togglePatternStatus(ctx context.Context, patternID string, isActive bool, changedBy, reason string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pattern, exists := pm.patterns[patternID]
	if !exists {
		return fmt.Errorf("pattern not found: %s", patternID)
	}
	
	pattern.IsActive = isActive
	pattern.UpdatedAt = time.Now()
	
	// Add to version history
	if pm.versioning != nil {
		version := pm.versioning.getNextVersion(patternID)
		changeType := "deactivated"
		if isActive {
			changeType = "activated"
		}
		
		pm.versioning.addVersion(patternID, &PatternVersion{
			Version:    version,
			Pattern:    pattern,
			ChangedBy:  changedBy,
			ChangedAt:  time.Now(),
			ChangeType: changeType,
			Reason:     reason,
		})
	}
	
	return nil
}

// RollbackPattern rolls back a pattern to a previous version
func (pm *PatternManager) RollbackPattern(ctx context.Context, patternID string, version int, rolledBackBy, reason string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.versioning == nil {
		return fmt.Errorf("versioning not enabled")
	}
	
	versions := pm.versioning.getVersions(patternID)
	if len(versions) == 0 {
		return fmt.Errorf("no versions found for pattern: %s", patternID)
	}
	
	var targetVersion *PatternVersion
	for _, v := range versions {
		if v.Version == version {
			targetVersion = v
			break
		}
	}
	
	if targetVersion == nil {
		return fmt.Errorf("version %d not found for pattern: %s", version, patternID)
	}
	
	// Restore pattern from version
	restoredPattern := *targetVersion.Pattern
	restoredPattern.UpdatedAt = time.Now()
	
	// Recompile regex
	var regex *regexp.Regexp
	var err error
	
	if restoredPattern.CaseSensitive {
		regex, err = regexp.Compile(restoredPattern.Pattern)
	} else {
		regex, err = regexp.Compile("(?i)" + restoredPattern.Pattern)
	}
	
	if err != nil {
		return fmt.Errorf("failed to compile restored pattern: %w", err)
	}
	
	restoredPattern.compiledRegex = regex
	
	// Store restored pattern
	pm.patterns[patternID] = &restoredPattern
	pm.rebuildIndexes()
	
	// Add rollback to version history
	nextVersion := pm.versioning.getNextVersion(patternID)
	pm.versioning.addVersion(patternID, &PatternVersion{
		Version:    nextVersion,
		Pattern:    &restoredPattern,
		ChangedBy:  rolledBackBy,
		ChangedAt:  time.Now(),
		ChangeType: "rollback",
		Reason:     fmt.Sprintf("Rolled back to version %d: %s", version, reason),
		Metadata: map[string]interface{}{
			"rollback_from_version": nextVersion - 1,
			"rollback_to_version":   version,
		},
	})
	
	return nil
}

// UpdatePatternPerformance updates pattern performance metrics
func (pm *PatternManager) UpdatePatternPerformance(patternID string, matched bool, executionTime time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	pattern, exists := pm.patterns[patternID]
	if !exists {
		return
	}
	
	if matched {
		pattern.MatchCount++
		now := time.Now()
		pattern.LastMatched = &now
	}
	
	// Update performance score (simple algorithm)
	totalMatches := pattern.MatchCount + pattern.FalsePositives
	if totalMatches > 0 {
		accuracy := float64(pattern.MatchCount) / float64(totalMatches)
		speed := 1.0 / executionTime.Seconds() // Operations per second
		pattern.PerformanceScore = (accuracy * 0.7) + (speed * 0.3)
	}
}

// GetPatternVersions retrieves version history for a pattern
func (pm *PatternManager) GetPatternVersions(patternID string) []*PatternVersion {
	if pm.versioning == nil {
		return nil
	}
	
	return pm.versioning.getVersions(patternID)
}

// validatePattern validates a pattern before storing
func (pm *PatternManager) validatePattern(pattern *CustomPattern) error {
	if pattern.ID == "" {
		return fmt.Errorf("pattern ID is required")
	}
	
	if pattern.Name == "" {
		return fmt.Errorf("pattern name is required")
	}
	
	if pattern.Pattern == "" {
		return fmt.Errorf("pattern regex is required")
	}
	
	if pattern.Organization == "" {
		return fmt.Errorf("organization is required")
	}
	
	if pattern.CreatedBy == "" {
		return fmt.Errorf("created by is required")
	}
	
	// Validate regex
	return pm.validator.validateRegex(pattern.Pattern)
}

// rebuildIndexes rebuilds organization and type indexes
func (pm *PatternManager) rebuildIndexes() {
	// Clear indexes
	pm.patternsByOrg = make(map[string][]*CustomPattern)
	pm.patternsByType = make(map[string][]*CustomPattern)
	
	// Rebuild indexes
	for _, pattern := range pm.patterns {
		pm.patternsByOrg[pattern.Organization] = append(pm.patternsByOrg[pattern.Organization], pattern)
		pm.patternsByType[pattern.PIIType] = append(pm.patternsByType[pattern.PIIType], pattern)
	}
}

// calculateComplexityScore calculates a complexity score for a regex pattern
func (pm *PatternManager) calculateComplexityScore(pattern string) int {
	score := 0
	
	// Basic length penalty
	score += len(pattern)
	
	// Complex constructs penalty
	complexConstructs := []string{
		".*", ".+", ".{", "?:", "?=", "?!", "?<=", "?<!",
		"(?", "[^", "\\d", "\\w", "\\s",
	}
	
	for _, construct := range complexConstructs {
		score += strings.Count(pattern, construct) * 10
	}
	
	// Quantifier penalty
	quantifiers := []string{"+", "*", "?", "{"}
	for _, q := range quantifiers {
		score += strings.Count(pattern, q) * 5
	}
	
	return score
}

// generateSuggestions generates improvement suggestions for a pattern
func (pm *PatternManager) generateSuggestions(pattern *CustomPattern, testResult *PatternTestResult) []string {
	var suggestions []string
	
	// Performance suggestions
	if testResult.Performance.ComplexityScore > 100 {
		suggestions = append(suggestions, "Consider simplifying the pattern to improve performance")
	}
	
	if testResult.Performance.AverageExecutionTime > 1000000 { // 1ms
		suggestions = append(suggestions, "Pattern execution time is high - consider optimizing")
	}
	
	// Pattern structure suggestions
	if strings.Contains(pattern.Pattern, ".*.*") {
		suggestions = append(suggestions, "Multiple .* quantifiers may cause catastrophic backtracking")
	}
	
	if !strings.Contains(pattern.Pattern, "^") && !strings.Contains(pattern.Pattern, "$") {
		suggestions = append(suggestions, "Consider adding anchors (^ or $) for more precise matching")
	}
	
	// Test coverage suggestions
	failedTests := 0
	for _, test := range testResult.TestInputs {
		if !test.Passed {
			failedTests++
		}
	}
	
	if failedTests > 0 {
		suggestions = append(suggestions, fmt.Sprintf("%d test cases failed - review pattern logic", failedTests))
	}
	
	return suggestions
}

// ValidateRegex validates a regex pattern
func (pv *PatternValidator) validateRegex(pattern string) error {
	if len(pattern) > pv.maxPatternLength {
		return fmt.Errorf("pattern exceeds maximum length of %d characters", pv.maxPatternLength)
	}
	
	// Check against banned patterns
	for _, banned := range pv.bannedPatterns {
		if banned.MatchString(pattern) {
			return fmt.Errorf("pattern contains banned construct")
		}
	}
	
	// Try to compile the regex
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}
	
	return nil
}

// createBannedPatterns creates regex patterns that are not allowed
func createBannedPatterns() []*regexp.Regexp {
	bannedPatterns := []string{
		`\(\?\#`,     // Comments (can be used for ReDoS)
		`\(\?\:.*\).*\(\?\:.*\).*\(\?\:.*\)`, // Too many non-capturing groups
		`\.\*.*\.\*.*\.\*`, // Multiple .* (catastrophic backtracking risk)
	}
	
	var compiled []*regexp.Regexp
	for _, pattern := range bannedPatterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, regex)
		}
	}
	
	return compiled
}

// Versioning methods

func (pv *PatternVersioning) addVersion(patternID string, version *PatternVersion) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	
	pv.versions[patternID] = append(pv.versions[patternID], version)
	
	// Sort by version number
	sort.Slice(pv.versions[patternID], func(i, j int) bool {
		return pv.versions[patternID][i].Version < pv.versions[patternID][j].Version
	})
}

func (pv *PatternVersioning) getVersions(patternID string) []*PatternVersion {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	
	versions := pv.versions[patternID]
	result := make([]*PatternVersion, len(versions))
	copy(result, versions)
	
	return result
}

func (pv *PatternVersioning) getNextVersion(patternID string) int {
	pv.mu.RLock()
	defer pv.mu.RUnlock()
	
	versions := pv.versions[patternID]
	if len(versions) == 0 {
		return 1
	}
	
	maxVersion := 0
	for _, version := range versions {
		if version.Version > maxVersion {
			maxVersion = version.Version
		}
	}
	
	return maxVersion + 1
}

// GetDefaultPatternManagerConfig returns default configuration
func GetDefaultPatternManagerConfig() PatternManagerConfig {
	return PatternManagerConfig{
		MaxPatternsPerOrg:      100,
		MaxPatternLength:       1000,
		MaxExecutionTime:       10 * time.Millisecond,
		EnableVersioning:       true,
		MaxVersionsPerPattern:  50,
		RequireValidation:      true,
		AutoDeactivateOnErrors: true,
		PerformanceTracking:    true,
	}
} 