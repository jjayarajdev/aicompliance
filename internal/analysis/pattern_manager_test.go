package analysis

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestPatternManager_NewPatternManager(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	
	if pm == nil {
		t.Fatal("Expected non-nil pattern manager")
	}
	
	if pm.validator == nil {
		t.Fatal("Expected validator to be initialized")
	}
	
	if pm.versioning == nil {
		t.Fatal("Expected versioning to be initialized")
	}
}

func TestPatternManager_AddPattern(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	
	pattern := &CustomPattern{
		ID:           "test-pattern-1",
		Name:         "Test Employee ID",
		Description:  "Matches employee ID format EMP-XXXXXX",
		Pattern:      `EMP-\d{6}`,
		PIIType:      "custom",
		Organization: "test-org",
		CreatedBy:    "test-user",
		Priority:     10,
		Confidence:   0.9,
		IsActive:     true,
	}
	
	ctx := context.Background()
	err := pm.AddPattern(ctx, pattern)
	
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}
	
	// Verify pattern was stored
	stored, err := pm.GetPattern(pattern.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve pattern: %v", err)
	}
	
	if stored.Name != pattern.Name {
		t.Errorf("Expected name %s, got %s", pattern.Name, stored.Name)
	}
	
	if stored.compiledRegex == nil {
		t.Error("Expected compiled regex to be set")
	}
}

func TestPatternManager_GetPatternsByOrganization(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	// Add multiple patterns for the same organization
	patterns := []*CustomPattern{
		{
			ID: "pattern-1", Name: "Pattern 1", Pattern: `TEST-\d{3}`,
			PIIType: "custom", Organization: "org1", CreatedBy: "user1",
			Priority: 10, IsActive: true,
		},
		{
			ID: "pattern-2", Name: "Pattern 2", Pattern: `USER-\d{4}`,
			PIIType: "custom", Organization: "org1", CreatedBy: "user1",
			Priority: 20, IsActive: true,
		},
		{
			ID: "pattern-3", Name: "Pattern 3", Pattern: `DOC-\d{5}`,
			PIIType: "custom", Organization: "org2", CreatedBy: "user1",
			Priority: 5, IsActive: true,
		},
	}
	
	for _, pattern := range patterns {
		err := pm.AddPattern(ctx, pattern)
		if err != nil {
			t.Fatalf("Failed to add pattern %s: %v", pattern.ID, err)
		}
	}
	
	// Get patterns for org1
	org1Patterns := pm.GetPatternsByOrganization("org1")
	if len(org1Patterns) != 2 {
		t.Errorf("Expected 2 patterns for org1, got %d", len(org1Patterns))
	}
	
	// Verify they're sorted by priority (higher first)
	if org1Patterns[0].Priority < org1Patterns[1].Priority {
		t.Error("Expected patterns to be sorted by priority descending")
	}
	
	// Get patterns for org2
	org2Patterns := pm.GetPatternsByOrganization("org2")
	if len(org2Patterns) != 1 {
		t.Errorf("Expected 1 pattern for org2, got %d", len(org2Patterns))
	}
}

func TestPatternManager_UpdatePattern(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	// Add initial pattern
	pattern := &CustomPattern{
		ID: "test-pattern", Name: "Original Name", Pattern: `ORIG-\d{3}`,
		PIIType: "custom", Organization: "test-org", CreatedBy: "user1",
		Priority: 10, IsActive: true,
	}
	
	err := pm.AddPattern(ctx, pattern)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}
	
	// Update pattern
	updates := &CustomPattern{
		Name:        "Updated Name",
		Pattern:     `UPD-\d{4}`,
		Priority:    20,
		Description: "Updated description",
	}
	
	err = pm.UpdatePattern(ctx, pattern.ID, updates, "user2", "Test update")
	if err != nil {
		t.Fatalf("Failed to update pattern: %v", err)
	}
	
	// Verify updates
	updated, err := pm.GetPattern(pattern.ID)
	if err != nil {
		t.Fatalf("Failed to get updated pattern: %v", err)
	}
	
	if updated.Name != updates.Name {
		t.Errorf("Expected name %s, got %s", updates.Name, updated.Name)
	}
	
	if updated.Pattern != updates.Pattern {
		t.Errorf("Expected pattern %s, got %s", updates.Pattern, updated.Pattern)
	}
	
	if updated.Priority != updates.Priority {
		t.Errorf("Expected priority %d, got %d", updates.Priority, updated.Priority)
	}
	
	// Verify version history
	versions := pm.GetPatternVersions(pattern.ID)
	if len(versions) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}
}

func TestPatternManager_TestPattern(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	
	pattern := &CustomPattern{
		ID:      "test-pattern",
		Name:    "Test Pattern",
		Pattern: `EMP-\d{6}`,
		PIIType: "custom",
	}
	
	testCases := []PatternTestCase{
		{Input: "EMP-123456", ShouldMatch: true, ExpectedMatch: "EMP-123456"},
		{Input: "EMP-ABCDEF", ShouldMatch: false},
		{Input: "USER-123456", ShouldMatch: false},
		{Input: "Some text with EMP-789012 in it", ShouldMatch: true, ExpectedMatch: "EMP-789012"},
	}
	
	ctx := context.Background()
	result, err := pm.TestPattern(ctx, pattern, testCases)
	
	if err != nil {
		t.Fatalf("Failed to test pattern: %v", err)
	}
	
	if !result.IsValid {
		t.Errorf("Expected pattern to be valid, but got errors: %v", result.Errors)
	}
	
	// Check individual test results
	for i, testCase := range result.TestInputs {
		if !testCase.Passed {
			t.Errorf("Test case %d failed: input %s", i, testCase.Input)
		}
	}
	
	// Check performance metrics
	if result.Performance.AverageExecutionTime <= 0 {
		t.Error("Expected positive average execution time")
	}
	
	if result.Performance.ComplexityScore <= 0 {
		t.Error("Expected positive complexity score")
	}
}

func TestPatternManager_InvalidPattern(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	
	// Test invalid regex
	pattern := &CustomPattern{
		ID:           "invalid-pattern",
		Name:         "Invalid Pattern",
		Pattern:      `[unclosed bracket`,
		PIIType:      "custom",
		Organization: "test-org",
		CreatedBy:    "test-user",
	}
	
	ctx := context.Background()
	err := pm.AddPattern(ctx, pattern)
	
	if err == nil {
		t.Fatal("Expected error for invalid regex pattern")
	}
}

func TestPatternManager_PatternValidation(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	
	testCases := []struct {
		name        string
		pattern     *CustomPattern
		shouldError bool
	}{
		{
			name: "Missing ID",
			pattern: &CustomPattern{
				Name: "Test", Pattern: `test`, Organization: "org", CreatedBy: "user",
			},
			shouldError: true,
		},
		{
			name: "Missing Name",
			pattern: &CustomPattern{
				ID: "test", Pattern: `test`, Organization: "org", CreatedBy: "user",
			},
			shouldError: true,
		},
		{
			name: "Missing Pattern",
			pattern: &CustomPattern{
				ID: "test", Name: "Test", Organization: "org", CreatedBy: "user",
			},
			shouldError: true,
		},
		{
			name: "Missing Organization",
			pattern: &CustomPattern{
				ID: "test", Name: "Test", Pattern: `test`, CreatedBy: "user",
			},
			shouldError: true,
		},
		{
			name: "Missing CreatedBy",
			pattern: &CustomPattern{
				ID: "test", Name: "Test", Pattern: `test`, Organization: "org",
			},
			shouldError: true,
		},
		{
			name: "Valid Pattern",
			pattern: &CustomPattern{
				ID: "test", Name: "Test", Pattern: `test`, 
				Organization: "org", CreatedBy: "user", PIIType: "custom",
			},
			shouldError: false,
		},
	}
	
	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := pm.AddPattern(ctx, tc.pattern)
			
			if tc.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tc.shouldError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestPatternManager_ActivateDeactivate(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	pattern := &CustomPattern{
		ID: "test-pattern", Name: "Test Pattern", Pattern: `TEST-\d{3}`,
		PIIType: "custom", Organization: "test-org", CreatedBy: "user1",
		IsActive: true,
	}
	
	err := pm.AddPattern(ctx, pattern)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}
	
	// Deactivate pattern
	err = pm.DeactivatePattern(ctx, pattern.ID, "admin", "Testing deactivation")
	if err != nil {
		t.Fatalf("Failed to deactivate pattern: %v", err)
	}
	
	// Verify deactivation
	updated, _ := pm.GetPattern(pattern.ID)
	if updated.IsActive {
		t.Error("Expected pattern to be inactive")
	}
	
	// Reactivate pattern
	err = pm.ActivatePattern(ctx, pattern.ID, "admin", "Testing reactivation")
	if err != nil {
		t.Fatalf("Failed to reactivate pattern: %v", err)
	}
	
	// Verify activation
	updated, _ = pm.GetPattern(pattern.ID)
	if !updated.IsActive {
		t.Error("Expected pattern to be active")
	}
	
	// Check version history
	versions := pm.GetPatternVersions(pattern.ID)
	if len(versions) < 3 { // created, deactivated, activated
		t.Errorf("Expected at least 3 versions, got %d", len(versions))
	}
}

func TestPatternManager_RollbackPattern(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	// Add initial pattern
	pattern := &CustomPattern{
		ID: "test-pattern", Name: "Version 1", Pattern: `V1-\d{3}`,
		PIIType: "custom", Organization: "test-org", CreatedBy: "user1",
	}
	
	err := pm.AddPattern(ctx, pattern)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}
	
	// Update to version 2
	updates := &CustomPattern{Name: "Version 2", Pattern: `V2-\d{4}`}
	err = pm.UpdatePattern(ctx, pattern.ID, updates, "user1", "Update to v2")
	if err != nil {
		t.Fatalf("Failed to update pattern: %v", err)
	}
	
	// Update to version 3
	updates = &CustomPattern{Name: "Version 3", Pattern: `V3-\d{5}`}
	err = pm.UpdatePattern(ctx, pattern.ID, updates, "user1", "Update to v3")
	if err != nil {
		t.Fatalf("Failed to update pattern: %v", err)
	}
	
	// Rollback to version 1
	err = pm.RollbackPattern(ctx, pattern.ID, 1, "admin", "Rolling back to v1")
	if err != nil {
		t.Fatalf("Failed to rollback pattern: %v", err)
	}
	
	// Verify rollback
	rolledBack, _ := pm.GetPattern(pattern.ID)
	if rolledBack.Name != "Version 1" {
		t.Errorf("Expected name 'Version 1', got %s", rolledBack.Name)
	}
	
	if rolledBack.Pattern != `V1-\d{3}` {
		t.Errorf("Expected pattern 'V1-\\d{3}', got %s", rolledBack.Pattern)
	}
}

func TestPatternManager_PerformanceTracking(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	pattern := &CustomPattern{
		ID: "perf-pattern", Name: "Performance Test", Pattern: `PERF-\d{3}`,
		PIIType: "custom", Organization: "test-org", CreatedBy: "user1",
	}
	
	err := pm.AddPattern(ctx, pattern)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}
	
	// Simulate matches
	pm.UpdatePatternPerformance(pattern.ID, true, 1*time.Millisecond)
	pm.UpdatePatternPerformance(pattern.ID, true, 2*time.Millisecond)
	pm.UpdatePatternPerformance(pattern.ID, false, 1*time.Millisecond) // false positive
	
	// Verify performance tracking
	updated, _ := pm.GetPattern(pattern.ID)
	if updated.MatchCount != 2 {
		t.Errorf("Expected match count 2, got %d", updated.MatchCount)
	}
	
	if updated.LastMatched == nil {
		t.Error("Expected last matched time to be set")
	}
	
	if updated.PerformanceScore <= 0 {
		t.Error("Expected positive performance score")
	}
}

func TestPatternManager_DeletePattern(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	pattern := &CustomPattern{
		ID: "delete-test", Name: "Delete Test", Pattern: `DEL-\d{3}`,
		PIIType: "custom", Organization: "test-org", CreatedBy: "user1",
	}
	
	err := pm.AddPattern(ctx, pattern)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}
	
	// Delete pattern
	err = pm.DeletePattern(ctx, pattern.ID, "admin", "Testing deletion")
	if err != nil {
		t.Fatalf("Failed to delete pattern: %v", err)
	}
	
	// Verify deletion
	_, err = pm.GetPattern(pattern.ID)
	if err == nil {
		t.Error("Expected error when getting deleted pattern")
	}
	
	// Verify deletion is in version history
	versions := pm.GetPatternVersions(pattern.ID)
	if len(versions) != 2 { // created, deleted
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}
	
	lastVersion := versions[len(versions)-1]
	if lastVersion.ChangeType != "deleted" {
		t.Errorf("Expected last version to be 'deleted', got %s", lastVersion.ChangeType)
	}
}

func TestPatternManager_ComplexityCalculation(t *testing.T) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	
	testCases := []struct {
		pattern   string
		expectHigh bool
	}{
		{"simple", false},
		{".*complex.*with.*multiple.*wildcards.*", true},
		{"(?:group1|group2|group3)+", true},
		{"^start", false},
		{"end$", false},
	}
	
	for _, tc := range testCases {
		score := pm.calculateComplexityScore(tc.pattern)
		
		if tc.expectHigh && score <= 50 {
			t.Errorf("Expected high complexity for pattern %s, got %d", tc.pattern, score)
		}
		
		if !tc.expectHigh && score > 100 {
			t.Errorf("Expected low complexity for pattern %s, got %d", tc.pattern, score)
		}
	}
}

// Benchmark tests
func BenchmarkPatternManager_AddPattern(b *testing.B) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern := &CustomPattern{
			ID: fmt.Sprintf("bench-pattern-%d", i),
			Name: "Benchmark Pattern", Pattern: `BENCH-\d{3}`,
			PIIType: "custom", Organization: "bench-org", CreatedBy: "bench-user",
		}
		
		pm.AddPattern(ctx, pattern)
	}
}

func BenchmarkPatternManager_GetPatternsByOrganization(b *testing.B) {
	config := GetDefaultPatternManagerConfig()
	pm := NewPatternManager(config)
	ctx := context.Background()
	
	// Add test patterns
	for i := 0; i < 100; i++ {
		pattern := &CustomPattern{
			ID: fmt.Sprintf("pattern-%d", i),
			Name: "Test Pattern", Pattern: `TEST-\d{3}`,
			PIIType: "custom", Organization: "test-org", CreatedBy: "user",
		}
		pm.AddPattern(ctx, pattern)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.GetPatternsByOrganization("test-org")
	}
} 