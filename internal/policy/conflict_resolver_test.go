package policy

import (
	"testing"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConflictResolver_NewConflictResolver(t *testing.T) {
	resolver := NewConflictResolver(nil)
	
	if resolver == nil {
		t.Fatal("Expected non-nil conflict resolver")
	}
	
	if resolver.config.DefaultStrategy != StrategyMostRestrictive {
		t.Errorf("Expected default strategy to be most restrictive, got %s", resolver.config.DefaultStrategy)
	}
	
	if len(resolver.strategies) == 0 {
		t.Error("Expected strategies to be registered")
	}
}

func TestConflictResolver_MostRestrictiveStrategy(t *testing.T) {
	resolver := NewConflictResolver(nil)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Allow Policy",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionAllow, Severity: SeverityInfo},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "Block Policy",
			Priority:   20,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy3",
			PolicyName: "Warn Policy",
			Priority:   15,
			Confidence: 0.7,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityMedium},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionBlock {
		t.Errorf("Expected Block action (most restrictive), got %s", decision.Action)
	}
	
	if analysis == nil {
		t.Fatal("Expected conflict analysis")
	}
	
	if analysis.TotalConflicts == 0 {
		t.Error("Expected conflicts to be detected")
	}
	
	if analysis.ResolutionStrategy != StrategyMostRestrictive {
		t.Errorf("Expected most restrictive strategy, got %s", analysis.ResolutionStrategy)
	}
	
	t.Logf("Resolution time: %v", analysis.ResolutionTime)
	t.Logf("Selected action: %s", decision.Action)
	t.Logf("Conflicts detected: %d", analysis.TotalConflicts)
}

func TestConflictResolver_HighestPriorityStrategy(t *testing.T) {
	config := &ConflictResolutionConfig{
		DefaultStrategy:  StrategyHighestPriority,
		ActionPriorities: getDefaultActionPriorities(),
	}
	
	resolver := NewConflictResolver(config)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Low Priority Allow",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionAllow, Severity: SeverityInfo},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "High Priority Warn",
			Priority:   100,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityMedium},
		},
		{
			PolicyID:   "policy3",
			PolicyName: "Medium Priority Block",
			Priority:   50,
			Confidence: 0.7,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionWarn {
		t.Errorf("Expected Warn action (highest priority), got %s", decision.Action)
	}
	
	if analysis.ResolutionStrategy != StrategyHighestPriority {
		t.Errorf("Expected highest priority strategy, got %s", analysis.ResolutionStrategy)
	}
	
	t.Logf("Highest priority policy selected: %s", decision.Reason)
}

func TestConflictResolver_WeightedStrategy(t *testing.T) {
	weightedConfig := &WeightedResolutionConfig{
		PolicyWeights: map[string]float64{
			"policy1": 1.0,
			"policy2": 3.0, // Higher weight
			"policy3": 2.0,
		},
		ActionWeights: map[ActionType]float64{
			ActionAllow: 1.0,
			ActionWarn:  2.0,
			ActionBlock: 3.0,
		},
		ConfidenceWeight: 1.0,
		PriorityWeight:   0.1,
	}
	
	config := &ConflictResolutionConfig{
		DefaultStrategy: StrategyWeighted,
		WeightedConfig:  weightedConfig,
	}
	
	resolver := NewConflictResolver(config)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Low Weight Policy",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "High Weight Policy",
			Priority:   10,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityMedium},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionWarn {
		t.Errorf("Expected Warn action (highest weighted), got %s", decision.Action)
	}
	
	if analysis.ResolutionStrategy != StrategyWeighted {
		t.Errorf("Expected weighted strategy, got %s", analysis.ResolutionStrategy)
	}
	
	t.Logf("Weighted resolution result: %s", decision.Reason)
}

func TestConflictResolver_ConsensusStrategy(t *testing.T) {
	consensusConfig := &ConsensusResolutionConfig{
		MinimumAgreement: 0.6, // 60% agreement
		QuorumThreshold:  2,   // At least 2 policies
		TieBreaker:       StrategyMostRestrictive,
	}
	
	config := &ConflictResolutionConfig{
		DefaultStrategy: StrategyConsensus,
		ConsensusConfig: consensusConfig,
	}
	
	resolver := NewConflictResolver(config)
	
	// Test case with clear consensus
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Block Policy 1",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "Block Policy 2",
			Priority:   20,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy3",
			PolicyName: "Warn Policy",
			Priority:   15,
			Confidence: 0.7,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityMedium},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionBlock {
		t.Errorf("Expected Block action (consensus), got %s", decision.Action)
	}
	
	if analysis.ResolutionStrategy != StrategyConsensus {
		t.Errorf("Expected consensus strategy, got %s", analysis.ResolutionStrategy)
	}
	
	t.Logf("Consensus resolution: %s", decision.Reason)
}

func TestConflictResolver_RiskBasedStrategy(t *testing.T) {
	config := &ConflictResolutionConfig{
		DefaultStrategy: StrategyRiskBased,
	}
	
	resolver := NewConflictResolver(config)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Low Risk Policy",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityLow},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "High Risk Policy",
			Priority:   20,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityCritical},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:           "test-request",
		Content:      "SSN: 123-45-6789",
		ContentType:  "sensitive",
		Organization: "finance-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{HasPII: true},
			Classification: &analysis.ClassificationResult{
				Level: analysis.SensitivityConfidential,
			},
		},
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionBlock {
		t.Errorf("Expected Block action (highest risk), got %s", decision.Action)
	}
	
	if analysis.ResolutionStrategy != StrategyRiskBased {
		t.Errorf("Expected risk-based strategy, got %s", analysis.ResolutionStrategy)
	}
	
	t.Logf("Risk-based resolution: %s", decision.Reason)
}

func TestConflictResolver_DetailedAnalysis(t *testing.T) {
	resolver := NewConflictResolver(nil)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Policy 1",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionAllow, Severity: SeverityInfo},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "Policy 2",
			Priority:   10, // Same priority
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy3",
			PolicyName: "Policy 3",
			Priority:   20,
			Confidence: 0.7,
			Action:     PolicyAction{Type: ActionRedact, Severity: SeverityMedium},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	// Verify detailed analysis
	if analysis.TotalConflicts == 0 {
		t.Error("Expected conflicts to be detected")
	}
	
	if len(analysis.ConflictingPolicies) == 0 {
		t.Error("Expected conflicting policy pairs to be identified")
	}
	
	if len(analysis.ActionConflicts) == 0 {
		t.Error("Expected action conflicts to be analyzed")
	}
	
	if len(analysis.PriorityConflicts) == 0 {
		t.Error("Expected priority conflicts to be analyzed")
	}
	
	if len(analysis.Recommendations) == 0 {
		t.Error("Expected recommendations to be generated")
	}
	
	if analysis.Confidence <= 0 {
		t.Error("Expected positive confidence score")
	}
	
	t.Logf("Analysis details:")
	t.Logf("  Total conflicts: %d", analysis.TotalConflicts)
	t.Logf("  Conflicting pairs: %d", len(analysis.ConflictingPolicies))
	t.Logf("  Action conflicts: %d", len(analysis.ActionConflicts))
	t.Logf("  Priority conflicts: %d", len(analysis.PriorityConflicts))
	t.Logf("  Recommendations: %d", len(analysis.Recommendations))
	t.Logf("  Resolution confidence: %.2f", analysis.Confidence)
}

func TestConflictResolver_NoConflicts(t *testing.T) {
	resolver := NewConflictResolver(nil)
	
	// Single policy match - no conflicts
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Single Policy",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionAllow, Severity: SeverityInfo},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionAllow {
		t.Errorf("Expected Allow action, got %s", decision.Action)
	}
	
	if analysis != nil {
		t.Error("Expected no conflict analysis for single policy")
	}
	
	t.Logf("Single policy resolution: %s", decision.Reason)
}

func TestConflictResolver_EmptyMatches(t *testing.T) {
	resolver := NewConflictResolver(nil)
	
	// No policy matches
	matches := []PolicyMatch{}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	decision, analysis, err := resolver.ResolveConflicts(matches, request)
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if decision.Action != ActionAllow {
		t.Errorf("Expected default Allow action, got %s", decision.Action)
	}
	
	if analysis != nil {
		t.Error("Expected no conflict analysis for no policies")
	}
	
	t.Logf("No policies resolution: %s", decision.Reason)
}

func TestConflictResolver_Metrics(t *testing.T) {
	resolver := NewConflictResolver(nil)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Policy 1",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "Policy 2",
			Priority:   20,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityMedium},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Test content",
	}
	
	// Perform multiple resolutions to test metrics
	for i := 0; i < 5; i++ {
		_, _, err := resolver.ResolveConflicts(matches, request)
		if err != nil {
			t.Fatalf("Resolution %d failed: %v", i+1, err)
		}
	}
	
	metrics := resolver.GetMetrics()
	
	if metrics.TotalConflicts == 0 {
		t.Error("Expected conflicts to be tracked in metrics")
	}
	
	if len(metrics.ConflictsByStrategy) == 0 {
		t.Error("Expected strategy usage to be tracked")
	}
	
	if len(metrics.ResolutionTimes) == 0 {
		t.Error("Expected resolution times to be tracked")
	}
	
	if metrics.AverageResolutionTime <= 0 {
		t.Error("Expected positive average resolution time")
	}
	
	t.Logf("Metrics after 5 resolutions:")
	t.Logf("  Total conflicts: %d", metrics.TotalConflicts)
	t.Logf("  Average resolution time: %v", metrics.AverageResolutionTime)
	t.Logf("  Conflicts by strategy: %v", metrics.ConflictsByStrategy)
}

// Benchmark tests for performance validation
func BenchmarkConflictResolver_SimpleConflict(b *testing.B) {
	resolver := NewConflictResolver(nil)
	
	matches := []PolicyMatch{
		{
			PolicyID:   "policy1",
			PolicyName: "Policy 1",
			Priority:   10,
			Confidence: 0.9,
			Action:     PolicyAction{Type: ActionBlock, Severity: SeverityHigh},
		},
		{
			PolicyID:   "policy2",
			PolicyName: "Policy 2",
			Priority:   20,
			Confidence: 0.8,
			Action:     PolicyAction{Type: ActionWarn, Severity: SeverityMedium},
		},
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "benchmark-request",
		Content: "Benchmark content",
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _, err := resolver.ResolveConflicts(matches, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConflictResolver_ComplexConflict(b *testing.B) {
	resolver := NewConflictResolver(nil)
	
	// Create multiple conflicting policies
	matches := make([]PolicyMatch, 10)
	actions := []ActionType{ActionAllow, ActionWarn, ActionBlock, ActionRedact, ActionMask}
	
	for i := 0; i < 10; i++ {
		matches[i] = PolicyMatch{
			PolicyID:   fmt.Sprintf("policy%d", i),
			PolicyName: fmt.Sprintf("Policy %d", i),
			Priority:   i * 10,
			Confidence: 0.8 + float64(i%3)*0.05,
			Action:     PolicyAction{Type: actions[i%len(actions)], Severity: SeverityMedium},
		}
	}
	
	request := &PolicyEvaluationRequest{
		ID:      "benchmark-complex-request",
		Content: "Complex benchmark content",
	}
	
	b.ResetTimer()
	b.ReportAllocs()
	
	for i := 0; i < b.N; i++ {
		_, _, err := resolver.ResolveConflicts(matches, request)
		if err != nil {
			b.Fatal(err)
		}
	}
} 