package analysis

import (
	"context"
	"testing"
	"time"
)

func TestEnsembleVoter_NewEnsembleVoter(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	voter := NewEnsembleVoter(config)
	
	if voter == nil {
		t.Fatal("Expected non-nil ensemble voter")
	}
	
	if voter.config.VotingStrategy != VotingWeighted {
		t.Errorf("Expected default voting strategy %s, got %s", VotingWeighted, voter.config.VotingStrategy)
	}
	
	// Check default component weights
	expectedWeights := map[string]float64{
		"pii_detection":  0.30,
		"classification": 0.30,
		"ml_analysis":    0.25,
		"file_scanning":  0.15,
	}
	
	for component, expectedWeight := range expectedWeights {
		if weight, exists := voter.config.ComponentWeights[component]; !exists {
			t.Errorf("Expected component weight for %s to exist", component)
		} else if weight != expectedWeight {
			t.Errorf("Expected component weight for %s to be %f, got %f", component, expectedWeight, weight)
		}
	}
}

func TestEnsembleVoter_WeightedVoting(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.VotingStrategy = VotingWeighted
	voter := NewEnsembleVoter(config)
	
	// Create mock analysis result
	result := &AnalysisResult{
		PIIDetection: &PIIDetectionResult{
			HasPII: true,
			Matches: []PIIMatch{
				{Type: "email", Value: "test@example.com", Position: Position{Start: 0, End: 16}},
				{Type: "phone", Value: "555-1234", Position: Position{Start: 20, End: 28}},
			},
			Statistics: PIIStatistics{
				ConfidenceAvg: 0.85,
				MatchesByType: map[PIIType]int{
					PIITypeEmail: 1,
					PIITypePhone: 1,
				},
			},
		},
		Classification: &ClassificationResult{
			Level:      SensitivityConfidential,
			Confidence: 0.78,
		},
		MLAnalysis: &MLAnalysisResult{
			ConfidenceScore: 0.82,
			BusinessCategories: []BusinessCategory{
				{Category: "finance", Confidence: 0.9, Sensitivity: "confidential"},
			},
			Entities: &EntityResult{Count: 5},
		},
	}
	
	ctx := context.Background()
	ensembleResult, err := voter.VoteOnAnalysis(ctx, result)
	
	if err != nil {
		t.Fatalf("Ensemble voting failed: %v", err)
	}
	
	if ensembleResult == nil {
		t.Fatal("Expected non-nil ensemble result")
	}
	
	// Check that final decision was made
	if ensembleResult.FinalDecision == "" {
		t.Error("Expected final decision to be set")
	}
	
	// Check confidence metrics
	if ensembleResult.ConfidenceMetrics.WeightedAverage <= 0 {
		t.Error("Expected positive weighted average confidence")
	}
	
	// Check voting results
	if ensembleResult.VotingResults.TotalVotes != 3 {
		t.Errorf("Expected 3 total votes, got %d", ensembleResult.VotingResults.TotalVotes)
	}
	
	// Check component votes
	if len(ensembleResult.ComponentVotes) != 3 {
		t.Errorf("Expected 3 component votes, got %d", len(ensembleResult.ComponentVotes))
	}
	
	// Verify specific component votes exist
	expectedComponents := []string{"pii_detection", "classification", "ml_analysis"}
	for _, component := range expectedComponents {
		if _, exists := ensembleResult.ComponentVotes[component]; !exists {
			t.Errorf("Expected vote from component %s", component)
		}
	}
}

func TestEnsembleVoter_MajorityVoting(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.VotingStrategy = VotingMajority
	voter := NewEnsembleVoter(config)
	
	// Create test analysis result with clear majority
	result := &AnalysisResult{
		PIIDetection: &PIIDetectionResult{
			HasPII:  false,
			Matches: []PIIMatch{},
			Statistics: PIIStatistics{
				ConfidenceAvg: 0.9,
			},
		},
		Classification: &ClassificationResult{
			Level:      SensitivityPublic,
			Confidence: 0.85,
		},
		MLAnalysis: &MLAnalysisResult{
			ConfidenceScore: 0.8,
			BusinessCategories: []BusinessCategory{
				{Category: "general", Confidence: 0.8, Sensitivity: "public"},
			},
			Entities: &EntityResult{Count: 0},
		},
	}
	
	ctx := context.Background()
	ensembleResult, err := voter.VoteOnAnalysis(ctx, result)
	
	if err != nil {
		t.Fatalf("Majority voting failed: %v", err)
	}
	
	// With majority voting, should get "low" as the most frequent decision
	if ensembleResult.VotingResults.WinningOption != "low" {
		t.Errorf("Expected winning option 'low', got '%s'", ensembleResult.VotingResults.WinningOption)
	}
	
	// Check winning margin
	if ensembleResult.VotingResults.WinningMargin <= 0.5 {
		t.Error("Expected winning margin > 0.5 for clear majority")
	}
}

func TestEnsembleVoter_ConsensusVoting(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.VotingStrategy = VotingConsensus
	config.ConsensusThreshold = 0.8 // High threshold
	voter := NewEnsembleVoter(config)
	
	// Create result with disagreement (should fall back to "uncertain")
	result := &AnalysisResult{
		PIIDetection: &PIIDetectionResult{
			HasPII: true,
			Matches: []PIIMatch{
				{Type: "ssn", Value: "123-45-6789", Position: Position{Start: 0, End: 11}},
			},
			Statistics: PIIStatistics{
				ConfidenceAvg: 0.95,
			},
		},
		Classification: &ClassificationResult{
			Level:      SensitivityPublic, // Conflicting with PII
			Confidence: 0.7,
		},
		MLAnalysis: &MLAnalysisResult{
			ConfidenceScore: 0.6,
			BusinessCategories: []BusinessCategory{
				{Category: "general", Confidence: 0.6, Sensitivity: "internal"},
			},
			Entities: &EntityResult{Count: 1},
		},
	}
	
	ctx := context.Background()
	ensembleResult, err := voter.VoteOnAnalysis(ctx, result)
	
	if err != nil {
		t.Fatalf("Consensus voting failed: %v", err)
	}
	
	// Check disagreement analysis
	if !ensembleResult.DisagreementAnalysis.HasDisagreement {
		t.Error("Expected disagreement to be detected")
	}
	
	if len(ensembleResult.DisagreementAnalysis.ConflictingPairs) == 0 {
		t.Error("Expected conflicting pairs to be identified")
	}
}

func TestEnsembleVoter_RankedChoiceVoting(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.VotingStrategy = VotingRankedChoice
	voter := NewEnsembleVoter(config)
	
	result := &AnalysisResult{
		PIIDetection: &PIIDetectionResult{
			HasPII: true,
			Matches: []PIIMatch{
				{Type: "email", Value: "user@corp.com", Position: Position{Start: 0, End: 12}},
			},
			Statistics: PIIStatistics{
				ConfidenceAvg: 0.88,
			},
		},
		Classification: &ClassificationResult{
			Level:      SensitivityInternal,
			Confidence: 0.72,
		},
		MLAnalysis: &MLAnalysisResult{
			ConfidenceScore: 0.65,
			BusinessCategories: []BusinessCategory{
				{Category: "business", Confidence: 0.65, Sensitivity: "internal"},
			},
			Entities: &EntityResult{Count: 2},
		},
	}
	
	ctx := context.Background()
	ensembleResult, err := voter.VoteOnAnalysis(ctx, result)
	
	if err != nil {
		t.Fatalf("Ranked choice voting failed: %v", err)
	}
	
	// Check that elimination rounds were recorded
	if len(ensembleResult.VotingResults.RoundResults) == 0 {
		t.Error("Expected elimination rounds in ranked choice voting")
	}
	
	// Winner should be the highest confidence option after elimination
	if ensembleResult.VotingResults.WinningMargin != 1.0 {
		t.Error("Expected winning margin of 1.0 for ranked choice winner")
	}
}

func TestEnsembleVoter_BayesianVoting(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.VotingStrategy = VotingBayesian
	voter := NewEnsembleVoter(config)
	
	// Add some component performance history
	voter.UpdateComponentPerformance("pii_detection", 0.9)
	voter.UpdateComponentPerformance("classification", 0.85)
	voter.UpdateComponentPerformance("ml_analysis", 0.8)
	
	result := &AnalysisResult{
		PIIDetection: &PIIDetectionResult{
			HasPII: true,
			Matches: []PIIMatch{
				{Type: "credit_card", Value: "4111-1111-1111-1111", Position: Position{Start: 0, End: 19}},
			},
			Statistics: PIIStatistics{
				ConfidenceAvg: 0.92,
			},
		},
		Classification: &ClassificationResult{
			Level:      SensitivityRestricted,
			Confidence: 0.88,
		},
		MLAnalysis: &MLAnalysisResult{
			ConfidenceScore: 0.85,
			BusinessCategories: []BusinessCategory{
				{Category: "finance", Confidence: 0.9, Sensitivity: "restricted"},
			},
			Entities: &EntityResult{Count: 3},
		},
	}
	
	ctx := context.Background()
	ensembleResult, err := voter.VoteOnAnalysis(ctx, result)
	
	if err != nil {
		t.Fatalf("Bayesian voting failed: %v", err)
	}
	
	// Bayesian voting should incorporate component reliability
	if ensembleResult.FinalDecision != "restricted" {
		t.Errorf("Expected final decision 'restricted', got '%s'", ensembleResult.FinalDecision)
	}
}

func TestEnsembleVoter_ConfidenceMetrics(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	voter := NewEnsembleVoter(config)
	
	// Test confidence metrics calculation
	votes := []ComponentVote{
		{Component: "comp1", Confidence: 0.8, Weight: 0.3},
		{Component: "comp2", Confidence: 0.9, Weight: 0.4},
		{Component: "comp3", Confidence: 0.7, Weight: 0.3},
	}
	
	metrics := voter.calculateConfidenceMetrics(votes)
	
	// Check weighted average
	expectedWeighted := (0.8*0.3 + 0.9*0.4 + 0.7*0.3) / (0.3 + 0.4 + 0.3)
	if abs(metrics.WeightedAverage-expectedWeighted) > 0.001 {
		t.Errorf("Expected weighted average %f, got %f", expectedWeighted, metrics.WeightedAverage)
	}
	
	// Check arithmetic mean
	expectedArithmetic := (0.8 + 0.9 + 0.7) / 3.0
	if abs(metrics.ArithmeticMean-expectedArithmetic) > 0.001 {
		t.Errorf("Expected arithmetic mean %f, got %f", expectedArithmetic, metrics.ArithmeticMean)
	}
	
	// Check confidence range
	expectedRange := 0.9 - 0.7
	if abs(metrics.ConfidenceRange-expectedRange) > 0.001 {
		t.Errorf("Expected confidence range %f, got %f", expectedRange, metrics.ConfidenceRange)
	}
	
	// Check median
	expectedMedian := 0.8
	if abs(metrics.MedianConfidence-expectedMedian) > 0.001 {
		t.Errorf("Expected median confidence %f, got %f", expectedMedian, metrics.MedianConfidence)
	}
}

func TestEnsembleVoter_DisagreementAnalysis(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.DisagreementThreshold = 0.3
	voter := NewEnsembleVoter(config)
	
	// Create votes with disagreement
	votes := []ComponentVote{
		{Component: "comp1", Vote: "high", Confidence: 0.8, Weight: 0.4},
		{Component: "comp2", Vote: "low", Confidence: 0.9, Weight: 0.3},
		{Component: "comp3", Vote: "medium", Confidence: 0.7, Weight: 0.3},
	}
	
	analysis := voter.analyzeDisagreements(votes)
	
	if !analysis.HasDisagreement {
		t.Error("Expected disagreement to be detected")
	}
	
	// Should have conflicting pairs
	expectedPairs := 3 // All pairs conflict
	if len(analysis.ConflictingPairs) != expectedPairs {
		t.Errorf("Expected %d conflicting pairs, got %d", expectedPairs, len(analysis.ConflictingPairs))
	}
	
	// Check disagreement level
	expectedLevel := 2.0 / 2.0 // (3 unique votes - 1) / (3 votes - 1)
	if abs(analysis.DisagreementLevel-expectedLevel) > 0.001 {
		t.Errorf("Expected disagreement level %f, got %f", expectedLevel, analysis.DisagreementLevel)
	}
	
	// Should trigger high disagreement strategy
	if analysis.ResolutionStrategy != "high_disagreement_detected" {
		t.Errorf("Expected high disagreement strategy, got %s", analysis.ResolutionStrategy)
	}
}

func TestEnsembleVoter_UncertaintyEstimation(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	voter := NewEnsembleVoter(config)
	
	// Test variance-based uncertainty
	config.UncertaintyMethod = "variance"
	voter.config = config
	
	// High variance votes (high uncertainty)
	highVarianceVotes := []ComponentVote{
		{Component: "comp1", Vote: "high", Confidence: 0.1},
		{Component: "comp2", Vote: "low", Confidence: 0.9},
	}
	
	highUncertainty := voter.calculateUncertainty(highVarianceVotes)
	
	// Low variance votes (low uncertainty)
	lowVarianceVotes := []ComponentVote{
		{Component: "comp1", Vote: "medium", Confidence: 0.8},
		{Component: "comp2", Vote: "medium", Confidence: 0.82},
	}
	
	lowUncertainty := voter.calculateUncertainty(lowVarianceVotes)
	
	if highUncertainty <= lowUncertainty {
		t.Error("Expected high variance to result in higher uncertainty")
	}
	
	// Test entropy-based uncertainty
	config.UncertaintyMethod = "entropy"
	voter.config = config
	
	// All same votes (low entropy)
	sameVotes := []ComponentVote{
		{Component: "comp1", Vote: "high"},
		{Component: "comp2", Vote: "high"},
		{Component: "comp3", Vote: "high"},
	}
	
	lowEntropyUncertainty := voter.calculateUncertainty(sameVotes)
	
	// Mixed votes (high entropy)
	mixedVotes := []ComponentVote{
		{Component: "comp1", Vote: "high"},
		{Component: "comp2", Vote: "medium"},
		{Component: "comp3", Vote: "low"},
	}
	
	highEntropyUncertainty := voter.calculateUncertainty(mixedVotes)
	
	if highEntropyUncertainty <= lowEntropyUncertainty {
		t.Error("Expected mixed votes to result in higher entropy uncertainty")
	}
}

func TestEnsembleVoter_CalibrationHistory(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.EnableCalibration = true
	config.HistoricalSamples = 5
	voter := NewEnsembleVoter(config)
	
	// Add calibration history
	component := "test_component"
	voter.UpdateCalibrationHistory(component, 0.8, 0.75, map[string]interface{}{"context": "test"})
	voter.UpdateCalibrationHistory(component, 0.9, 0.85, map[string]interface{}{"context": "test"})
	voter.UpdateCalibrationHistory(component, 0.7, 0.72, map[string]interface{}{"context": "test"})
	
	// Check history was stored
	if len(voter.calibrationHistory[component]) != 3 {
		t.Errorf("Expected 3 calibration samples, got %d", len(voter.calibrationHistory[component]))
	}
	
	// Test calibration
	calibratedScore := voter.calibrateScore(0.85, voter.calibrationHistory[component])
	
	// Should interpolate between 0.8->0.75 and 0.9->0.85
	// Expected: 0.75 + (0.85-0.8)/(0.9-0.8) * (0.85-0.75) = 0.75 + 0.5 * 0.1 = 0.8
	expectedCalibrated := 0.8
	if abs(calibratedScore-expectedCalibrated) > 0.001 {
		t.Errorf("Expected calibrated score %f, got %f", expectedCalibrated, calibratedScore)
	}
}

func TestEnsembleVoter_ComponentPerformanceTracking(t *testing.T) {
	config := GetDefaultEnsembleConfig()
	config.CalibrationDecayFactor = 0.9
	voter := NewEnsembleVoter(config)
	
	component := "test_component"
	
	// Add performance data
	voter.UpdateComponentPerformance(component, 0.8)
	voter.UpdateComponentPerformance(component, 0.85)
	voter.UpdateComponentPerformance(component, 0.9)
	
	perf := voter.componentPerformance[component]
	
	// Check average accuracy
	expectedAvg := (0.8 + 0.85 + 0.9) / 3.0
	if abs(perf.AverageAccuracy-expectedAvg) > 0.001 {
		t.Errorf("Expected average accuracy %f, got %f", expectedAvg, perf.AverageAccuracy)
	}
	
	// Check reliability score (should weight recent performance more)
	if perf.ReliabilityScore <= perf.AverageAccuracy {
		t.Error("Expected reliability score to weight recent performance higher")
	}
	
	// Check sample count
	if perf.SampleCount != 3 {
		t.Errorf("Expected sample count 3, got %d", perf.SampleCount)
	}
}

func TestEnsembleVoter_ProfileConfiguration(t *testing.T) {
	// Test different ensemble profiles
	profiles := []struct {
		name              string
		strategy          VotingStrategy
		consensusThreshold float64
	}{
		{"conservative", VotingConsensus, 0.8},
		{"performance", VotingWeighted, 0.6},
		{"security_focused", VotingBayesian, 0.9},
	}
	
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			config := GetDefaultEnsembleConfig()
			config.VotingStrategy = profile.strategy
			config.ConsensusThreshold = profile.consensusThreshold
			
			voter := NewEnsembleVoter(config)
			
			if voter.config.VotingStrategy != profile.strategy {
				t.Errorf("Expected voting strategy %s, got %s", profile.strategy, voter.config.VotingStrategy)
			}
			
			if voter.config.ConsensusThreshold != profile.consensusThreshold {
				t.Errorf("Expected consensus threshold %f, got %f", profile.consensusThreshold, voter.config.ConsensusThreshold)
			}
		})
	}
}

// Helper function for floating point comparison
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// Benchmark tests for performance validation
func BenchmarkEnsembleVoter_WeightedVoting(b *testing.B) {
	config := GetDefaultEnsembleConfig()
	voter := NewEnsembleVoter(config)
	
	result := &AnalysisResult{
		PIIDetection: &PIIDetectionResult{
			HasPII: true,
			Matches: []PIIMatch{
				{Type: "email", Value: "test@example.com", Position: Position{Start: 0, End: 16}},
			},
			Statistics: PIIStatistics{ConfidenceAvg: 0.85},
		},
		Classification: &ClassificationResult{
			Level:      SensitivityInternal,
			Confidence: 0.78,
		},
		MLAnalysis: &MLAnalysisResult{
			ConfidenceScore: 0.82,
			BusinessCategories: []BusinessCategory{
				{Category: "general", Confidence: 0.8, Sensitivity: "internal"},
			},
			Entities: &EntityResult{Count: 2},
		},
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := voter.VoteOnAnalysis(ctx, result)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnsembleVoter_AllStrategies(b *testing.B) {
	strategies := []VotingStrategy{
		VotingMajority,
		VotingWeighted,
		VotingRankedChoice,
		VotingConsensus,
		VotingBayesian,
	}
	
	for _, strategy := range strategies {
		b.Run(string(strategy), func(b *testing.B) {
			config := GetDefaultEnsembleConfig()
			config.VotingStrategy = strategy
			voter := NewEnsembleVoter(config)
			
			result := &AnalysisResult{
				PIIDetection: &PIIDetectionResult{
					HasPII: true,
					Matches: []PIIMatch{
						{Type: "email", Value: "test@example.com", Position: Position{Start: 0, End: 16}},
					},
					Statistics: PIIStatistics{ConfidenceAvg: 0.85},
				},
				Classification: &ClassificationResult{
					Level:      SensitivityInternal,
					Confidence: 0.78,
				},
				MLAnalysis: &MLAnalysisResult{
					ConfidenceScore: 0.82,
					BusinessCategories: []BusinessCategory{
						{Category: "general", Confidence: 0.8, Sensitivity: "internal"},
					},
					Entities: &EntityResult{Count: 2},
				},
			}
			
			ctx := context.Background()
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := voter.VoteOnAnalysis(ctx, result)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
} 