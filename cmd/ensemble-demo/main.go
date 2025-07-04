package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ai-gateway-poc/internal/analysis"
)

func main() {
	fmt.Println("🗳️  AI Gateway Task 2.7: Ensemble Voting & Enhanced Confidence Scoring Demo")
	fmt.Println("=" + strings.Repeat("=", 79))
	fmt.Println()

	// Test scenarios
	testCases := []struct {
		name    string
		content string
		description string
	}{
		{
			name:    "High Consensus",
			content: "This is public marketing content about our new product launch.",
			description: "Simple public content - all components should agree",
		},
		{
			name:    "Clear High Risk",
			content: "CONFIDENTIAL: SSN 123-45-6789, Credit Card: 4111-1111-1111-1111",
			description: "Multiple PII with confidential marking - high risk consensus",
		},
		{
			name:    "Disagreement Case",
			content: "Team meeting notes - John's email is john@company.com",
			description: "Mixed signals: internal notes with PII - should show disagreement",
		},
	}

	// Voting strategies to test
	strategies := []struct {
		name     string
		strategy analysis.VotingStrategy
	}{
		{"Majority", analysis.VotingMajority},
		{"Weighted", analysis.VotingWeighted},
		{"Consensus", analysis.VotingConsensus},
		{"Bayesian", analysis.VotingBayesian},
	}

	fmt.Println("📊 ENSEMBLE VOTING STRATEGY COMPARISON")
	fmt.Println(strings.Repeat("-", 50))

	for _, testCase := range testCases {
		fmt.Printf("\n🧪 Test Case: %s\n", testCase.name)
		fmt.Printf("📝 %s\n", testCase.description)
		fmt.Printf("📄 Content: %s\n", testCase.content)
		fmt.Println(strings.Repeat("-", 40))

		// Create mock analysis result
		analysisResult := createMockAnalysisResult(testCase.content)
		
		// Test each strategy
		for _, strategy := range strategies {
			config := analysis.GetDefaultEnsembleConfig()
			config.VotingStrategy = strategy.strategy
			voter := analysis.NewEnsembleVoter(config)
			
			ctx := context.Background()
			result, err := voter.VoteOnAnalysis(ctx, analysisResult)
			if err != nil {
				fmt.Printf("❌ %s: Error - %v\n", strategy.name, err)
				continue
			}
			
			fmt.Printf("🗳️  %s: %s (conf: %.3f, consensus: %.3f)\n",
				strategy.name, result.FinalDecision, result.FinalConfidence, result.ConsensusLevel)
			
			if result.DisagreementAnalysis.HasDisagreement {
				fmt.Printf("   ⚠️  Disagreement: %.3f\n", result.DisagreementAnalysis.DisagreementLevel)
			}
		}
	}

	fmt.Println("\n🔬 DETAILED CONFIDENCE ANALYSIS")
	fmt.Println(strings.Repeat("-", 40))
	
	// Detailed analysis for one case
	complexCase := testCases[2]
	analysisResult := createMockAnalysisResult(complexCase.content)
	
	config := analysis.GetDefaultEnsembleConfig()
	config.EnableUncertainty = true
	voter := analysis.NewEnsembleVoter(config)
	
	result, err := voter.VoteOnAnalysis(context.Background(), analysisResult)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("📊 Analyzing: %s\n\n", complexCase.name)
	
	// Confidence metrics
	m := result.ConfidenceMetrics
	fmt.Println("📈 Confidence Metrics:")
	fmt.Printf("   Weighted Avg: %.4f\n", m.WeightedAverage)
	fmt.Printf("   Arithmetic:   %.4f\n", m.ArithmeticMean)
	fmt.Printf("   Median:       %.4f\n", m.MedianConfidence)
	fmt.Printf("   Std Dev:      %.4f\n", m.StandardDeviation)
	fmt.Printf("   Range:        %.4f\n", m.ConfidenceRange)
	
	// Component votes
	fmt.Println("\n🗳️  Component Votes:")
	for component, vote := range result.ComponentVotes {
		fmt.Printf("   %s: %s (%.3f)\n", 
			strings.Title(strings.ReplaceAll(component, "_", " ")), 
			vote.Vote, vote.Confidence)
	}
	
	// Voting results
	fmt.Println("\n📊 Voting Results:")
	fmt.Printf("   Winner: %s (%.1f%% margin)\n", 
		result.VotingResults.WinningOption, 
		result.VotingResults.WinningMargin*100)
	
	fmt.Printf("   Distribution: ")
	for option, pct := range result.VotingResults.VoteDistribution {
		fmt.Printf("%s: %.1f%% ", option, pct*100)
	}
	fmt.Println()
	
	// Uncertainty
	if result.Uncertainty > 0 {
		fmt.Printf("   Uncertainty: %.4f\n", result.Uncertainty)
	}
	
	// Disagreement analysis
	if result.DisagreementAnalysis.HasDisagreement {
		fmt.Println("\n⚠️  Disagreement Analysis:")
		fmt.Printf("   Level: %.3f\n", result.DisagreementAnalysis.DisagreementLevel)
		fmt.Printf("   Strategy: %s\n", result.DisagreementAnalysis.ResolutionStrategy)
		fmt.Printf("   Conflicts: %d pairs\n", len(result.DisagreementAnalysis.ConflictingPairs))
	}

	fmt.Println("\n🎉 Task 2.7 Implementation Complete!")
	fmt.Println("✅ Ensemble voting with multiple strategies")
	fmt.Println("✅ Enhanced confidence scoring with detailed metrics")
	fmt.Println("✅ Disagreement detection and analysis")
	fmt.Println("✅ Uncertainty estimation")
	fmt.Println("✅ Component vote tracking and rationale")
}

func createMockAnalysisResult(content string) *analysis.AnalysisResult {
	contentLower := strings.ToLower(content)
	
	// PII Detection simulation
	piiMatches := []analysis.PIIMatch{}
	piiConfidence := 0.5
	
	if strings.Contains(contentLower, "ssn") || strings.Contains(content, "123-45-6789") {
		piiMatches = append(piiMatches, analysis.PIIMatch{
			Type: "ssn", Value: "123-45-6789",
		})
		piiConfidence = 0.95
	}
	
	if strings.Contains(contentLower, "credit") {
		piiMatches = append(piiMatches, analysis.PIIMatch{
			Type: "credit_card", Value: "4111-1111-1111-1111",
		})
		piiConfidence = 0.92
	}
	
	if strings.Contains(content, "@") {
		piiMatches = append(piiMatches, analysis.PIIMatch{
			Type: "email", Value: "john@company.com",
		})
		piiConfidence = max(piiConfidence, 0.85)
	}
	
	// Classification simulation  
	var classLevel analysis.SensitivityLevel
	classConfidence := 0.7
	
	if strings.Contains(contentLower, "confidential") {
		classLevel = analysis.SensitivityConfidential
		classConfidence = 0.90
	} else if strings.Contains(contentLower, "team") || strings.Contains(contentLower, "meeting") {
		classLevel = analysis.SensitivityInternal
		classConfidence = 0.75
	} else if strings.Contains(contentLower, "public") || strings.Contains(contentLower, "marketing") {
		classLevel = analysis.SensitivityPublic
		classConfidence = 0.85
	} else {
		classLevel = analysis.SensitivityInternal
		classConfidence = 0.65
	}
	
	// ML Analysis simulation
	mlConfidence := 0.75
	categories := []analysis.BusinessCategory{
		{Category: "general", Confidence: 0.7, Sensitivity: "internal"},
	}
	
	if strings.Contains(contentLower, "confidential") {
		categories = []analysis.BusinessCategory{
			{Category: "security", Confidence: 0.9, Sensitivity: "confidential"},
		}
		mlConfidence = 0.88
	} else if strings.Contains(contentLower, "marketing") {
		categories = []analysis.BusinessCategory{
			{Category: "marketing", Confidence: 0.8, Sensitivity: "public"},
		}
		mlConfidence = 0.82
	}
	
	return &analysis.AnalysisResult{
		PIIDetection: &analysis.PIIDetectionResult{
			HasPII:  len(piiMatches) > 0,
			Matches: piiMatches,
			Statistics: analysis.PIIStatistics{
				ConfidenceAvg: piiConfidence,
			},
		},
		Classification: &analysis.ClassificationResult{
			Level:      classLevel,
			Confidence: classConfidence,
		},
		MLAnalysis: &analysis.MLAnalysisResult{
			ConfidenceScore:    mlConfidence,
			BusinessCategories: categories,
			Entities: &analysis.EntityResult{Count: len(piiMatches) + 1},
		},
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
} 