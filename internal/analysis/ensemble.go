package analysis

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"
)

// EnsembleVotingConfig configures the ensemble voting system
type EnsembleVotingConfig struct {
	// Voting strategies
	VotingStrategy          VotingStrategy `mapstructure:"voting_strategy"`
	WeightedVoting          bool           `mapstructure:"weighted_voting"`
	ConsensusThreshold      float64        `mapstructure:"consensus_threshold"`
	DisagreementThreshold   float64        `mapstructure:"disagreement_threshold"`
	
	// Confidence calibration
	EnableCalibration       bool           `mapstructure:"enable_calibration"`
	HistoricalSamples       int            `mapstructure:"historical_samples"`
	CalibrationDecayFactor  float64        `mapstructure:"calibration_decay_factor"`
	
	// Component weights for ensemble
	ComponentWeights        map[string]float64 `mapstructure:"component_weights"`
	DynamicWeighting        bool               `mapstructure:"dynamic_weighting"`
	
	// Uncertainty estimation
	EnableUncertainty       bool    `mapstructure:"enable_uncertainty"`
	UncertaintyMethod       string  `mapstructure:"uncertainty_method"` // "variance", "entropy", "bootstrap"
	
	// Decision thresholds
	MinConfidenceThreshold  float64 `mapstructure:"min_confidence_threshold"`
	HighConfidenceThreshold float64 `mapstructure:"high_confidence_threshold"`
}

// VotingStrategy defines different ensemble voting methods
type VotingStrategy string

const (
	VotingMajority        VotingStrategy = "majority"
	VotingWeighted        VotingStrategy = "weighted"
	VotingRankedChoice    VotingStrategy = "ranked_choice"
	VotingConsensus       VotingStrategy = "consensus"
	VotingBayesian        VotingStrategy = "bayesian"
)

// EnsembleResult contains the ensemble voting results
type EnsembleResult struct {
	// Overall decision
	FinalDecision       string                 `json:"final_decision"`
	FinalConfidence     float64                `json:"final_confidence"`
	FinalRiskLevel      string                 `json:"final_risk_level"`
	
	// Confidence analysis
	ConfidenceMetrics   ConfidenceMetrics      `json:"confidence_metrics"`
	CalibrationScore    float64                `json:"calibration_score"`
	Uncertainty         float64                `json:"uncertainty"`
	
	// Voting details
	VotingResults       VotingResults          `json:"voting_results"`
	ComponentVotes      map[string]ComponentVote `json:"component_votes"`
	
	// Agreement analysis
	ConsensusLevel      float64                `json:"consensus_level"`
	DisagreementAnalysis DisagreementAnalysis  `json:"disagreement_analysis"`
	
	// Performance metrics
	ProcessingTimeMs    int64                  `json:"processing_time_ms"`
	VotingStrategy      VotingStrategy         `json:"voting_strategy"`
}

// ConfidenceMetrics contains detailed confidence analysis
type ConfidenceMetrics struct {
	WeightedAverage     float64   `json:"weighted_average"`
	ArithmeticMean      float64   `json:"arithmetic_mean"`
	GeometricMean       float64   `json:"geometric_mean"`
	HarmonicMean        float64   `json:"harmonic_mean"`
	MedianConfidence    float64   `json:"median_confidence"`
	ConfidenceVariance  float64   `json:"confidence_variance"`
	ConfidenceRange     float64   `json:"confidence_range"`
	StandardDeviation   float64   `json:"standard_deviation"`
}

// VotingResults contains detailed voting information
type VotingResults struct {
	TotalVotes          int                    `json:"total_votes"`
	ValidVotes          int                    `json:"valid_votes"`
	WinningOption       string                 `json:"winning_option"`
	WinningMargin       float64                `json:"winning_margin"`
	VoteDistribution    map[string]float64     `json:"vote_distribution"`
	RoundResults        []VotingRound          `json:"round_results,omitempty"`
}

// VotingRound represents one round of voting (for ranked choice)
type VotingRound struct {
	Round               int                    `json:"round"`
	Candidates          map[string]float64     `json:"candidates"`
	EliminatedCandidate string                 `json:"eliminated_candidate,omitempty"`
}

// ComponentVote represents one component's vote
type ComponentVote struct {
	Component           string                 `json:"component"`
	Vote                string                 `json:"vote"`
	Confidence          float64                `json:"confidence"`
	Weight              float64                `json:"weight"`
	CalibratedConfidence float64              `json:"calibrated_confidence"`
	Rationale           string                 `json:"rationale"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// DisagreementAnalysis analyzes disagreements between components
type DisagreementAnalysis struct {
	HasDisagreement     bool                   `json:"has_disagreement"`
	DisagreementLevel   float64                `json:"disagreement_level"`
	ConflictingPairs    []ComponentPair        `json:"conflicting_pairs"`
	MainConflicts       []string               `json:"main_conflicts"`
	ResolutionStrategy  string                 `json:"resolution_strategy"`
}

// ComponentPair represents a pair of conflicting components
type ComponentPair struct {
	Component1          string                 `json:"component1"`
	Component2          string                 `json:"component2"`
	ConflictSeverity    float64                `json:"conflict_severity"`
	ConflictType        string                 `json:"conflict_type"`
}

// EnsembleVoter implements the ensemble voting system
type EnsembleVoter struct {
	config              EnsembleVotingConfig
	calibrationHistory  map[string][]CalibrationSample
	componentPerformance map[string]ComponentPerformance
}

// CalibrationSample stores historical accuracy data for calibration
type CalibrationSample struct {
	PredictedConfidence float64
	ActualAccuracy      float64
	Timestamp          time.Time
	ContextMetadata    map[string]interface{}
}

// ComponentPerformance tracks component reliability over time
type ComponentPerformance struct {
	AccuracyHistory     []float64
	AverageAccuracy     float64
	ReliabilityScore    float64
	LastUpdated         time.Time
	SampleCount         int64
}

// NewEnsembleVoter creates a new ensemble voting system
func NewEnsembleVoter(config EnsembleVotingConfig) *EnsembleVoter {
	if config.ComponentWeights == nil {
		config.ComponentWeights = map[string]float64{
			"pii_detection":   0.30,
			"classification":  0.30,
			"ml_analysis":     0.25,
			"file_scanning":   0.15,
		}
	}
	
	return &EnsembleVoter{
		config:              config,
		calibrationHistory:  make(map[string][]CalibrationSample),
		componentPerformance: make(map[string]ComponentPerformance),
	}
}

// VoteOnAnalysis performs ensemble voting on analysis results
func (ev *EnsembleVoter) VoteOnAnalysis(ctx context.Context, result *AnalysisResult) (*EnsembleResult, error) {
	start := time.Now()
	
	ensembleResult := &EnsembleResult{
		ComponentVotes:    make(map[string]ComponentVote),
		ProcessingTimeMs:  0,
		VotingStrategy:    ev.config.VotingStrategy,
	}
	
	// Extract component votes
	componentVotes := ev.extractComponentVotes(result)
	
	// Apply calibration if enabled
	if ev.config.EnableCalibration {
		ev.calibrateConfidences(componentVotes)
	}
	
	// Calculate confidence metrics
	ensembleResult.ConfidenceMetrics = ev.calculateConfidenceMetrics(componentVotes)
	
	// Perform voting based on strategy
	votingResults, err := ev.performVoting(componentVotes)
	if err != nil {
		return nil, fmt.Errorf("voting failed: %w", err)
	}
	ensembleResult.VotingResults = *votingResults
	
	// Analyze disagreements
	ensembleResult.DisagreementAnalysis = ev.analyzeDisagreements(componentVotes)
	
	// Calculate consensus level
	ensembleResult.ConsensusLevel = ev.calculateConsensusLevel(componentVotes)
	
	// Calculate uncertainty if enabled
	if ev.config.EnableUncertainty {
		ensembleResult.Uncertainty = ev.calculateUncertainty(componentVotes)
	}
	
	// Make final decision
	ev.makeFinalDecision(ensembleResult, componentVotes)
	
	// Store component votes in result
	for _, vote := range componentVotes {
		ensembleResult.ComponentVotes[vote.Component] = vote
	}
	
	ensembleResult.ProcessingTimeMs = time.Since(start).Milliseconds()
	
	return ensembleResult, nil
}

// extractComponentVotes converts analysis results to component votes
func (ev *EnsembleVoter) extractComponentVotes(result *AnalysisResult) []ComponentVote {
	var votes []ComponentVote
	
	// PII Detection vote
	if result.PIIDetection != nil {
		riskLevel := "low"
		if len(result.PIIDetection.Matches) > 0 {
			riskLevel = "medium"
			if len(result.PIIDetection.Matches) >= 3 {
				riskLevel = "high"
			}
		}
		
		votes = append(votes, ComponentVote{
			Component:  "pii_detection",
			Vote:       riskLevel,
			Confidence: result.PIIDetection.Statistics.ConfidenceAvg,
			Weight:     ev.config.ComponentWeights["pii_detection"],
			Rationale:  fmt.Sprintf("Found %d PII items", len(result.PIIDetection.Matches)),
			Metadata: map[string]interface{}{
				"pii_count": len(result.PIIDetection.Matches),
				"pii_types": len(result.PIIDetection.Statistics.MatchesByType),
			},
		})
	}
	
	// Classification vote
	if result.Classification != nil {
		votes = append(votes, ComponentVote{
			Component:  "classification",
			Vote:       string(result.Classification.Level),
			Confidence: result.Classification.Confidence,
			Weight:     ev.config.ComponentWeights["classification"],
			Rationale:  fmt.Sprintf("Classified as %s", result.Classification.Level),
			Metadata: map[string]interface{}{
				"rules_matched": len(result.Classification.MatchedRules),
				"patterns_found": len(result.Classification.MatchedPatterns),
			},
		})
	}
	
	// ML Analysis vote
	if result.MLAnalysis != nil {
		riskLevel := "low"
		for _, category := range result.MLAnalysis.BusinessCategories {
			if category.Sensitivity == "restricted" {
				riskLevel = "restricted"
				break
			} else if category.Sensitivity == "confidential" && riskLevel != "restricted" {
				riskLevel = "confidential"
			}
		}
		
		votes = append(votes, ComponentVote{
			Component:  "ml_analysis",
			Vote:       riskLevel,
			Confidence: result.MLAnalysis.ConfidenceScore,
			Weight:     ev.config.ComponentWeights["ml_analysis"],
			Rationale:  fmt.Sprintf("ML analysis suggests %s sensitivity", riskLevel),
			Metadata: map[string]interface{}{
				"business_categories": len(result.MLAnalysis.BusinessCategories),
				"entities_found":     result.MLAnalysis.Entities.Count,
			},
		})
	}
	
	// File Scanning vote
	if result.FileScanning != nil {
		votes = append(votes, ComponentVote{
			Component:  "file_scanning",
			Vote:       result.FileScanning.SecurityAssessment.RiskLevel,
			Confidence: result.FileScanning.ConfidenceScore,
			Weight:     ev.config.ComponentWeights["file_scanning"],
			Rationale:  "File security assessment",
			Metadata:   map[string]interface{}{},
		})
	}
	
	return votes
}

// performVoting executes the voting strategy
func (ev *EnsembleVoter) performVoting(votes []ComponentVote) (*VotingResults, error) {
	switch ev.config.VotingStrategy {
	case VotingMajority:
		return ev.majorityVoting(votes)
	case VotingWeighted:
		return ev.weightedVoting(votes)
	case VotingRankedChoice:
		return ev.rankedChoiceVoting(votes)
	case VotingConsensus:
		return ev.consensusVoting(votes)
	case VotingBayesian:
		return ev.bayesianVoting(votes)
	default:
		return ev.weightedVoting(votes) // Default to weighted voting
	}
}

// majorityVoting implements simple majority voting
func (ev *EnsembleVoter) majorityVoting(votes []ComponentVote) (*VotingResults, error) {
	voteCount := make(map[string]int)
	
	for _, vote := range votes {
		voteCount[vote.Vote]++
	}
	
	var winner string
	maxVotes := 0
	for option, count := range voteCount {
		if count > maxVotes {
			maxVotes = count
			winner = option
		}
	}
	
	distribution := make(map[string]float64)
	for option, count := range voteCount {
		distribution[option] = float64(count) / float64(len(votes))
	}
	
	margin := 0.0
	if len(votes) > 0 {
		margin = float64(maxVotes) / float64(len(votes))
	}
	
	return &VotingResults{
		TotalVotes:       len(votes),
		ValidVotes:       len(votes),
		WinningOption:    winner,
		WinningMargin:    margin,
		VoteDistribution: distribution,
	}, nil
}

// weightedVoting implements confidence-weighted voting
func (ev *EnsembleVoter) weightedVoting(votes []ComponentVote) (*VotingResults, error) {
	weightedVotes := make(map[string]float64)
	totalWeight := 0.0
	
	for _, vote := range votes {
		weight := vote.Weight * vote.Confidence
		weightedVotes[vote.Vote] += weight
		totalWeight += weight
	}
	
	var winner string
	maxWeight := 0.0
	for option, weight := range weightedVotes {
		if weight > maxWeight {
			maxWeight = weight
			winner = option
		}
	}
	
	distribution := make(map[string]float64)
	if totalWeight > 0 {
		for option, weight := range weightedVotes {
			distribution[option] = weight / totalWeight
		}
	}
	
	margin := 0.0
	if totalWeight > 0 {
		margin = maxWeight / totalWeight
	}
	
	return &VotingResults{
		TotalVotes:       len(votes),
		ValidVotes:       len(votes),
		WinningOption:    winner,
		WinningMargin:    margin,
		VoteDistribution: distribution,
	}, nil
}

// rankedChoiceVoting implements ranked choice voting with elimination rounds
func (ev *EnsembleVoter) rankedChoiceVoting(votes []ComponentVote) (*VotingResults, error) {
	// For simplicity, we'll rank by confidence and eliminate lowest confidence options
	candidates := make(map[string]float64)
	
	for _, vote := range votes {
		if existing, exists := candidates[vote.Vote]; !exists || vote.Confidence > existing {
			candidates[vote.Vote] = vote.Confidence
		}
	}
	
	var rounds []VotingRound
	roundNum := 1
	
	for len(candidates) > 1 {
		round := VotingRound{
			Round:      roundNum,
			Candidates: make(map[string]float64),
		}
		
		// Copy current candidates
		for option, score := range candidates {
			round.Candidates[option] = score
		}
		
		// Find minimum confidence candidate to eliminate
		minScore := math.Inf(1)
		var toEliminate string
		for option, score := range candidates {
			if score < minScore {
				minScore = score
				toEliminate = option
			}
		}
		
		if toEliminate != "" {
			round.EliminatedCandidate = toEliminate
			delete(candidates, toEliminate)
		}
		
		rounds = append(rounds, round)
		roundNum++
	}
	
	var winner string
	for option := range candidates {
		winner = option
		break
	}
	
	distribution := make(map[string]float64)
	if len(votes) > 0 {
		voteCount := make(map[string]int)
		for _, vote := range votes {
			voteCount[vote.Vote]++
		}
		
		for option, count := range voteCount {
			distribution[option] = float64(count) / float64(len(votes))
		}
	}
	
	return &VotingResults{
		TotalVotes:       len(votes),
		ValidVotes:       len(votes),
		WinningOption:    winner,
		WinningMargin:    1.0, // Winner of ranked choice
		VoteDistribution: distribution,
		RoundResults:     rounds,
	}, nil
}

// consensusVoting requires agreement above threshold
func (ev *EnsembleVoter) consensusVoting(votes []ComponentVote) (*VotingResults, error) {
	// First try weighted voting
	weighted, err := ev.weightedVoting(votes)
	if err != nil {
		return nil, err
	}
	
	// Check if consensus threshold is met
	if weighted.WinningMargin >= ev.config.ConsensusThreshold {
		weighted.WinningOption = weighted.WinningOption
	} else {
		// No consensus reached - fall back to "uncertain"
		weighted.WinningOption = "uncertain"
		weighted.WinningMargin = 0.0
	}
	
	return weighted, nil
}

// bayesianVoting implements Bayesian model averaging
func (ev *EnsembleVoter) bayesianVoting(votes []ComponentVote) (*VotingResults, error) {
	// Simplified Bayesian approach using component reliability as priors
	posteriors := make(map[string]float64)
	
	for _, vote := range votes {
		// Get component performance (reliability as prior)
		performance := ev.componentPerformance[vote.Component]
		prior := performance.ReliabilityScore
		if prior == 0 {
			prior = 0.5 // Neutral prior
		}
		
		// Calculate likelihood (confidence weighted by component weight)
		likelihood := vote.Confidence * vote.Weight
		
		// Simple Bayesian update: posterior ∝ likelihood × prior
		posterior := likelihood * prior
		posteriors[vote.Vote] += posterior
	}
	
	// Normalize posteriors
	totalPosterior := 0.0
	for _, posterior := range posteriors {
		totalPosterior += posterior
	}
	
	distribution := make(map[string]float64)
	var winner string
	maxPosterior := 0.0
	
	if totalPosterior > 0 {
		for option, posterior := range posteriors {
			normalized := posterior / totalPosterior
			distribution[option] = normalized
			
			if normalized > maxPosterior {
				maxPosterior = normalized
				winner = option
			}
		}
	}
	
	return &VotingResults{
		TotalVotes:       len(votes),
		ValidVotes:       len(votes),
		WinningOption:    winner,
		WinningMargin:    maxPosterior,
		VoteDistribution: distribution,
	}, nil
}

// calculateConfidenceMetrics computes comprehensive confidence statistics
func (ev *EnsembleVoter) calculateConfidenceMetrics(votes []ComponentVote) ConfidenceMetrics {
	if len(votes) == 0 {
		return ConfidenceMetrics{}
	}
	
	var confidences []float64
	var weightedSum, totalWeight float64
	
	for _, vote := range votes {
		confidences = append(confidences, vote.Confidence)
		weightedSum += vote.Confidence * vote.Weight
		totalWeight += vote.Weight
	}
	
	sort.Float64s(confidences)
	
	// Calculate various means
	arithmeticMean := ev.arithmeticMean(confidences)
	geometricMean := ev.geometricMean(confidences)
	harmonicMean := ev.harmonicMean(confidences)
	median := ev.median(confidences)
	variance := ev.variance(confidences, arithmeticMean)
	
	weightedAverage := 0.0
	if totalWeight > 0 {
		weightedAverage = weightedSum / totalWeight
	}
	
	confidenceRange := confidences[len(confidences)-1] - confidences[0]
	
	return ConfidenceMetrics{
		WeightedAverage:   weightedAverage,
		ArithmeticMean:    arithmeticMean,
		GeometricMean:     geometricMean,
		HarmonicMean:      harmonicMean,
		MedianConfidence:  median,
		ConfidenceVariance: variance,
		ConfidenceRange:   confidenceRange,
		StandardDeviation: math.Sqrt(variance),
	}
}

// analyzeDisagreements identifies conflicts between components
func (ev *EnsembleVoter) analyzeDisagreements(votes []ComponentVote) DisagreementAnalysis {
	analysis := DisagreementAnalysis{
		ConflictingPairs: []ComponentPair{},
		MainConflicts:    []string{},
	}
	
	// Find conflicting pairs
	for i, vote1 := range votes {
		for j, vote2 := range votes {
			if i >= j {
				continue
			}
			
			if vote1.Vote != vote2.Vote {
				// Calculate conflict severity based on confidence difference
				confidenceDiff := math.Abs(vote1.Confidence - vote2.Confidence)
				severity := confidenceDiff * math.Min(vote1.Weight, vote2.Weight)
				
				analysis.ConflictingPairs = append(analysis.ConflictingPairs, ComponentPair{
					Component1:       vote1.Component,
					Component2:       vote2.Component,
					ConflictSeverity: severity,
					ConflictType:     fmt.Sprintf("%s vs %s", vote1.Vote, vote2.Vote),
				})
			}
		}
	}
	
	// Calculate disagreement level
	if len(votes) > 1 {
		uniqueVotes := make(map[string]bool)
		for _, vote := range votes {
			uniqueVotes[vote.Vote] = true
		}
		
		analysis.DisagreementLevel = float64(len(uniqueVotes)-1) / float64(len(votes)-1)
		analysis.HasDisagreement = len(uniqueVotes) > 1
		
		if analysis.DisagreementLevel >= ev.config.DisagreementThreshold {
			analysis.ResolutionStrategy = "high_disagreement_detected"
		} else {
			analysis.ResolutionStrategy = "normal_consensus"
		}
	}
	
	return analysis
}

// calculateConsensusLevel measures agreement between components
func (ev *EnsembleVoter) calculateConsensusLevel(votes []ComponentVote) float64 {
	if len(votes) <= 1 {
		return 1.0
	}
	
	// Calculate consensus using both vote agreement and confidence similarity
	voteAgreement := ev.calculateVoteAgreement(votes)
	confidenceAgreement := ev.calculateConfidenceAgreement(votes)
	
	// Weighted combination
	return 0.7*voteAgreement + 0.3*confidenceAgreement
}

// calculateVoteAgreement measures how much votes agree
func (ev *EnsembleVoter) calculateVoteAgreement(votes []ComponentVote) float64 {
	voteCount := make(map[string]int)
	for _, vote := range votes {
		voteCount[vote.Vote]++
	}
	
	maxCount := 0
	for _, count := range voteCount {
		if count > maxCount {
			maxCount = count
		}
	}
	
	return float64(maxCount) / float64(len(votes))
}

// calculateConfidenceAgreement measures confidence similarity
func (ev *EnsembleVoter) calculateConfidenceAgreement(votes []ComponentVote) float64 {
	if len(votes) <= 1 {
		return 1.0
	}
	
	var confidences []float64
	for _, vote := range votes {
		confidences = append(confidences, vote.Confidence)
	}
	
	mean := ev.arithmeticMean(confidences)
	variance := ev.variance(confidences, mean)
	
	// Convert variance to agreement (lower variance = higher agreement)
	// Use exponential decay to map variance [0, ∞) to agreement [1, 0)
	agreement := math.Exp(-variance * 10) // Scaling factor of 10
	
	return agreement
}

// calculateUncertainty estimates uncertainty in the ensemble decision
func (ev *EnsembleVoter) calculateUncertainty(votes []ComponentVote) float64 {
	switch ev.config.UncertaintyMethod {
	case "variance":
		return ev.uncertaintyFromVariance(votes)
	case "entropy":
		return ev.uncertaintyFromEntropy(votes)
	case "bootstrap":
		return ev.uncertaintyFromBootstrap(votes)
	default:
		return ev.uncertaintyFromVariance(votes)
	}
}

// uncertaintyFromVariance calculates uncertainty from confidence variance
func (ev *EnsembleVoter) uncertaintyFromVariance(votes []ComponentVote) float64 {
	var confidences []float64
	for _, vote := range votes {
		confidences = append(confidences, vote.Confidence)
	}
	
	if len(confidences) == 0 {
		return 1.0 // Maximum uncertainty
	}
	
	mean := ev.arithmeticMean(confidences)
	variance := ev.variance(confidences, mean)
	
	// Normalize variance to [0, 1] range
	// Maximum variance occurs when half votes are 0, half are 1
	maxVariance := 0.25
	normalizedVariance := math.Min(variance/maxVariance, 1.0)
	
	return normalizedVariance
}

// uncertaintyFromEntropy calculates uncertainty using Shannon entropy
func (ev *EnsembleVoter) uncertaintyFromEntropy(votes []ComponentVote) float64 {
	voteCount := make(map[string]int)
	for _, vote := range votes {
		voteCount[vote.Vote]++
	}
	
	total := len(votes)
	if total == 0 {
		return 1.0
	}
	
	entropy := 0.0
	for _, count := range voteCount {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	
	// Normalize by maximum possible entropy
	maxEntropy := math.Log2(float64(len(voteCount)))
	if maxEntropy > 0 {
		return entropy / maxEntropy
	}
	
	return 0.0
}

// uncertaintyFromBootstrap uses bootstrap sampling for uncertainty estimation
func (ev *EnsembleVoter) uncertaintyFromBootstrap(votes []ComponentVote) float64 {
	if len(votes) < 2 {
		return 0.0
	}
	
	bootstrapSamples := 100
	var results []string
	
	// Bootstrap sampling
	for i := 0; i < bootstrapSamples; i++ {
		sample := ev.bootstrapSample(votes)
		voting, _ := ev.weightedVoting(sample)
		if voting != nil {
			results = append(results, voting.WinningOption)
		}
	}
	
	// Calculate uncertainty from result diversity
	resultCount := make(map[string]int)
	for _, result := range results {
		resultCount[result]++
	}
	
	if len(results) == 0 {
		return 1.0
	}
	
	// Use entropy of bootstrap results as uncertainty measure
	entropy := 0.0
	for _, count := range resultCount {
		p := float64(count) / float64(len(results))
		entropy -= p * math.Log2(p)
	}
	
	maxEntropy := math.Log2(float64(len(resultCount)))
	if maxEntropy > 0 {
		return entropy / maxEntropy
	}
	
	return 0.0
}

// bootstrapSample creates a bootstrap sample from votes
func (ev *EnsembleVoter) bootstrapSample(votes []ComponentVote) []ComponentVote {
	sample := make([]ComponentVote, len(votes))
	for i := range sample {
		// Sample with replacement
		idx := rand.Intn(len(votes))
		sample[i] = votes[idx]
	}
	return sample
}

// makeFinalDecision determines the final ensemble decision
func (ev *EnsembleVoter) makeFinalDecision(result *EnsembleResult, votes []ComponentVote) {
	result.FinalDecision = result.VotingResults.WinningOption
	result.FinalConfidence = result.ConfidenceMetrics.WeightedAverage
	
	// Map decision to risk level
	riskMapping := map[string]string{
		"public":       "low",
		"internal":     "medium", 
		"confidential": "high",
		"restricted":   "critical",
		"low":          "low",
		"medium":       "medium",
		"high":         "high",
		"critical":     "critical",
	}
	
	if mappedRisk, exists := riskMapping[result.FinalDecision]; exists {
		result.FinalRiskLevel = mappedRisk
	} else {
		result.FinalRiskLevel = result.FinalDecision
	}
	
	// Apply confidence threshold checks
	if result.FinalConfidence < ev.config.MinConfidenceThreshold {
		result.FinalDecision = "uncertain"
		result.FinalRiskLevel = "unknown"
	}
}

// calibrateConfidences applies historical calibration to confidence scores
func (ev *EnsembleVoter) calibrateConfidences(votes []ComponentVote) {
	for i := range votes {
		if calibrationData, exists := ev.calibrationHistory[votes[i].Component]; exists && len(calibrationData) > 0 {
			votes[i].CalibratedConfidence = ev.calibrateScore(votes[i].Confidence, calibrationData)
		} else {
			votes[i].CalibratedConfidence = votes[i].Confidence
		}
	}
}

// calibrateScore calibrates a confidence score based on historical data
func (ev *EnsembleVoter) calibrateScore(score float64, history []CalibrationSample) float64 {
	// Simple isotonic regression approach
	// Find closest historical predictions and interpolate
	
	if len(history) == 0 {
		return score
	}
	
	// Sort by predicted confidence
	sort.Slice(history, func(i, j int) bool {
		return history[i].PredictedConfidence < history[j].PredictedConfidence
	})
	
	// Find interpolation points
	for i := 0; i < len(history)-1; i++ {
		if score >= history[i].PredictedConfidence && score <= history[i+1].PredictedConfidence {
			// Linear interpolation
			t := (score - history[i].PredictedConfidence) / (history[i+1].PredictedConfidence - history[i].PredictedConfidence)
			return history[i].ActualAccuracy + t*(history[i+1].ActualAccuracy-history[i].ActualAccuracy)
		}
	}
	
	// Extrapolation cases
	if score < history[0].PredictedConfidence {
		return history[0].ActualAccuracy
	}
	if score > history[len(history)-1].PredictedConfidence {
		return history[len(history)-1].ActualAccuracy
	}
	
	return score // Fallback
}

// Mathematical helper functions

func (ev *EnsembleVoter) arithmeticMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (ev *EnsembleVoter) geometricMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	product := 1.0
	for _, v := range values {
		if v <= 0 {
			return 0 // Geometric mean undefined for non-positive values
		}
		product *= v
	}
	return math.Pow(product, 1.0/float64(len(values)))
}

func (ev *EnsembleVoter) harmonicMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		if v <= 0 {
			return 0 // Harmonic mean undefined for non-positive values
		}
		sum += 1.0 / v
	}
	return float64(len(values)) / sum
}

func (ev *EnsembleVoter) median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	n := len(values)
	if n%2 == 0 {
		return (values[n/2-1] + values[n/2]) / 2
	}
	return values[n/2]
}

func (ev *EnsembleVoter) variance(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	sum := 0.0
	for _, v := range values {
		diff := v - mean
		sum += diff * diff
	}
	return sum / float64(len(values))
}

// UpdateCalibrationHistory adds a new calibration sample
func (ev *EnsembleVoter) UpdateCalibrationHistory(component string, predictedConfidence, actualAccuracy float64, metadata map[string]interface{}) {
	sample := CalibrationSample{
		PredictedConfidence: predictedConfidence,
		ActualAccuracy:      actualAccuracy,
		Timestamp:          time.Now(),
		ContextMetadata:    metadata,
	}
	
	ev.calibrationHistory[component] = append(ev.calibrationHistory[component], sample)
	
	// Limit history size
	if len(ev.calibrationHistory[component]) > ev.config.HistoricalSamples {
		ev.calibrationHistory[component] = ev.calibrationHistory[component][1:]
	}
}

// UpdateComponentPerformance updates component reliability tracking
func (ev *EnsembleVoter) UpdateComponentPerformance(component string, accuracy float64) {
	perf := ev.componentPerformance[component]
	
	perf.AccuracyHistory = append(perf.AccuracyHistory, accuracy)
	perf.SampleCount++
	perf.LastUpdated = time.Now()
	
	// Calculate average accuracy
	sum := 0.0
	for _, acc := range perf.AccuracyHistory {
		sum += acc
	}
	perf.AverageAccuracy = sum / float64(len(perf.AccuracyHistory))
	
	// Calculate reliability score (weighted recent performance more)
	weightedSum := 0.0
	totalWeight := 0.0
	decayFactor := ev.config.CalibrationDecayFactor
	
	for i, acc := range perf.AccuracyHistory {
		weight := math.Pow(decayFactor, float64(len(perf.AccuracyHistory)-1-i))
		weightedSum += acc * weight
		totalWeight += weight
	}
	
	if totalWeight > 0 {
		perf.ReliabilityScore = weightedSum / totalWeight
	} else {
		perf.ReliabilityScore = perf.AverageAccuracy
	}
	
	// Limit history size
	if len(perf.AccuracyHistory) > ev.config.HistoricalSamples {
		perf.AccuracyHistory = perf.AccuracyHistory[1:]
	}
	
	ev.componentPerformance[component] = perf
}

// GetDefaultEnsembleConfig returns default ensemble voting configuration
func GetDefaultEnsembleConfig() EnsembleVotingConfig {
	return EnsembleVotingConfig{
		VotingStrategy:         VotingWeighted,
		WeightedVoting:         true,
		ConsensusThreshold:     0.7,
		DisagreementThreshold:  0.5,
		EnableCalibration:      true,
		HistoricalSamples:      100,
		CalibrationDecayFactor: 0.95,
		ComponentWeights: map[string]float64{
			"pii_detection":  0.30,
			"classification": 0.30,
			"ml_analysis":    0.25,
			"file_scanning":  0.15,
		},
		DynamicWeighting:        false,
		EnableUncertainty:       true,
		UncertaintyMethod:       "variance",
		MinConfidenceThreshold:  0.3,
		HighConfidenceThreshold: 0.8,
	}
} 