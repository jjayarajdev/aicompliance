package policy

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// resolveMostRestrictive implements the most restrictive action strategy
func (cr *ConflictResolver) resolveMostRestrictive(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	// Sort actions by restrictiveness based on configuration
	actionPriorities := config.ActionPriorities
	if len(actionPriorities) == 0 {
		actionPriorities = getDefaultActionPriorities()
	}
	
	// Find the most restrictive action
	var selectedMatch *PolicyMatch
	highestRestriction := -1
	
	for _, match := range matches {
		restriction := getActionRestrictionLevel(match.Action.Type, actionPriorities)
		if restriction > highestRestriction {
			highestRestriction = restriction
			selectedMatch = &match
		}
	}
	
	if selectedMatch == nil {
		selectedMatch = &matches[0] // Fallback
	}
	
	// Calculate confidence based on consensus
	confidence := calculateConsensusConfidence(matches, selectedMatch.Action.Type)
	
	decision := &PolicyDecision{
		Action:     selectedMatch.Action.Type,
		Reason:     fmt.Sprintf("Most restrictive action selected from %d policies", len(matches)),
		Confidence: confidence,
		Severity:   selectedMatch.Action.Severity,
		Message:    selectedMatch.Action.Message,
		Parameters: selectedMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveHighestPriority implements priority-based resolution
func (cr *ConflictResolver) resolveHighestPriority(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	// Sort by priority (highest first)
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Priority != matches[j].Priority {
			return matches[i].Priority > matches[j].Priority
		}
		// If same priority, use confidence as tiebreaker
		return matches[i].Confidence > matches[j].Confidence
	})
	
	selectedMatch := matches[0]
	
	// Check for ties at the highest priority
	var tiedMatches []PolicyMatch
	for _, match := range matches {
		if match.Priority == selectedMatch.Priority {
			tiedMatches = append(tiedMatches, match)
		}
	}
	
	// If there are ties, resolve them using most restrictive
	if len(tiedMatches) > 1 {
		return cr.resolveMostRestrictive(tiedMatches, request, config)
	}
	
	confidence := selectedMatch.Confidence
	if len(matches) > 1 {
		confidence = math.Min(confidence, 0.9) // Reduce confidence for conflicts
	}
	
	decision := &PolicyDecision{
		Action:     selectedMatch.Action.Type,
		Reason:     fmt.Sprintf("Highest priority policy (%d) selected", selectedMatch.Priority),
		Confidence: confidence,
		Severity:   selectedMatch.Action.Severity,
		Message:    selectedMatch.Action.Message,
		Parameters: selectedMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveFirstMatch implements first-match strategy
func (cr *ConflictResolver) resolveFirstMatch(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	selectedMatch := matches[0]
	
	decision := &PolicyDecision{
		Action:     selectedMatch.Action.Type,
		Reason:     "First matching policy selected",
		Confidence: selectedMatch.Confidence * 0.8, // Reduce confidence for arbitrary selection
		Severity:   selectedMatch.Action.Severity,
		Message:    selectedMatch.Action.Message,
		Parameters: selectedMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveLastMatch implements last-match strategy
func (cr *ConflictResolver) resolveLastMatch(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	selectedMatch := matches[len(matches)-1]
	
	decision := &PolicyDecision{
		Action:     selectedMatch.Action.Type,
		Reason:     "Last matching policy selected",
		Confidence: selectedMatch.Confidence * 0.8, // Reduce confidence for arbitrary selection
		Severity:   selectedMatch.Action.Severity,
		Message:    selectedMatch.Action.Message,
		Parameters: selectedMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveWeighted implements weighted scoring resolution
func (cr *ConflictResolver) resolveWeighted(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	weightConfig := config.WeightedConfig
	if weightConfig == nil {
		weightConfig = getDefaultWeightedConfig()
	}
	
	var bestMatch *PolicyMatch
	var bestScore float64 = -1
	
	for _, match := range matches {
		score := cr.calculateWeightedScore(match, weightConfig)
		if score > bestScore {
			bestScore = score
			bestMatch = &match
		}
	}
	
	if bestMatch == nil {
		bestMatch = &matches[0] // Fallback
	}
	
	decision := &PolicyDecision{
		Action:     bestMatch.Action.Type,
		Reason:     fmt.Sprintf("Highest weighted score (%.2f) from %d policies", bestScore, len(matches)),
		Confidence: math.Min(bestMatch.Confidence, bestScore),
		Severity:   bestMatch.Action.Severity,
		Message:    bestMatch.Action.Message,
		Parameters: bestMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveConsensus implements consensus-based resolution
func (cr *ConflictResolver) resolveConsensus(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	consensusConfig := config.ConsensusConfig
	if consensusConfig == nil {
		consensusConfig = getDefaultConsensusConfig()
	}
	
	// Group by action
	actionGroups := make(map[ActionType][]PolicyMatch)
	for _, match := range matches {
		actionGroups[match.Action.Type] = append(actionGroups[match.Action.Type], match)
	}
	
	// Check for consensus
	totalPolicies := len(matches)
	for action, policies := range actionGroups {
		agreement := float64(len(policies)) / float64(totalPolicies)
		
		if agreement >= consensusConfig.MinimumAgreement && len(policies) >= consensusConfig.QuorumThreshold {
			// We have consensus
			selectedMatch := cr.selectBestFromGroup(policies)
			
			decision := &PolicyDecision{
				Action:     action,
				Reason:     fmt.Sprintf("Consensus achieved: %.1f%% agreement (%d/%d policies)", agreement*100, len(policies), totalPolicies),
				Confidence: agreement * selectedMatch.Confidence,
				Severity:   selectedMatch.Action.Severity,
				Message:    selectedMatch.Action.Message,
				Parameters: selectedMatch.Action.Parameters,
			}
			
			conflicts := cr.detectConflicts(matches)
			return decision, conflicts, nil
		}
	}
	
	// No consensus, use tie breaker
	return cr.executeStrategy(consensusConfig.TieBreaker, matches, request)
}

// resolveRiskBased implements risk-based resolution
func (cr *ConflictResolver) resolveRiskBased(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	var selectedMatch *PolicyMatch
	var highestRisk float64 = -1
	
	for _, match := range matches {
		risk := cr.calculateRiskScore(match, request)
		if risk > highestRisk {
			highestRisk = risk
			selectedMatch = &match
		}
	}
	
	if selectedMatch == nil {
		selectedMatch = &matches[0] // Fallback
	}
	
	decision := &PolicyDecision{
		Action:     selectedMatch.Action.Type,
		Reason:     fmt.Sprintf("Highest risk score (%.2f) policy selected", highestRisk),
		Confidence: selectedMatch.Confidence * (1.0 - (highestRisk * 0.1)), // Adjust confidence based on risk
		Severity:   selectedMatch.Action.Severity,
		Message:    selectedMatch.Action.Message,
		Parameters: selectedMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveContextual implements context-aware resolution
func (cr *ConflictResolver) resolveContextual(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	// Score policies based on context relevance
	var bestMatch *PolicyMatch
	var bestScore float64 = -1
	
	for _, match := range matches {
		score := cr.calculateContextualScore(match, request)
		if score > bestScore {
			bestScore = score
			bestMatch = &match
		}
	}
	
	if bestMatch == nil {
		bestMatch = &matches[0] // Fallback
	}
	
	decision := &PolicyDecision{
		Action:     bestMatch.Action.Type,
		Reason:     fmt.Sprintf("Best contextual fit (score: %.2f)", bestScore),
		Confidence: bestMatch.Confidence * bestScore,
		Severity:   bestMatch.Action.Severity,
		Message:    bestMatch.Action.Message,
		Parameters: bestMatch.Action.Parameters,
	}
	
	conflicts := cr.detectConflicts(matches)
	return decision, conflicts, nil
}

// resolveHybrid implements hybrid resolution combining multiple strategies
func (cr *ConflictResolver) resolveHybrid(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	// Use different strategies based on the nature of conflicts
	conflicts := cr.detectConflicts(matches)
	
	// If high-severity conflicts, use most restrictive
	for _, conflict := range conflicts {
		if conflict.Severity == ConflictSeverityHigh {
			return cr.resolveMostRestrictive(matches, request, config)
		}
	}
	
	// If many policies agree, use consensus
	if len(matches) >= 3 {
		decision, _, err := cr.resolveConsensus(matches, request, config)
		if err == nil && decision.Confidence > 0.7 {
			return decision, conflicts, nil
		}
	}
	
	// Default to priority-based
	return cr.resolveHighestPriority(matches, request, config)
}

// resolveAdaptive implements adaptive resolution that learns from patterns
func (cr *ConflictResolver) resolveAdaptive(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error) {
	// Analyze historical resolution patterns
	historicalStrategy := cr.analyzeHistoricalPatterns(matches, request)
	
	// If we have a confident historical pattern, use it
	if historicalStrategy != "" {
		return cr.executeStrategy(ConflictResolutionStrategy(historicalStrategy), matches, request)
	}
	
	// Otherwise, use hybrid approach
	return cr.resolveHybrid(matches, request, config)
}

// Helper functions for resolution strategies

// calculateWeightedScore calculates a weighted score for a policy match
func (cr *ConflictResolver) calculateWeightedScore(match PolicyMatch, config *WeightedResolutionConfig) float64 {
	score := 0.0
	
	// Policy weight
	if weight, exists := config.PolicyWeights[match.PolicyID]; exists {
		score += weight
	} else {
		score += 1.0 // Default weight
	}
	
	// Action weight
	if weight, exists := config.ActionWeights[match.Action.Type]; exists {
		score += weight
	}
	
	// Severity weight
	if weight, exists := config.SeverityWeights[match.Action.Severity]; exists {
		score += weight
	}
	
	// Confidence factor
	score += match.Confidence * config.ConfidenceWeight
	
	// Priority factor
	score += float64(match.Priority) * config.PriorityWeight
	
	return score
}

// calculateRiskScore calculates risk-based score
func (cr *ConflictResolver) calculateRiskScore(match PolicyMatch, request *PolicyEvaluationRequest) float64 {
	risk := 0.0
	
	// Base risk from action type
	actionRisks := map[ActionType]float64{
		ActionBlock:      1.0,
		ActionQuarantine: 0.9,
		ActionRedact:     0.7,
		ActionMask:       0.6,
		ActionWarn:       0.4,
		ActionLog:        0.2,
		ActionAllow:      0.0,
	}
	
	if actionRisk, exists := actionRisks[match.Action.Type]; exists {
		risk += actionRisk
	}
	
	// Severity factor
	severityRisks := map[ActionSeverity]float64{
		SeverityCritical: 1.0,
		SeverityHigh:     0.8,
		SeverityMedium:   0.6,
		SeverityLow:      0.4,
		SeverityInfo:     0.2,
	}
	
	if severityRisk, exists := severityRisks[match.Action.Severity]; exists {
		risk += severityRisk
	}
	
	// Confidence factor (higher confidence = lower risk adjustment needed)
	risk *= (2.0 - match.Confidence)
	
	// Analysis-based risk factors
	if request.Analysis != nil {
		if request.Analysis.PIIDetection != nil && request.Analysis.PIIDetection.HasPII {
			risk += 0.3
		}
		
		if request.Analysis.Classification != nil {
			switch request.Analysis.Classification.Level {
			case "confidential":
				risk += 0.4
			case "restricted":
				risk += 0.3
			case "internal":
				risk += 0.2
			}
		}
	}
	
	return math.Min(risk, 2.0) // Cap at 2.0
}

// calculateContextualScore calculates context-aware score
func (cr *ConflictResolver) calculateContextualScore(match PolicyMatch, request *PolicyEvaluationRequest) float64 {
	score := match.Confidence
	
	// User context
	if request.User != "" {
		// Could check if policy is user-specific
		score += 0.1
	}
	
	// Organization context
	if request.Organization != "" {
		// Could check if policy matches organization
		score += 0.1
	}
	
	// Content type relevance
	if request.ContentType != "" {
		// Could check if policy is content-type specific
		score += 0.1
	}
	
	// Time-based context
	currentHour := time.Now().Hour()
	if currentHour >= 9 && currentHour <= 17 {
		// Business hours - stricter policies might be more relevant
		if match.Action.Type == ActionBlock || match.Action.Type == ActionRedact {
			score += 0.1
		}
	}
	
	return math.Min(score, 1.0)
}

// selectBestFromGroup selects the best policy from a group with same action
func (cr *ConflictResolver) selectBestFromGroup(policies []PolicyMatch) PolicyMatch {
	if len(policies) == 1 {
		return policies[0]
	}
	
	// Sort by confidence and priority
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].Confidence != policies[j].Confidence {
			return policies[i].Confidence > policies[j].Confidence
		}
		return policies[i].Priority > policies[j].Priority
	})
	
	return policies[0]
}

// analyzeHistoricalPatterns analyzes historical resolution patterns
func (cr *ConflictResolver) analyzeHistoricalPatterns(matches []PolicyMatch, request *PolicyEvaluationRequest) string {
	// This would analyze historical patterns from metrics/logs
	// For now, return empty to indicate no clear pattern
	return ""
}

// Utility functions

// getDefaultActionPriorities returns default action priority ordering
func getDefaultActionPriorities() []ActionType {
	return []ActionType{
		ActionBlock,
		ActionQuarantine,
		ActionRedact,
		ActionMask,
		ActionWarn,
		ActionLog,
		ActionAllow,
	}
}

// getActionRestrictionLevel returns restriction level for an action
func getActionRestrictionLevel(action ActionType, priorities []ActionType) int {
	for i, priority := range priorities {
		if priority == action {
			return len(priorities) - i
		}
	}
	return 0
}

// calculateConsensusConfidence calculates confidence based on consensus
func calculateConsensusConfidence(matches []PolicyMatch, selectedAction ActionType) float64 {
	agreeing := 0
	totalConfidence := 0.0
	
	for _, match := range matches {
		if match.Action.Type == selectedAction {
			agreeing++
			totalConfidence += match.Confidence
		}
	}
	
	if agreeing == 0 {
		return 0.0
	}
	
	avgConfidence := totalConfidence / float64(agreeing)
	consensus := float64(agreeing) / float64(len(matches))
	
	return avgConfidence * consensus
}

// getDefaultWeightedConfig returns default weighted resolution config
func getDefaultWeightedConfig() *WeightedResolutionConfig {
	return &WeightedResolutionConfig{
		PolicyWeights:   make(map[string]float64),
		ActionWeights:   make(map[ActionType]float64),
		SeverityWeights: make(map[ActionSeverity]float64),
		ConfidenceWeight: 1.0,
		PriorityWeight:   0.1,
	}
}

// getDefaultConsensusConfig returns default consensus config
func getDefaultConsensusConfig() *ConsensusResolutionConfig {
	return &ConsensusResolutionConfig{
		MinimumAgreement: 0.6, // 60% agreement
		QuorumThreshold:  2,   // At least 2 policies
		TieBreaker:       StrategyMostRestrictive,
	}
} 