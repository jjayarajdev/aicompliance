package policy

import (
	"fmt"
	"sort"
	"time"
)

// ConflictResolver handles policy conflicts with multiple resolution strategies
type ConflictResolver struct {
	strategies map[ConflictResolutionStrategy]ResolutionFunc
	config     *ConflictResolutionConfig
	metrics    *ConflictMetrics
}

// ConflictResolutionConfig configures conflict resolution behavior
type ConflictResolutionConfig struct {
	// Default strategy
	DefaultStrategy        ConflictResolutionStrategy `json:"default_strategy"`
	
	// Action priority ordering (highest to lowest priority)
	ActionPriorities       []ActionType               `json:"action_priorities"`
	
	// Advanced settings
	EnableDetailedAnalysis bool                       `json:"enable_detailed_analysis"`
	MaxConflictsToTrack    int                        `json:"max_conflicts_to_track"`
	ConflictTimeout        time.Duration              `json:"conflict_timeout"`
	
	// Strategy-specific configurations
	WeightedConfig         *WeightedResolutionConfig  `json:"weighted_config,omitempty"`
	ConsensusConfig        *ConsensusResolutionConfig `json:"consensus_config,omitempty"`
	CustomConfig           *CustomResolutionConfig    `json:"custom_config,omitempty"`
}

// ConflictResolutionStrategy represents different conflict resolution approaches
type ConflictResolutionStrategy string

const (
	// Basic strategies
	StrategyMostRestrictive   ConflictResolutionStrategy = "most_restrictive"
	StrategyHighestPriority   ConflictResolutionStrategy = "highest_priority"
	StrategyFirstMatch        ConflictResolutionStrategy = "first_match"
	StrategyLastMatch         ConflictResolutionStrategy = "last_match"
	
	// Advanced strategies
	StrategyWeighted          ConflictResolutionStrategy = "weighted"
	StrategyConsensus         ConflictResolutionStrategy = "consensus"
	StrategyRiskBased         ConflictResolutionStrategy = "risk_based"
	StrategyContextual        ConflictResolutionStrategy = "contextual"
	
	// Composite strategies
	StrategyHybrid            ConflictResolutionStrategy = "hybrid"
	StrategyAdaptive          ConflictResolutionStrategy = "adaptive"
	StrategyCustom            ConflictResolutionStrategy = "custom"
)

// WeightedResolutionConfig configures weighted resolution
type WeightedResolutionConfig struct {
	PolicyWeights    map[string]float64 `json:"policy_weights"`
	ActionWeights    map[ActionType]float64 `json:"action_weights"`
	SeverityWeights  map[ActionSeverity]float64 `json:"severity_weights"`
	ConfidenceWeight float64            `json:"confidence_weight"`
	PriorityWeight   float64            `json:"priority_weight"`
}

// ConsensusResolutionConfig configures consensus-based resolution
type ConsensusResolutionConfig struct {
	MinimumAgreement float64 `json:"minimum_agreement"` // 0.0 to 1.0
	QuorumThreshold  int     `json:"quorum_threshold"`  // Minimum policies needed
	TieBreaker       ConflictResolutionStrategy `json:"tie_breaker"`
}

// CustomResolutionConfig configures custom resolution handlers
type CustomResolutionConfig struct {
	HandlerName    string                 `json:"handler_name"`
	Parameters     map[string]interface{} `json:"parameters"`
	FallbackStrategy ConflictResolutionStrategy `json:"fallback_strategy"`
}

// ResolutionFunc represents a conflict resolution function
type ResolutionFunc func(matches []PolicyMatch, request *PolicyEvaluationRequest, config *ConflictResolutionConfig) (*PolicyDecision, []PolicyConflict, error)

// ConflictAnalysis provides detailed conflict analysis
type ConflictAnalysis struct {
	ConflictID          string                     `json:"conflict_id"`
	TotalConflicts      int                        `json:"total_conflicts"`
	ConflictTypes       []ConflictType             `json:"conflict_types"`
	ConflictingPolicies []ConflictingPolicyPair    `json:"conflicting_policies"`
	ResolutionStrategy  ConflictResolutionStrategy `json:"resolution_strategy"`
	ResolutionTime      time.Duration              `json:"resolution_time"`
	
	// Detailed analysis
	ActionConflicts     []ActionConflict           `json:"action_conflicts"`
	PriorityConflicts   []PriorityConflict         `json:"priority_conflicts"`
	SeverityConflicts   []SeverityConflict         `json:"severity_conflicts"`
	
	// Resolution details
	SelectedPolicy      *PolicyMatch               `json:"selected_policy"`
	SelectedAction      PolicyAction               `json:"selected_action"`
	Confidence          float64                    `json:"confidence"`
	AlternativeActions  []PolicyAction             `json:"alternative_actions"`
	ResolutionReason    string                     `json:"resolution_reason"`
	
	// Recommendations
	Recommendations     []ConflictRecommendation   `json:"recommendations"`
	SuggestedChanges    []PolicySuggestion         `json:"suggested_changes"`
}

// ConflictingPolicyPair represents two conflicting policies
type ConflictingPolicyPair struct {
	Policy1     PolicyMatch     `json:"policy1"`
	Policy2     PolicyMatch     `json:"policy2"`
	ConflictType ConflictType   `json:"conflict_type"`
	Severity    ConflictSeverity `json:"severity"`
	Description string          `json:"description"`
}

// ActionConflict represents conflicting actions
type ActionConflict struct {
	Actions     []ActionType     `json:"actions"`
	Policies    []string         `json:"policies"`
	Severity    ConflictSeverity `json:"severity"`
	Resolution  ActionType       `json:"resolution"`
	Reason      string           `json:"reason"`
}

// PriorityConflict represents priority conflicts
type PriorityConflict struct {
	Policies    []PolicyMatch    `json:"policies"`
	PriorityRange [2]int         `json:"priority_range"`
	Resolution  string           `json:"resolution"`
}

// SeverityConflict represents severity conflicts
type SeverityConflict struct {
	Severities  []ActionSeverity `json:"severities"`
	Policies    []string         `json:"policies"`
	Resolution  ActionSeverity   `json:"resolution"`
}

// ConflictRecommendation provides recommendations for resolving conflicts
type ConflictRecommendation struct {
	Type        RecommendationType `json:"type"`
	Description string             `json:"description"`
	Action      string             `json:"action"`
	Priority    int                `json:"priority"`
	Impact      string             `json:"impact"`
}

// RecommendationType represents types of conflict recommendations
type RecommendationType string

const (
	RecommendationAdjustPriority   RecommendationType = "adjust_priority"
	RecommendationMergePolicies    RecommendationType = "merge_policies"
	RecommendationSplitPolicy      RecommendationType = "split_policy"
	RecommendationRefineConditions RecommendationType = "refine_conditions"
	RecommendationChangeAction     RecommendationType = "change_action"
	RecommendationAddException     RecommendationType = "add_exception"
)

// PolicySuggestion suggests changes to policies to reduce conflicts
type PolicySuggestion struct {
	PolicyID    string                 `json:"policy_id"`
	SuggestionType string              `json:"suggestion_type"`
	CurrentValue interface{}           `json:"current_value"`
	SuggestedValue interface{}         `json:"suggested_value"`
	Reason      string                 `json:"reason"`
	Impact      ConflictSeverity       `json:"impact"`
}

// ConflictMetrics tracks conflict resolution metrics
type ConflictMetrics struct {
	TotalConflicts          int64                                    `json:"total_conflicts"`
	ConflictsByType         map[ConflictType]int64                   `json:"conflicts_by_type"`
	ConflictsByStrategy     map[ConflictResolutionStrategy]int64     `json:"conflicts_by_strategy"`
	ResolutionTimes         []time.Duration                          `json:"resolution_times"`
	AverageResolutionTime   time.Duration                            `json:"average_resolution_time"`
	ConflictResolutionRate  float64                                  `json:"conflict_resolution_rate"`
	
	// Strategy effectiveness
	StrategySuccessRates    map[ConflictResolutionStrategy]float64   `json:"strategy_success_rates"`
	StrategyExecutionTimes  map[ConflictResolutionStrategy]time.Duration `json:"strategy_execution_times"`
}

// NewConflictResolver creates a new conflict resolver
func NewConflictResolver(config *ConflictResolutionConfig) *ConflictResolver {
	if config == nil {
		config = getDefaultConflictResolutionConfig()
	}
	
	resolver := &ConflictResolver{
		strategies: make(map[ConflictResolutionStrategy]ResolutionFunc),
		config:     config,
		metrics:    &ConflictMetrics{
			ConflictsByType:     make(map[ConflictType]int64),
			ConflictsByStrategy: make(map[ConflictResolutionStrategy]int64),
			StrategySuccessRates: make(map[ConflictResolutionStrategy]float64),
			StrategyExecutionTimes: make(map[ConflictResolutionStrategy]time.Duration),
		},
	}
	
	// Register built-in strategies
	resolver.registerBuiltinStrategies()
	
	return resolver
}

// ResolveConflicts resolves conflicts between multiple policy matches
func (cr *ConflictResolver) ResolveConflicts(matches []PolicyMatch, request *PolicyEvaluationRequest) (*PolicyDecision, *ConflictAnalysis, error) {
	start := time.Now()
	
	// If no conflicts, return the single match
	if len(matches) <= 1 {
		if len(matches) == 0 {
			return &PolicyDecision{
				Action:     ActionAllow,
				Reason:     "No policies matched",
				Confidence: 1.0,
				Severity:   SeverityInfo,
			}, nil, nil
		}
		
		match := matches[0]
		return &PolicyDecision{
			Action:     match.Action.Type,
			Reason:     fmt.Sprintf("Single policy match: %s", match.PolicyName),
			Confidence: match.Confidence,
			Severity:   match.Action.Severity,
			Message:    match.Action.Message,
			Parameters: match.Action.Parameters,
		}, nil, nil
	}
	
	// Detect conflicts
	conflicts := cr.detectConflicts(matches)
	
	// Generate conflict analysis
	analysis := &ConflictAnalysis{
		ConflictID:          generateConflictID(matches),
		TotalConflicts:      len(conflicts),
		ConflictTypes:       extractConflictTypes(conflicts),
		ConflictingPolicies: cr.analyzeConflictingPairs(matches),
		ResolutionStrategy:  cr.config.DefaultStrategy,
		ActionConflicts:     cr.analyzeActionConflicts(matches),
		PriorityConflicts:   cr.analyzePriorityConflicts(matches),
		SeverityConflicts:   cr.analyzeSeverityConflicts(matches),
	}
	
	// Select resolution strategy
	strategy := cr.selectResolutionStrategy(matches, conflicts)
	analysis.ResolutionStrategy = strategy
	
	// Resolve using selected strategy
	decision, _, err := cr.executeStrategy(strategy, matches, request)
	if err != nil {
		return nil, analysis, err
	}
	
	// Complete analysis
	analysis.ResolutionTime = time.Since(start)
	analysis.SelectedAction = PolicyAction{
		Type:       decision.Action,
		Severity:   decision.Severity,
		Message:    decision.Message,
		Parameters: decision.Parameters,
	}
	analysis.Confidence = decision.Confidence
	analysis.ResolutionReason = decision.Reason
	analysis.Recommendations = cr.generateRecommendations(matches, conflicts)
	analysis.SuggestedChanges = cr.generatePolicySuggestions(matches, conflicts)
	
	// Update metrics
	cr.updateMetrics(strategy, conflicts, time.Since(start))
	
	return decision, analysis, nil
}

// detectConflicts identifies conflicts between policy matches
func (cr *ConflictResolver) detectConflicts(matches []PolicyMatch) []PolicyConflict {
	var conflicts []PolicyConflict
	
	// Check for action conflicts
	actionConflicts := cr.detectActionConflicts(matches)
	conflicts = append(conflicts, actionConflicts...)
	
	// Check for priority conflicts
	priorityConflicts := cr.detectPriorityConflicts(matches)
	conflicts = append(conflicts, priorityConflicts...)
	
	// Check for severity conflicts
	severityConflicts := cr.detectSeverityConflicts(matches)
	conflicts = append(conflicts, severityConflicts...)
	
	// Check for scope conflicts
	scopeConflicts := cr.detectScopeConflicts(matches)
	conflicts = append(conflicts, scopeConflicts...)
	
	return conflicts
}

// detectActionConflicts identifies conflicting actions
func (cr *ConflictResolver) detectActionConflicts(matches []PolicyMatch) []PolicyConflict {
	var conflicts []PolicyConflict
	
	actionGroups := make(map[ActionType][]PolicyMatch)
	for _, match := range matches {
		actionGroups[match.Action.Type] = append(actionGroups[match.Action.Type], match)
	}
	
	// If we have multiple different actions, there's a conflict
	if len(actionGroups) > 1 {
		var policyIDs []string
		var policyNames []string
		var actions []ActionType
		
		for action, policies := range actionGroups {
			actions = append(actions, action)
			for _, policy := range policies {
				policyIDs = append(policyIDs, policy.PolicyID)
				policyNames = append(policyNames, policy.PolicyName)
			}
		}
		
		severity := cr.calculateConflictSeverity(actions)
		
		conflicts = append(conflicts, PolicyConflict{
			Type:        ConflictTypeAction,
			PolicyIDs:   policyIDs,
			PolicyNames: policyNames,
			Description: fmt.Sprintf("Multiple actions detected: %v", actions),
			Severity:    severity,
		})
	}
	
	return conflicts
}

// detectPriorityConflicts identifies priority-based conflicts
func (cr *ConflictResolver) detectPriorityConflicts(matches []PolicyMatch) []PolicyConflict {
	var conflicts []PolicyConflict
	
	priorityGroups := make(map[int][]PolicyMatch)
	for _, match := range matches {
		priorityGroups[match.Priority] = append(priorityGroups[match.Priority], match)
	}
	
	// Check for same priority with different actions
	for priority, policies := range priorityGroups {
		if len(policies) > 1 {
			actionSet := make(map[ActionType]bool)
			for _, policy := range policies {
				actionSet[policy.Action.Type] = true
			}
			
			if len(actionSet) > 1 {
				var policyIDs []string
				var policyNames []string
				
				for _, policy := range policies {
					policyIDs = append(policyIDs, policy.PolicyID)
					policyNames = append(policyNames, policy.PolicyName)
				}
				
				conflicts = append(conflicts, PolicyConflict{
					Type:        ConflictTypePriority,
					PolicyIDs:   policyIDs,
					PolicyNames: policyNames,
					Description: fmt.Sprintf("Same priority (%d) with different actions", priority),
					Severity:    ConflictSeverityMedium,
				})
			}
		}
	}
	
	return conflicts
}

// detectSeverityConflicts identifies severity-based conflicts
func (cr *ConflictResolver) detectSeverityConflicts(matches []PolicyMatch) []PolicyConflict {
	var conflicts []PolicyConflict
	
	severityMap := make(map[ActionSeverity][]PolicyMatch)
	for _, match := range matches {
		severityMap[match.Action.Severity] = append(severityMap[match.Action.Severity], match)
	}
	
	// Check for conflicting severities with same action
	actionSeverities := make(map[ActionType][]ActionSeverity)
	for _, match := range matches {
		actionSeverities[match.Action.Type] = append(actionSeverities[match.Action.Type], match.Action.Severity)
	}
	
	for action, severities := range actionSeverities {
		if len(severities) > 1 {
			severitySet := make(map[ActionSeverity]bool)
			for _, severity := range severities {
				severitySet[severity] = true
			}
			
			if len(severitySet) > 1 {
				conflicts = append(conflicts, PolicyConflict{
					Type:        ConflictTypeAction,
					Description: fmt.Sprintf("Action %s has multiple severities: %v", action, severities),
					Severity:    ConflictSeverityLow,
				})
			}
		}
	}
	
	return conflicts
}

// detectScopeConflicts identifies scope-based conflicts
func (cr *ConflictResolver) detectScopeConflicts(matches []PolicyMatch) []PolicyConflict {
	// For now, this is a placeholder - scope conflicts would be detected
	// based on overlapping but contradictory policy scopes
	return []PolicyConflict{}
}

// executeStrategy executes the selected resolution strategy
func (cr *ConflictResolver) executeStrategy(strategy ConflictResolutionStrategy, matches []PolicyMatch, request *PolicyEvaluationRequest) (*PolicyDecision, []PolicyConflict, error) {
	strategyFunc, exists := cr.strategies[strategy]
	if !exists {
		// Fallback to most restrictive
		strategyFunc = cr.strategies[StrategyMostRestrictive]
	}
	
	return strategyFunc(matches, request, cr.config)
}

// registerBuiltinStrategies registers all built-in resolution strategies
func (cr *ConflictResolver) registerBuiltinStrategies() {
	cr.strategies[StrategyMostRestrictive] = cr.resolveMostRestrictive
	cr.strategies[StrategyHighestPriority] = cr.resolveHighestPriority
	cr.strategies[StrategyFirstMatch] = cr.resolveFirstMatch
	cr.strategies[StrategyLastMatch] = cr.resolveLastMatch
	cr.strategies[StrategyWeighted] = cr.resolveWeighted
	cr.strategies[StrategyConsensus] = cr.resolveConsensus
	cr.strategies[StrategyRiskBased] = cr.resolveRiskBased
	cr.strategies[StrategyContextual] = cr.resolveContextual
	cr.strategies[StrategyHybrid] = cr.resolveHybrid
	cr.strategies[StrategyAdaptive] = cr.resolveAdaptive
}

// Helper methods for conflict analysis and resolution

// selectResolutionStrategy selects the best strategy based on context
func (cr *ConflictResolver) selectResolutionStrategy(matches []PolicyMatch, conflicts []PolicyConflict) ConflictResolutionStrategy {
	// If configured to use default strategy
	if cr.config.DefaultStrategy != "" {
		return cr.config.DefaultStrategy
	}
	
	// Adaptive strategy selection based on conflict characteristics
	highSeverityConflicts := 0
	for _, conflict := range conflicts {
		if conflict.Severity == ConflictSeverityHigh {
			highSeverityConflicts++
		}
	}
	
	// High severity conflicts - use most restrictive
	if highSeverityConflicts > 0 {
		return StrategyMostRestrictive
	}
	
	// Many policies with clear priorities - use priority
	if len(matches) > 3 && cr.hasClearPriorityDifferences(matches) {
		return StrategyHighestPriority
	}
	
	// Default to most restrictive for safety
	return StrategyMostRestrictive
}

// hasClearPriorityDifferences checks if matches have clear priority differences
func (cr *ConflictResolver) hasClearPriorityDifferences(matches []PolicyMatch) bool {
	if len(matches) < 2 {
		return false
	}
	
	priorities := make(map[int]int)
	for _, match := range matches {
		priorities[match.Priority]++
	}
	
	// If all policies have different priorities, priorities are clear
	return len(priorities) == len(matches)
}

// analyzeConflictingPairs analyzes pairs of conflicting policies
func (cr *ConflictResolver) analyzeConflictingPairs(matches []PolicyMatch) []ConflictingPolicyPair {
	var pairs []ConflictingPolicyPair
	
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			policy1 := matches[i]
			policy2 := matches[j]
			
			// Check for action conflicts
			if policy1.Action.Type != policy2.Action.Type {
				pairs = append(pairs, ConflictingPolicyPair{
					Policy1:     policy1,
					Policy2:     policy2,
					ConflictType: ConflictTypeAction,
					Severity:    cr.calculatePairConflictSeverity(policy1.Action.Type, policy2.Action.Type),
					Description: fmt.Sprintf("Action conflict: %s vs %s", policy1.Action.Type, policy2.Action.Type),
				})
			}
			
			// Check for priority conflicts with same action
			if policy1.Priority == policy2.Priority && policy1.Action.Type != policy2.Action.Type {
				pairs = append(pairs, ConflictingPolicyPair{
					Policy1:     policy1,
					Policy2:     policy2,
					ConflictType: ConflictTypePriority,
					Severity:    ConflictSeverityMedium,
					Description: fmt.Sprintf("Same priority (%d) with different actions", policy1.Priority),
				})
			}
		}
	}
	
	return pairs
}

// analyzeActionConflicts analyzes action-level conflicts
func (cr *ConflictResolver) analyzeActionConflicts(matches []PolicyMatch) []ActionConflict {
	var conflicts []ActionConflict
	
	actionGroups := make(map[ActionType][]string)
	for _, match := range matches {
		actionGroups[match.Action.Type] = append(actionGroups[match.Action.Type], match.PolicyID)
	}
	
	// If multiple actions exist, there's a conflict
	if len(actionGroups) > 1 {
		var actions []ActionType
		var allPolicies []string
		
		for action, policies := range actionGroups {
			actions = append(actions, action)
			allPolicies = append(allPolicies, policies...)
		}
		
		// Determine resolution using current strategy
		resolution := cr.resolveActionConflict(actions)
		
		conflicts = append(conflicts, ActionConflict{
			Actions:  actions,
			Policies: allPolicies,
			Severity: cr.calculateConflictSeverity(actions),
			Resolution: resolution,
			Reason:   fmt.Sprintf("Resolved using %s strategy", cr.config.DefaultStrategy),
		})
	}
	
	return conflicts
}

// analyzePriorityConflicts analyzes priority-related conflicts
func (cr *ConflictResolver) analyzePriorityConflicts(matches []PolicyMatch) []PriorityConflict {
	var conflicts []PriorityConflict
	
	priorityGroups := make(map[int][]PolicyMatch)
	for _, match := range matches {
		priorityGroups[match.Priority] = append(priorityGroups[match.Priority], match)
	}
	
	// Find priority ranges with conflicts
	for priority, policies := range priorityGroups {
		if len(policies) > 1 {
			// Check if they have different actions
			actionSet := make(map[ActionType]bool)
			for _, policy := range policies {
				actionSet[policy.Action.Type] = true
			}
			
			if len(actionSet) > 1 {
				conflicts = append(conflicts, PriorityConflict{
					Policies:      policies,
					PriorityRange: [2]int{priority, priority},
					Resolution:    fmt.Sprintf("Apply most restrictive among priority %d policies", priority),
				})
			}
		}
	}
	
	return conflicts
}

// analyzeSeverityConflicts analyzes severity-related conflicts
func (cr *ConflictResolver) analyzeSeverityConflicts(matches []PolicyMatch) []SeverityConflict {
	var conflicts []SeverityConflict
	
	severityMap := make(map[ActionSeverity][]string)
	for _, match := range matches {
		severityMap[match.Action.Severity] = append(severityMap[match.Action.Severity], match.PolicyID)
	}
	
	// Check for multiple severities with the same action type
	actionSeverities := make(map[ActionType][]ActionSeverity)
	for _, match := range matches {
		actionSeverities[match.Action.Type] = append(actionSeverities[match.Action.Type], match.Action.Severity)
	}
	
	for _, severities := range actionSeverities {
		if len(severities) > 1 {
			severitySet := make(map[ActionSeverity]bool)
			var uniqueSeverities []ActionSeverity
			var policies []string
			
			for i, severity := range severities {
				if !severitySet[severity] {
					severitySet[severity] = true
					uniqueSeverities = append(uniqueSeverities, severity)
				}
				policies = append(policies, matches[i].PolicyID)
			}
			
			if len(uniqueSeverities) > 1 {
				conflicts = append(conflicts, SeverityConflict{
					Severities: uniqueSeverities,
					Policies:   policies,
					Resolution: cr.resolveHighestSeverity(uniqueSeverities),
				})
			}
		}
	}
	
	return conflicts
}

// generateRecommendations generates recommendations for resolving conflicts
func (cr *ConflictResolver) generateRecommendations(matches []PolicyMatch, conflicts []PolicyConflict) []ConflictRecommendation {
	var recommendations []ConflictRecommendation
	
	// Analyze conflict patterns
	for _, conflict := range conflicts {
		switch conflict.Type {
		case ConflictTypeAction:
			recommendations = append(recommendations, ConflictRecommendation{
				Type:        RecommendationAdjustPriority,
				Description: "Consider adjusting policy priorities to establish clear precedence",
				Action:      "Review and adjust priority values to eliminate conflicts",
				Priority:    3,
				Impact:      "High - will reduce decision ambiguity",
			})
			
		case ConflictTypePriority:
			recommendations = append(recommendations, ConflictRecommendation{
				Type:        RecommendationRefineConditions,
				Description: "Refine policy conditions to reduce overlap",
				Action:      "Add more specific conditions to differentiate policy triggers",
				Priority:    2,
				Impact:      "Medium - will reduce false conflicts",
			})
		}
	}
	
	// Policy-specific recommendations
	if len(matches) > 5 {
		recommendations = append(recommendations, ConflictRecommendation{
			Type:        RecommendationMergePolicies,
			Description: "Consider merging similar policies to reduce complexity",
			Action:      "Identify and merge policies with similar conditions and actions",
			Priority:    1,
			Impact:      "High - will simplify policy management",
		})
	}
	
	// Sort by priority
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].Priority > recommendations[j].Priority
	})
	
	return recommendations
}

// generatePolicySuggestions generates specific policy change suggestions
func (cr *ConflictResolver) generatePolicySuggestions(matches []PolicyMatch, conflicts []PolicyConflict) []PolicySuggestion {
	var suggestions []PolicySuggestion
	
	// Analyze priority distribution
	priorities := make(map[int]int)
	for _, match := range matches {
		priorities[match.Priority]++
	}
	
	// Suggest priority adjustments for conflicts
	for priority, count := range priorities {
		if count > 1 {
			suggestions = append(suggestions, PolicySuggestion{
				PolicyID:       "multiple",
				SuggestionType: "priority_adjustment",
				CurrentValue:   priority,
				SuggestedValue: fmt.Sprintf("Distribute across range %d-%d", priority, priority+count-1),
				Reason:         fmt.Sprintf("%d policies share priority %d", count, priority),
				Impact:         ConflictSeverityMedium,
			})
		}
	}
	
	// Suggest action harmonization
	actionCounts := make(map[ActionType]int)
	for _, match := range matches {
		actionCounts[match.Action.Type]++
	}
	
	if len(actionCounts) > 2 {
		suggestions = append(suggestions, PolicySuggestion{
			PolicyID:       "multiple",
			SuggestionType: "action_harmonization",
			CurrentValue:   len(actionCounts),
			SuggestedValue: "2-3 distinct actions maximum",
			Reason:         "Too many different actions create complexity",
			Impact:         ConflictSeverityLow,
		})
	}
	
	return suggestions
}

// updateMetrics updates conflict resolution metrics
func (cr *ConflictResolver) updateMetrics(strategy ConflictResolutionStrategy, conflicts []PolicyConflict, duration time.Duration) {
	cr.metrics.TotalConflicts += int64(len(conflicts))
	cr.metrics.ConflictsByStrategy[strategy]++
	cr.metrics.ResolutionTimes = append(cr.metrics.ResolutionTimes, duration)
	
	// Update average resolution time
	totalTime := time.Duration(0)
	for _, t := range cr.metrics.ResolutionTimes {
		totalTime += t
	}
	cr.metrics.AverageResolutionTime = totalTime / time.Duration(len(cr.metrics.ResolutionTimes))
	
	// Update strategy execution times
	if existing, exists := cr.metrics.StrategyExecutionTimes[strategy]; exists {
		cr.metrics.StrategyExecutionTimes[strategy] = (existing + duration) / 2
	} else {
		cr.metrics.StrategyExecutionTimes[strategy] = duration
	}
	
	// Track conflict types
	for _, conflict := range conflicts {
		cr.metrics.ConflictsByType[conflict.Type]++
	}
}

// Utility functions

// calculateConflictSeverity calculates severity based on conflicting actions
func (cr *ConflictResolver) calculateConflictSeverity(actions []ActionType) ConflictSeverity {
	// Map actions to severity levels
	actionSeverities := map[ActionType]int{
		ActionBlock:      5,
		ActionQuarantine: 4,
		ActionRedact:     3,
		ActionMask:       2,
		ActionWarn:       1,
		ActionLog:        1,
		ActionAllow:      0,
	}
	
	maxSeverity := 0
	minSeverity := 10
	
	for _, action := range actions {
		if severity, exists := actionSeverities[action]; exists {
			if severity > maxSeverity {
				maxSeverity = severity
			}
			if severity < minSeverity {
				minSeverity = severity
			}
		}
	}
	
	difference := maxSeverity - minSeverity
	if difference >= 4 {
		return ConflictSeverityHigh
	} else if difference >= 2 {
		return ConflictSeverityMedium
	}
	return ConflictSeverityLow
}

// calculatePairConflictSeverity calculates severity for a pair of conflicting actions
func (cr *ConflictResolver) calculatePairConflictSeverity(action1, action2 ActionType) ConflictSeverity {
	return cr.calculateConflictSeverity([]ActionType{action1, action2})
}

// resolveActionConflict determines which action should win in a conflict
func (cr *ConflictResolver) resolveActionConflict(actions []ActionType) ActionType {
	actionPriorities := getDefaultActionPriorities()
	
	var bestAction ActionType
	var bestPriority int = -1
	
	for _, action := range actions {
		priority := getActionRestrictionLevel(action, actionPriorities)
		if priority > bestPriority {
			bestPriority = priority
			bestAction = action
		}
	}
	
	return bestAction
}

// resolveHighestSeverity returns the highest severity from a list
func (cr *ConflictResolver) resolveHighestSeverity(severities []ActionSeverity) ActionSeverity {
	severityLevels := map[ActionSeverity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}
	
	highest := SeverityInfo
	highestLevel := 0
	
	for _, severity := range severities {
		if level, exists := severityLevels[severity]; exists && level > highestLevel {
			highestLevel = level
			highest = severity
		}
	}
	
	return highest
}

// extractConflictTypes extracts unique conflict types from conflicts
func extractConflictTypes(conflicts []PolicyConflict) []ConflictType {
	typeSet := make(map[ConflictType]bool)
	for _, conflict := range conflicts {
		typeSet[conflict.Type] = true
	}
	
	var types []ConflictType
	for conflictType := range typeSet {
		types = append(types, conflictType)
	}
	
	return types
}

// generateConflictID generates a unique ID for conflict analysis
func generateConflictID(matches []PolicyMatch) string {
	var policyIDs []string
	for _, match := range matches {
		policyIDs = append(policyIDs, match.PolicyID)
	}
	sort.Strings(policyIDs)
	
	hasher := fmt.Sprintf("conflict_%d_%v", len(matches), policyIDs)
	return fmt.Sprintf("%x", hasher)[:12]
}

// getDefaultConflictResolutionConfig returns default configuration
func getDefaultConflictResolutionConfig() *ConflictResolutionConfig {
	return &ConflictResolutionConfig{
		DefaultStrategy:         StrategyMostRestrictive,
		ActionPriorities:        getDefaultActionPriorities(),
		EnableDetailedAnalysis:  true,
		MaxConflictsToTrack:     100,
		ConflictTimeout:         5 * time.Second,
		WeightedConfig:          getDefaultWeightedConfig(),
		ConsensusConfig:         getDefaultConsensusConfig(),
	}
}

// GetMetrics returns current conflict resolution metrics
func (cr *ConflictResolver) GetMetrics() *ConflictMetrics {
	return cr.metrics
} 