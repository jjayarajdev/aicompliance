package policy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PolicyEngine represents the core policy evaluation engine
type PolicyEngine struct {
	policies         map[string]*Policy
	rulesets         map[string]*PolicyRuleset
	validator        *PolicyValidator
	logger           PolicyLogger
	cache            PolicyCacheInterface
	metrics          PolicyMetrics
	conflictResolver *ConflictResolver
	advancedEvaluator *AdvancedConditionEvaluator
}

// NewPolicyEngine creates a new policy engine instance
func NewPolicyEngine() *PolicyEngine {
	engine := &PolicyEngine{
		policies: make(map[string]*Policy),
		rulesets: make(map[string]*PolicyRuleset),
		validator: NewPolicyValidator(),
		conflictResolver: NewConflictResolver(nil), // Use nil for default config
		// Initialize advanced evaluator with default config
		advancedEvaluator: NewAdvancedConditionEvaluator(nil),
	}
	return engine
}

// AddPolicy adds a new policy to the engine
func (pe *PolicyEngine) AddPolicy(policy *Policy) error {
	// Validate policy before adding
	validationResult := pe.validator.ValidatePolicy(policy)
	if !validationResult.Valid {
		return fmt.Errorf("policy validation failed: %v", validationResult.Errors)
	}

	// Set timestamps
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	// Store policy
	pe.policies[policy.ID] = policy

	return nil
}

// GetPolicy retrieves a policy by ID
func (pe *PolicyEngine) GetPolicy(id string) (*Policy, error) {
	policy, exists := pe.policies[id]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", id)
	}
	return policy, nil
}

// UpdatePolicy updates an existing policy
func (pe *PolicyEngine) UpdatePolicy(policy *Policy) error {
	existing, exists := pe.policies[policy.ID]
	if !exists {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}

	// Validate updated policy
	validationResult := pe.validator.ValidatePolicy(policy)
	if !validationResult.Valid {
		return fmt.Errorf("policy validation failed: %v", validationResult.Errors)
	}

	// Preserve creation time, update modification time
	policy.CreatedAt = existing.CreatedAt
	policy.UpdatedAt = time.Now()

	// Store updated policy
	pe.policies[policy.ID] = policy

	return nil
}

// DeletePolicy removes a policy from the engine
func (pe *PolicyEngine) DeletePolicy(id string) error {
	if _, exists := pe.policies[id]; !exists {
		return fmt.Errorf("policy not found: %s", id)
	}
	
	delete(pe.policies, id)
	return nil
}

// ListPolicies returns all policies
func (pe *PolicyEngine) ListPolicies() []*Policy {
	policies := make([]*Policy, 0, len(pe.policies))
	for _, policy := range pe.policies {
		policies = append(policies, policy)
	}
	return policies
}

// EvaluateRequest evaluates a request against all applicable policies
func (pe *PolicyEngine) EvaluateRequest(ctx context.Context, request *PolicyEvaluationRequest) (*PolicyEvaluationResult, error) {
	start := time.Now()

	result := &PolicyEvaluationResult{
		RequestID:       request.ID,
		MatchedPolicies: []PolicyMatch{},
		Actions:         []ExecutedAction{},
		Conflicts:       []PolicyConflict{},
		Recommendations: []string{},
		Timestamp:       start,
		Metadata:        make(map[string]interface{}),
	}

	// Find applicable policies
	applicablePolicies := pe.findApplicablePolicies(request)
	
	// Evaluate each applicable policy
	for _, policy := range applicablePolicies {
		policyMatch := pe.evaluatePolicy(policy, request)
		if policyMatch != nil {
			result.MatchedPolicies = append(result.MatchedPolicies, *policyMatch)
		}
	}

	// Resolve conflicts and determine final decision
	finalDecision := pe.resolveConflicts(result.MatchedPolicies, result)
	result.Decision = finalDecision

	// Calculate confidence
	result.Confidence = pe.calculateOverallConfidence(result.MatchedPolicies)

	result.ProcessingTime = time.Since(start)

	return result, nil
}

// findApplicablePolicies finds policies that apply to the request
func (pe *PolicyEngine) findApplicablePolicies(request *PolicyEvaluationRequest) []*Policy {
	var applicable []*Policy

	for _, policy := range pe.policies {
		if policy.Status != PolicyStatusActive {
			continue
		}

		// Check if policy applies to this request
		if pe.isPolicyApplicable(policy, request) {
			applicable = append(applicable, policy)
		}
	}

	return applicable
}

// isPolicyApplicable checks if a policy applies to a request
func (pe *PolicyEngine) isPolicyApplicable(policy *Policy, request *PolicyEvaluationRequest) bool {
	// Check organization scope
	if len(policy.Scope.Organizations) > 0 {
		found := false
		for _, org := range policy.Scope.Organizations {
			if org == request.Organization {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check user scope
	if len(policy.Scope.Users) > 0 {
		found := false
		for _, user := range policy.Scope.Users {
			if user == request.User {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check content type scope
	if len(policy.Scope.ContentTypes) > 0 {
		found := false
		for _, contentType := range policy.Scope.ContentTypes {
			if contentType == request.ContentType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// evaluatePolicy evaluates a single policy against a request
func (pe *PolicyEngine) evaluatePolicy(policy *Policy, request *PolicyEvaluationRequest) *PolicyMatch {
	// Evaluate each rule in the policy
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}

		if pe.evaluateCondition(rule.Condition, request) {
			// Rule matched, create policy match
			return &PolicyMatch{
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Priority:   rule.Priority,
				Confidence: 1.0, // For now, simple binary matching
				Action:     rule.Action,
			}
		}
	}

	return nil
}

// evaluateCondition evaluates a condition against a request
func (pe *PolicyEngine) evaluateCondition(condition *PolicyCondition, request *PolicyEvaluationRequest) bool {
	if condition == nil {
		return true
	}

	// Try advanced evaluator first for sophisticated conditions
	if pe.advancedEvaluator != nil {
		// Check if this is an advanced condition type that should use the advanced evaluator
		if pe.shouldUseAdvancedEvaluator(condition) {
			result, err := pe.advancedEvaluator.EvaluateAdvancedCondition(condition, request)
			if err == nil {
				return result.Matched
			}
			// Fall back to basic evaluation if advanced evaluation fails
		}
	}

	switch condition.Type {
	case ConditionAnd:
		for _, child := range condition.Children {
			if !pe.evaluateCondition(child, request) {
				return false
			}
		}
		return true

	case ConditionOr:
		for _, child := range condition.Children {
			if pe.evaluateCondition(child, request) {
				return true
			}
		}
		return false

	case ConditionNot:
		if len(condition.Children) == 1 {
			return !pe.evaluateCondition(condition.Children[0], request)
		}
		return false

	case ConditionPIIDetected:
		if request.Analysis != nil && request.Analysis.PIIDetection != nil {
			return request.Analysis.PIIDetection.HasPII
		}
		return false

	case ConditionSensitivityLevel:
		if request.Analysis != nil && request.Analysis.Classification != nil {
			return string(request.Analysis.Classification.Level) == condition.Value
		}
		return false

	case ConditionConfidenceAbove:
		if request.Analysis != nil {
			threshold, ok := condition.Value.(float64)
			if !ok {
				return false
			}
			return request.Analysis.Confidence > threshold
		}
		return false

	case ConditionRiskLevel:
		if request.Analysis != nil {
			return request.Analysis.OverallRiskLevel == condition.Value
		}
		return false

	// Enhanced basic conditions with improved handling
	case ConditionEquals:
		return pe.evaluateBasicComparison(condition, request, "equals")
	case ConditionNotEquals:
		return !pe.evaluateBasicComparison(condition, request, "equals")
	case ConditionContains:
		return pe.evaluateBasicComparison(condition, request, "contains")
	case ConditionNotContains:
		return !pe.evaluateBasicComparison(condition, request, "contains")
	case ConditionStartsWith:
		return pe.evaluateBasicComparison(condition, request, "starts_with")
	case ConditionEndsWith:
		return pe.evaluateBasicComparison(condition, request, "ends_with")
	case ConditionGreaterThan:
		return pe.evaluateBasicComparison(condition, request, "greater_than")
	case ConditionLessThan:
		return pe.evaluateBasicComparison(condition, request, "less_than")

	default:
		return false
	}
}

// shouldUseAdvancedEvaluator determines if a condition should use the advanced evaluator
func (pe *PolicyEngine) shouldUseAdvancedEvaluator(condition *PolicyCondition) bool {
	// Use advanced evaluator for regex conditions
	if condition.Regex {
		return true
	}
	
	// Use advanced evaluator for complex string/expression conditions
	if value, ok := condition.Value.(string); ok {
		if strings.HasPrefix(value, "expr:") || 
		   strings.HasPrefix(value, "fn:") || 
		   strings.HasPrefix(value, "regex:") {
			return true
		}
	}
	
	// Use advanced evaluator for specific condition types
	switch condition.Type {
	case "regex_match", "regex_find", "regex_extract",
		 "ml_classify", "ml_score", "ml_sentiment",
		 "expression", "formula", "function",
		 "string_length", "string_words", "string_lines",
		 "math_expression", "statistical":
		return true
	}
	
	return false
}

// evaluateBasicComparison handles basic comparison operations
func (pe *PolicyEngine) evaluateBasicComparison(condition *PolicyCondition, request *PolicyEvaluationRequest, operation string) bool {
	fieldValue := pe.getFieldValueFromRequest(condition.Field, request)
	
	switch operation {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", condition.Value)
	case "contains":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		valueStr := fmt.Sprintf("%v", condition.Value)
		if condition.CaseSensitive {
			return strings.Contains(fieldStr, valueStr)
		}
		return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))
	case "starts_with":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		valueStr := fmt.Sprintf("%v", condition.Value)
		if condition.CaseSensitive {
			return strings.HasPrefix(fieldStr, valueStr)
		}
		return strings.HasPrefix(strings.ToLower(fieldStr), strings.ToLower(valueStr))
	case "ends_with":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		valueStr := fmt.Sprintf("%v", condition.Value)
		if condition.CaseSensitive {
			return strings.HasSuffix(fieldStr, valueStr)
		}
		return strings.HasSuffix(strings.ToLower(fieldStr), strings.ToLower(valueStr))
	case "greater_than":
		fieldNum := pe.toFloat64(fieldValue)
		valueNum := pe.toFloat64(condition.Value)
		return fieldNum > valueNum
	case "less_than":
		fieldNum := pe.toFloat64(fieldValue)
		valueNum := pe.toFloat64(condition.Value)
		return fieldNum < valueNum
	default:
		return false
	}
}

// getFieldValueFromRequest extracts a field value from the request
func (pe *PolicyEngine) getFieldValueFromRequest(fieldName string, request *PolicyEvaluationRequest) interface{} {
	if fieldName == "" || fieldName == "content" {
		return request.Content
	}
	
	switch fieldName {
	case "content_type":
		return request.ContentType
	case "source":
		return request.Source
	case "user":
		return request.User
	case "organization":
		return request.Organization
	case "timestamp":
		return request.Timestamp
	default:
		// Check request context
		if request.Context != nil {
			if value, exists := request.Context[fieldName]; exists {
				return value
			}
		}
		// Check analysis results
		if request.Analysis != nil {
			return pe.getFieldFromAnalysis(fieldName, request.Analysis)
		}
	}
	
	return nil
}

// getFieldFromAnalysis extracts a field from analysis results
func (pe *PolicyEngine) getFieldFromAnalysis(fieldName string, analysis interface{}) interface{} {
	// This would need to be implemented based on the actual analysis structure
	// For now, return nil
	return nil
}

// toFloat64 converts a value to float64 for numeric comparisons
func (pe *PolicyEngine) toFloat64(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

// resolveConflicts resolves conflicts between matched policies using advanced conflict resolver
func (pe *PolicyEngine) resolveConflicts(matches []PolicyMatch, result *PolicyEvaluationResult) PolicyDecision {
	if len(matches) == 0 {
		// No matches, use default allow
		return PolicyDecision{
			Action:     ActionAllow,
			Reason:     "No policies matched",
			Confidence: 1.0,
			Severity:   SeverityInfo,
		}
	}

	if len(matches) == 1 {
		// Single match, use its action
		match := matches[0]
		return PolicyDecision{
			Action:     match.Action.Type,
			Reason:     fmt.Sprintf("Policy '%s' matched", match.PolicyName),
			Confidence: match.Confidence,
			Severity:   match.Action.Severity,
			Message:    match.Action.Message,
			Parameters: match.Action.Parameters,
		}
	}

	// Use sophisticated conflict resolver for multiple matches
	request := &PolicyEvaluationRequest{
		ID: result.RequestID,
		// We don't have the full request context here, but the resolver
		// can work with the matches and basic information
	}
	
	decision, conflictAnalysis, err := pe.conflictResolver.ResolveConflicts(matches, request)
	if err != nil {
		// Fallback to simple most restrictive rule
		return pe.resolveFallback(matches)
	}
	
	// Store conflict analysis in result metadata
	if conflictAnalysis != nil {
		// Convert ConflictingPolicyPair to PolicyConflict for compatibility
		var conflicts []PolicyConflict
		for _, pair := range conflictAnalysis.ConflictingPolicies {
			conflicts = append(conflicts, PolicyConflict{
				Type:        pair.ConflictType,
				PolicyIDs:   []string{pair.Policy1.PolicyID, pair.Policy2.PolicyID},
				PolicyNames: []string{pair.Policy1.PolicyName, pair.Policy2.PolicyName},
				Description: pair.Description,
				Severity:    pair.Severity,
			})
		}
		result.Conflicts = conflicts
		
		// Convert ConflictRecommendation to strings for compatibility
		var recommendations []string
		for _, rec := range conflictAnalysis.Recommendations {
			recommendations = append(recommendations, rec.Description)
		}
		result.Recommendations = recommendations
		
		if result.Metadata == nil {
			result.Metadata = make(map[string]interface{})
		}
		result.Metadata["conflict_analysis"] = conflictAnalysis
	}
	
	return *decision
}

// resolveFallback provides fallback conflict resolution
func (pe *PolicyEngine) resolveFallback(matches []PolicyMatch) PolicyDecision {
	// Fallback to simple most restrictive rule
	mostRestrictive := pe.findMostRestrictiveAction(matches)

	return PolicyDecision{
		Action:     mostRestrictive.Action.Type,
		Reason:     fmt.Sprintf("Most restrictive policy '%s' applied (fallback)", mostRestrictive.PolicyName),
		Confidence: mostRestrictive.Confidence * 0.8, // Reduce confidence for fallback
		Severity:   mostRestrictive.Action.Severity,
		Message:    mostRestrictive.Action.Message,
		Parameters: mostRestrictive.Action.Parameters,
	}
}

// findMostRestrictiveAction finds the most restrictive action among matches
func (pe *PolicyEngine) findMostRestrictiveAction(matches []PolicyMatch) PolicyMatch {
	// Priority order: Block > Quarantine > Redact > Mask > Warn > Allow
	actionPriorities := map[ActionType]int{
		ActionBlock:      100,
		ActionQuarantine: 90,
		ActionRedact:     80,
		ActionMask:       70,
		ActionWarn:       60,
		ActionLog:        50,
		ActionAllow:      10,
	}

	mostRestrictive := matches[0]
	highestPriority := actionPriorities[mostRestrictive.Action.Type]

	for _, match := range matches[1:] {
		priority := actionPriorities[match.Action.Type]
		if priority > highestPriority {
			mostRestrictive = match
			highestPriority = priority
		}
	}

	return mostRestrictive
}

// calculateOverallConfidence calculates overall confidence from matches
func (pe *PolicyEngine) calculateOverallConfidence(matches []PolicyMatch) float64 {
	if len(matches) == 0 {
		return 1.0
	}

	totalConfidence := 0.0
	for _, match := range matches {
		totalConfidence += match.Confidence
	}

	return totalConfidence / float64(len(matches))
}

// ValidatePolicy validates a policy using the engine's validator
func (pe *PolicyEngine) ValidatePolicy(policy *Policy) *PolicyValidationResult {
	return pe.validator.ValidatePolicy(policy)
}

// CreateSamplePolicies creates sample policies for demonstration
func CreateSamplePolicies() []*Policy {
	return []*Policy{
		{
			ID:          "pii-protection-policy",
			Name:        "PII Protection Policy",
			Description: "Blocks content containing high-confidence PII",
			Version:     "1.0.0",
			Status:      PolicyStatusActive,
			Priority:    100,
			Category:    "security",
			Owner:       "security-team",
			CreatedBy:   "admin",
			Rules: []PolicyRule{
				{
					ID:          "block-high-confidence-pii",
					Name:        "Block High Confidence PII",
					Description: "Block requests with high confidence PII detection",
					Priority:    10,
					Enabled:     true,
					Condition: &PolicyCondition{
						Type:     ConditionAnd,
						Children: []*PolicyCondition{
							{
								Type:  ConditionPIIDetected,
								Value: true,
							},
							{
								Type:  ConditionConfidenceAbove,
								Value: 0.9,
							},
						},
					},
					Action: PolicyAction{
						Type:     ActionBlock,
						Severity: SeverityHigh,
						Message:  "Request blocked due to high-confidence PII detection",
					},
				},
			},
			DefaultAction: PolicyAction{
				Type:     ActionAllow,
				Severity: SeverityInfo,
			},
		},
		{
			ID:          "content-classification-policy", 
			Name:        "Content Classification Policy",
			Description: "Redacts confidential content",
			Version:     "1.0.0",
			Status:      PolicyStatusActive,
			Priority:    90,
			Category:    "compliance",
			Owner:       "compliance-team",
			CreatedBy:   "admin",
			Rules: []PolicyRule{
				{
					ID:          "redact-confidential",
					Name:        "Redact Confidential Content",
					Description: "Redact content classified as confidential",
					Priority:    10,
					Enabled:     true,
					Condition: &PolicyCondition{
						Type:  ConditionSensitivityLevel,
						Value: "confidential",
					},
					Action: PolicyAction{
						Type:     ActionRedact,
						Severity: SeverityMedium,
						Message:  "Content redacted due to confidential classification",
					},
				},
			},
			DefaultAction: PolicyAction{
				Type:     ActionAllow,
				Severity: SeverityInfo,
			},
		},
	}
}

// SetConflictResolutionStrategy sets the conflict resolution strategy
func (pe *PolicyEngine) SetConflictResolutionStrategy(strategy ConflictResolutionStrategy) {
	if pe.conflictResolver != nil {
		pe.conflictResolver.config.DefaultStrategy = strategy
	}
}

// GetConflictMetrics returns conflict resolution metrics
func (pe *PolicyEngine) GetConflictMetrics() *ConflictMetrics {
	if pe.conflictResolver != nil {
		return pe.conflictResolver.GetMetrics()
	}
	return nil
}

// AnalyzeConflicts analyzes potential conflicts without making a decision
func (pe *PolicyEngine) AnalyzeConflicts(matches []PolicyMatch) (*ConflictAnalysis, error) {
	if pe.conflictResolver == nil {
		return nil, fmt.Errorf("conflict resolver not initialized")
	}
	
	request := &PolicyEvaluationRequest{
		ID: "analysis-only",
	}
	
	_, analysis, err := pe.conflictResolver.ResolveConflicts(matches, request)
	return analysis, err
} 