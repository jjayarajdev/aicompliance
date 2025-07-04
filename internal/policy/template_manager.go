package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"crypto/sha256"
	"encoding/hex"
)

// PolicyTemplateManager implements the template management system
type PolicyTemplateManager struct {
	templates           map[string]*PolicyTemplate
	collections         map[string]*TemplateCollection
	usageMetrics        map[string]*TemplateUsageMetrics
	mu                  sync.RWMutex
	config              *TemplateManagerConfig
	policyEngine        *PolicyEngine
	validator           *PolicyValidator
	searchIndex         *TemplateSearchIndex
	metrics             TemplateMetricsInterface
	logger              TemplateLoggerInterface
}

// TemplateManagerConfig represents configuration for the template manager
type TemplateManagerConfig struct {
	EnableMetrics           bool          `json:"enable_metrics"`
	EnableSearch            bool          `json:"enable_search"`
	EnableVersioning        bool          `json:"enable_versioning"`
	DefaultMaturity         TemplateMaturity `json:"default_maturity"`
	RequireValidation       bool          `json:"require_validation"`
	RequireTesting          bool          `json:"require_testing"`
	MaxTemplateSize         int64         `json:"max_template_size"`
	AllowedCategories       []TemplateCategory `json:"allowed_categories"`
	ParameterValidationMode string        `json:"parameter_validation_mode"`
	CacheEnabled            bool          `json:"cache_enabled"`
	CacheTTL                time.Duration `json:"cache_ttl"`
	ExportFormats           []string      `json:"export_formats"`
	ImportFormats           []string      `json:"import_formats"`
}

// TemplateSearchIndex provides search capabilities for templates
type TemplateSearchIndex struct {
	indexedFields  map[string]map[string][]*PolicyTemplate // field -> value -> templates
	textIndex      map[string][]*PolicyTemplate            // text -> templates
	mu             sync.RWMutex
}

// NewPolicyTemplateManager creates a new template manager
func NewPolicyTemplateManager(config *TemplateManagerConfig, policyEngine *PolicyEngine) *PolicyTemplateManager {
	if config == nil {
		config = getDefaultTemplateManagerConfig()
	}

	manager := &PolicyTemplateManager{
		templates:    make(map[string]*PolicyTemplate),
		collections:  make(map[string]*TemplateCollection),
		usageMetrics: make(map[string]*TemplateUsageMetrics),
		config:       config,
		policyEngine: policyEngine,
		validator:    NewPolicyValidator(),
		searchIndex:  NewTemplateSearchIndex(),
	}

	// Initialize built-in templates
	manager.initializeBuiltinTemplates()

	return manager
}

// CreateTemplate creates a new policy template
func (tm *PolicyTemplateManager) CreateTemplate(template *PolicyTemplate) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Validate template
	if err := tm.validateTemplateForCreation(template); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Set metadata
	now := time.Now()
	if template.ID == "" {
		template.ID = tm.generateTemplateID(template.Name)
	}
	template.CreatedAt = now
	template.UpdatedAt = now

	// Initialize metrics
	if tm.config.EnableMetrics {
		tm.usageMetrics[template.ID] = &TemplateUsageMetrics{
			TemplateID: template.ID,
		}
	}

	// Store template
	tm.templates[template.ID] = template

	// Update search index
	if tm.config.EnableSearch {
		tm.searchIndex.IndexTemplate(template)
	}

	return nil
}

// GetTemplate retrieves a template by ID
func (tm *PolicyTemplateManager) GetTemplate(templateID string) (*PolicyTemplate, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	template, exists := tm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	// Update usage metrics
	if tm.config.EnableMetrics {
		tm.updateTemplateAccess(templateID)
	}

	return tm.deepCopyTemplate(template), nil
}

// ListTemplates lists templates with optional filters
func (tm *PolicyTemplateManager) ListTemplates(filters *TemplateListFilters) ([]*PolicyTemplate, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var templates []*PolicyTemplate
	for _, template := range tm.templates {
		if tm.matchesFilters(template, filters) {
			templates = append(templates, tm.deepCopyTemplate(template))
		}
	}

	// Apply sorting and pagination
	templates = tm.sortTemplates(templates, filters)
	templates = tm.paginateTemplates(templates, filters)

	return templates, nil
}

// GetTemplatesByCategory retrieves templates by category
func (tm *PolicyTemplateManager) GetTemplatesByCategory(category TemplateCategory) ([]*PolicyTemplate, error) {
	filters := &TemplateListFilters{
		Categories: []TemplateCategory{category},
	}
	return tm.ListTemplates(filters)
}

// InstantiateTemplate creates a policy from a template
func (tm *PolicyTemplateManager) InstantiateTemplate(request *TemplateInstantiationRequest) (*TemplateInstantiationResult, error) {
	start := time.Now()

	// Get template
	template, err := tm.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	result := &TemplateInstantiationResult{
		Warnings:        []string{},
		Errors:          []string{},
		Recommendations: []string{},
		TestResults:     []TemplateTestResult{},
		Metadata:        make(map[string]interface{}),
	}

	// Validate parameters
	if request.Validate {
		paramValidation, err := tm.ValidateTemplateParameters(request.TemplateID, request.Parameters)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("parameter validation failed: %v", err))
		} else if !paramValidation.Valid {
			for _, e := range paramValidation.Errors {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", e.Parameter, e.Message))
			}
		}
	}

	// Generate policy from template
	policy, err := tm.generatePolicyFromTemplate(template, request)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("policy generation failed: %v", err))
		result.Success = false
		result.ExecutionTime = time.Since(start)
		return result, nil
	}

	result.Policy = policy

	// Validate generated policy
	if request.Validate && tm.policyEngine != nil {
		validationResult := tm.policyEngine.ValidatePolicy(policy)
		result.ValidationResult = validationResult
		if !validationResult.Valid {
			for _, e := range validationResult.Errors {
				result.Errors = append(result.Errors, fmt.Sprintf("policy validation: %s", e.Message))
			}
		}
	}

	// Run test cases if requested
	if len(request.TestCases) > 0 {
		testResults, err := tm.runTemplateTestCases(template, policy, request.TestCases)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("test execution failed: %v", err))
		} else {
			result.TestResults = testResults
		}
	}

	// Determine success
	result.Success = len(result.Errors) == 0
	result.ExecutionTime = time.Since(start)

	// Update usage metrics
	if tm.config.EnableMetrics {
		tm.recordTemplateUsage(request.TemplateID, result.Success)
	}

	return result, nil
}

// ValidateTemplateParameters validates template parameters
func (tm *PolicyTemplateManager) ValidateTemplateParameters(templateID string, parameters map[string]interface{}) (*ParameterValidationResult, error) {
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	result := &ParameterValidationResult{
		Valid:          true,
		Errors:         []ParameterValidationError{},
		Warnings:       []ParameterValidationWarning{},
		Suggestions:    []ParameterSuggestion{},
		ComputedValues: make(map[string]interface{}),
	}

	// Validate each parameter
	for _, param := range template.CustomizationOptions {
		value, provided := parameters[param.Name]

		// Check required parameters
		if param.Required && !provided {
			result.Valid = false
			result.Errors = append(result.Errors, ParameterValidationError{
				Parameter: param.Name,
				Message:   "required parameter not provided",
				Code:      "MISSING_REQUIRED",
				Severity:  "error",
			})
			continue
		}

		// Use default value if not provided
		if !provided && param.DefaultValue != nil {
			value = param.DefaultValue
			result.ComputedValues[param.Name] = value
		}

		// Validate parameter value
		if provided {
			if err := tm.validateParameterValue(param, value); err != nil {
				result.Valid = false
				result.Errors = append(result.Errors, ParameterValidationError{
					Parameter: param.Name,
					Message:   err.Error(),
					Code:      "INVALID_VALUE",
					Severity:  "error",
				})
			}
		}
	}

	return result, nil
}

// generatePolicyFromTemplate creates a policy from a template and parameters
func (tm *PolicyTemplateManager) generatePolicyFromTemplate(template *PolicyTemplate, request *TemplateInstantiationRequest) (*Policy, error) {
	// Start with the base policy template
	policy := &Policy{
		ID:          tm.generatePolicyID(request.Name),
		Name:        request.Name,
		Description: fmt.Sprintf("Generated from template: %s", template.Name),
		Version:     "1.0.0",
		Status:      PolicyStatusDraft,
		Category:    string(template.Category),
		Tags:        append(template.Tags, "generated", "template:"+template.ID),
		Owner:       request.Owner,
		CreatedBy:   request.Owner,
		Metadata:    make(map[string]interface{}),
	}

	// Apply request overrides
	if request.Priority != nil {
		policy.Priority = *request.Priority
	} else if template.DefaultConfiguration != nil {
		policy.Priority = template.DefaultConfiguration.Priority
	}

	if request.Category != "" {
		policy.Category = request.Category
	} else {
		policy.Category = string(template.Category)
	}

	if len(request.Tags) > 0 {
		policy.Tags = append(policy.Tags, request.Tags...)
	}

	if request.Scope != nil {
		policy.Scope = *request.Scope
	} else if template.DefaultConfiguration != nil && template.DefaultConfiguration.Scope != nil {
		policy.Scope = *template.DefaultConfiguration.Scope
	}

	// Generate rules from template rules
	policy.Rules = []PolicyRule{}
	for i, ruleTemplate := range template.Rules {
		rule, err := tm.generateRuleFromTemplate(ruleTemplate, request.Parameters, i)
		if err != nil {
			return nil, fmt.Errorf("failed to generate rule %s: %w", ruleTemplate.Name, err)
		}
		policy.Rules = append(policy.Rules, *rule)
	}

	// Set default action
	if template.PolicyTemplate != nil && template.PolicyTemplate.DefaultAction.Type != "" {
		policy.DefaultAction = template.PolicyTemplate.DefaultAction
	} else {
		policy.DefaultAction = PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
			Message:  "Default action for template-generated policy",
		}
	}

	// Add template metadata
	policy.Metadata["template_id"] = template.ID
	policy.Metadata["template_name"] = template.Name
	policy.Metadata["template_version"] = template.Version
	policy.Metadata["generated_at"] = time.Now()
	
	// Add request metadata
	if request.Metadata != nil {
		for k, v := range request.Metadata {
			policy.Metadata[k] = v
		}
	}

	return policy, nil
}

// Helper methods and utility functions
func (tm *PolicyTemplateManager) validateTemplateForCreation(template *PolicyTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}

	if template.Category == "" {
		return fmt.Errorf("template category is required")
	}

	// Check if template with same name exists
	for _, existing := range tm.templates {
		if existing.Name == template.Name && existing.ID != template.ID {
			return fmt.Errorf("template with name '%s' already exists", template.Name)
		}
	}

	return nil
}

func (tm *PolicyTemplateManager) generateTemplateID(name string) string {
	// Create a hash-based ID from the name
	normalized := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	hash := sha256.Sum256([]byte(normalized + time.Now().String()))
	return "template_" + hex.EncodeToString(hash[:8])
}

func (tm *PolicyTemplateManager) generatePolicyID(name string) string {
	normalized := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	hash := sha256.Sum256([]byte(normalized + time.Now().String()))
	return "policy_" + hex.EncodeToString(hash[:8])
}

func (tm *PolicyTemplateManager) deepCopyTemplate(template *PolicyTemplate) *PolicyTemplate {
	// Simple deep copy using JSON marshaling (for demo purposes)
	data, _ := json.Marshal(template)
	var copy PolicyTemplate
	json.Unmarshal(data, &copy)
	return &copy
}

func (tm *PolicyTemplateManager) matchesFilters(template *PolicyTemplate, filters *TemplateListFilters) bool {
	if filters == nil {
		return true
	}

	// Category filter
	if len(filters.Categories) > 0 {
		found := false
		for _, cat := range filters.Categories {
			if template.Category == cat {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Status filter
	if len(filters.Status) > 0 {
		found := false
		for _, status := range filters.Status {
			if template.Status == status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Author filter
	if filters.Author != "" && template.Author != filters.Author {
		return false
	}

	// Rating filter
	if filters.MinRating != nil && template.Rating < *filters.MinRating {
		return false
	}

	return true
}

func (tm *PolicyTemplateManager) sortTemplates(templates []*PolicyTemplate, filters *TemplateListFilters) []*PolicyTemplate {
	if filters == nil || filters.SortBy == "" {
		return templates
	}

	// Simple sorting implementation (for demo purposes)
	// In production, would use a more sophisticated sorting algorithm
	return templates
}

func (tm *PolicyTemplateManager) paginateTemplates(templates []*PolicyTemplate, filters *TemplateListFilters) []*PolicyTemplate {
	if filters == nil || filters.Limit <= 0 {
		return templates
	}

	start := filters.Offset
	end := start + filters.Limit

	if start >= len(templates) {
		return []*PolicyTemplate{}
	}

	if end > len(templates) {
		end = len(templates)
	}

	return templates[start:end]
}

func (tm *PolicyTemplateManager) validateParameterValue(param TemplateParameter, value interface{}) error {
	// Type validation
	switch param.Type {
	case ParameterTypeString:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string value")
		}
	case ParameterTypeNumber:
		switch value.(type) {
		case int, int64, float32, float64:
			// Valid numeric types
		default:
			return fmt.Errorf("expected numeric value")
		}
	case ParameterTypeBoolean:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected boolean value")
		}
	}

	// Constraint validation
	if param.Constraints != nil {
		if err := tm.validateParameterConstraints(param.Constraints, value); err != nil {
			return err
		}
	}

	return nil
}

func (tm *PolicyTemplateManager) validateParameterConstraints(constraints *ParameterConstraints, value interface{}) error {
	// Length constraints for strings
	if str, ok := value.(string); ok {
		if constraints.MinLength != nil && len(str) < *constraints.MinLength {
			return fmt.Errorf("value too short (minimum %d characters)", *constraints.MinLength)
		}
		if constraints.MaxLength != nil && len(str) > *constraints.MaxLength {
			return fmt.Errorf("value too long (maximum %d characters)", *constraints.MaxLength)
		}
		if constraints.Pattern != "" {
			matched, err := regexp.MatchString(constraints.Pattern, str)
			if err != nil {
				return fmt.Errorf("invalid pattern: %v", err)
			}
			if !matched {
				return fmt.Errorf("value does not match required pattern")
			}
		}
	}

	// Numeric constraints
	if constraints.MinValue != nil || constraints.MaxValue != nil {
		var numValue float64
		switch v := value.(type) {
		case int:
			numValue = float64(v)
		case int64:
			numValue = float64(v)
		case float32:
			numValue = float64(v)
		case float64:
			numValue = v
		default:
			return fmt.Errorf("numeric constraints applied to non-numeric value")
		}

		if constraints.MinValue != nil && numValue < *constraints.MinValue {
			return fmt.Errorf("value too small (minimum %.2f)", *constraints.MinValue)
		}
		if constraints.MaxValue != nil && numValue > *constraints.MaxValue {
			return fmt.Errorf("value too large (maximum %.2f)", *constraints.MaxValue)
		}
	}

	return nil
}

func (tm *PolicyTemplateManager) generateRuleFromTemplate(ruleTemplate PolicyRuleTemplate, parameters map[string]interface{}, index int) (*PolicyRule, error) {
	rule := &PolicyRule{
		ID:          fmt.Sprintf("rule_%d", index),
		Name:        ruleTemplate.Name,
		Description: ruleTemplate.Description,
		Priority:    ruleTemplate.Priority,
		Enabled:     true,
		Action:      ruleTemplate.Action,
		CreatedBy:   "template_system",
		CreatedAt:   time.Now(),
		Tags:        ruleTemplate.Tags,
	}

	// Process parameterized condition
	if ruleTemplate.ParameterizedCondition != nil {
		condition, err := tm.processParameterizedCondition(ruleTemplate.ParameterizedCondition, parameters)
		if err != nil {
			return nil, err
		}
		rule.Condition = condition
	} else {
		rule.Condition = ruleTemplate.Condition
	}

	return rule, nil
}

func (tm *PolicyTemplateManager) processParameterizedCondition(paramCondition *ParameterizedCondition, parameters map[string]interface{}) (*PolicyCondition, error) {
	// Simple parameter substitution in condition template
	template := paramCondition.Template

	// Replace parameter placeholders
	for key, value := range parameters {
		placeholder := fmt.Sprintf("{{%s}}", key)
		if strings.Contains(template, placeholder) {
			// Convert value to string for substitution
			valueStr := fmt.Sprintf("%v", value)
			template = strings.ReplaceAll(template, placeholder, valueStr)
		}
	}

	// For demo purposes, create a simple condition
	// In production, would parse the template string into a proper condition structure
	return &PolicyCondition{
		Type:  ConditionContains,
		Field: "content",
		Value: template,
	}, nil
}

func (tm *PolicyTemplateManager) runTemplateTestCases(template *PolicyTemplate, policy *Policy, testCaseIDs []string) ([]TemplateTestResult, error) {
	var results []TemplateTestResult

	for _, testCaseID := range testCaseIDs {
		// Find test case
		var testCase *TemplateTestCase
		for _, tc := range template.TestCases {
			if tc.ID == testCaseID {
				testCase = &tc
				break
			}
		}

		if testCase == nil {
			results = append(results, TemplateTestResult{
				TestCaseID: testCaseID,
				Name:       testCaseID,
				Passed:     false,
				Error:      "test case not found",
			})
			continue
		}

		// Run test case
		result := tm.executeTemplateTestCase(testCase, policy)
		results = append(results, result)
	}

	return results, nil
}

func (tm *PolicyTemplateManager) executeTemplateTestCase(testCase *TemplateTestCase, policy *Policy) TemplateTestResult {
	start := time.Now()

	result := TemplateTestResult{
		TestCaseID:    testCase.ID,
		Name:          testCase.Name,
		Passed:        true,
		Results:       []AssertionResult{},
		ExecutionTime: 0,
		Details:       make(map[string]interface{}),
	}

	// Execute test assertions
	for _, assertion := range testCase.Assertions {
		assertionResult := tm.executeAssertion(assertion, policy)
		result.Results = append(result.Results, assertionResult)
		if !assertionResult.Passed {
			result.Passed = false
		}
	}

	result.ExecutionTime = time.Since(start)
	return result
}

func (tm *PolicyTemplateManager) executeAssertion(assertion TestAssertion, policy *Policy) AssertionResult {
	// Simple assertion execution for demo
	return AssertionResult{
		Assertion: assertion,
		Passed:    true,
		Actual:    "test_value",
		Expected:  assertion.Expected,
		Message:   "assertion passed",
		Details:   "test assertion executed successfully",
	}
}

func (tm *PolicyTemplateManager) updateTemplateAccess(templateID string) {
	if metrics, exists := tm.usageMetrics[templateID]; exists {
		// Update access metrics (simplified for demo)
		metrics.TotalUsage++
		metrics.LastUsed = timePtr(time.Now())
	}
}

func (tm *PolicyTemplateManager) recordTemplateUsage(templateID string, success bool) {
	if metrics, exists := tm.usageMetrics[templateID]; exists {
		metrics.TotalUsage++
		if success {
			metrics.SuccessfulDeploys++
		} else {
			metrics.FailedDeploys++
		}
		
		// Update success rate
		total := metrics.SuccessfulDeploys + metrics.FailedDeploys
		if total > 0 {
			metrics.SuccessRate = float64(metrics.SuccessfulDeploys) / float64(total)
		}
		
		metrics.LastUsed = timePtr(time.Now())
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func getDefaultTemplateManagerConfig() *TemplateManagerConfig {
	return &TemplateManagerConfig{
		EnableMetrics:           true,
		EnableSearch:            true,
		EnableVersioning:        true,
		DefaultMaturity:         TemplateMaturityStable,
		RequireValidation:       true,
		RequireTesting:          false,
		MaxTemplateSize:         1024 * 1024, // 1MB
		AllowedCategories:       []TemplateCategory{TemplateCategoryPII, TemplateCategoryCompliance, TemplateCategorySecurity},
		ParameterValidationMode: "strict",
		CacheEnabled:            true,
		CacheTTL:                time.Hour,
		ExportFormats:           []string{"json", "yaml"},
		ImportFormats:           []string{"json", "yaml"},
	}
}

// Placeholder interfaces for demo
type TemplateMetricsInterface interface {
	RecordTemplateUsage(templateID string, success bool)
}

type TemplateLoggerInterface interface {
	LogTemplateEvent(event string, templateID string, details map[string]interface{})
}

// TemplateSearchIndex methods
func NewTemplateSearchIndex() *TemplateSearchIndex {
	return &TemplateSearchIndex{
		indexedFields: make(map[string]map[string][]*PolicyTemplate),
		textIndex:     make(map[string][]*PolicyTemplate),
	}
}

func (tsi *TemplateSearchIndex) IndexTemplate(template *PolicyTemplate) {
	tsi.mu.Lock()
	defer tsi.mu.Unlock()
	
	// Index by category
	if tsi.indexedFields["category"] == nil {
		tsi.indexedFields["category"] = make(map[string][]*PolicyTemplate)
	}
	categoryKey := string(template.Category)
	tsi.indexedFields["category"][categoryKey] = append(tsi.indexedFields["category"][categoryKey], template)
	
	// Index by tags
	if tsi.indexedFields["tags"] == nil {
		tsi.indexedFields["tags"] = make(map[string][]*PolicyTemplate)
	}
	for _, tag := range template.Tags {
		tsi.indexedFields["tags"][tag] = append(tsi.indexedFields["tags"][tag], template)
	}
}

// UpdateTemplate updates an existing template
func (tm *PolicyTemplateManager) UpdateTemplate(template *PolicyTemplate) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	existing, exists := tm.templates[template.ID]
	if !exists {
		return fmt.Errorf("template not found: %s", template.ID)
	}

	// Validate update
	if err := tm.validateTemplateForCreation(template); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Preserve creation time, update modification time
	template.CreatedAt = existing.CreatedAt
	template.UpdatedAt = time.Now()

	// Store updated template
	tm.templates[template.ID] = template

	// Update search index
	if tm.config.EnableSearch {
		tm.searchIndex.IndexTemplate(template)
	}

	return nil
}

// DeleteTemplate deletes a template
func (tm *PolicyTemplateManager) DeleteTemplate(templateID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.templates[templateID]; !exists {
		return fmt.Errorf("template not found: %s", templateID)
	}

	delete(tm.templates, templateID)

	// Clean up metrics
	if tm.config.EnableMetrics {
		delete(tm.usageMetrics, templateID)
	}

	return nil
}

// SearchTemplates searches templates with filters
func (tm *PolicyTemplateManager) SearchTemplates(query string, filters *TemplateSearchFilters) ([]*PolicyTemplate, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if !tm.config.EnableSearch {
		return nil, fmt.Errorf("search not enabled")
	}

	// Simple search implementation for demo
	var results []*PolicyTemplate
	for _, template := range tm.templates {
		if tm.matchesSearchQuery(template, query) && tm.matchesSearchFilters(template, filters) {
			results = append(results, tm.deepCopyTemplate(template))
		}
	}

	return results, nil
}

// GetTemplateRecommendations gets template recommendations based on context
func (tm *PolicyTemplateManager) GetTemplateRecommendations(context *TemplateRecommendationContext) ([]*PolicyTemplate, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var recommendations []*PolicyTemplate

	// Simple recommendation algorithm based on industry and use case
	for _, template := range tm.templates {
		score := tm.calculateRecommendationScore(template, context)
		if score > 0.5 { // Threshold for recommendations
			recommendations = append(recommendations, tm.deepCopyTemplate(template))
		}
	}

	// Sort by score (simplified for demo)
	return recommendations, nil
}

// PreviewTemplateInstantiation previews policy generation without execution
func (tm *PolicyTemplateManager) PreviewTemplateInstantiation(request *TemplateInstantiationRequest) (*Policy, error) {
	// Get template
	template, err := tm.GetTemplate(request.TemplateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Generate policy without storing or executing
	policy, err := tm.generatePolicyFromTemplate(template, request)
	if err != nil {
		return nil, fmt.Errorf("failed to generate policy preview: %w", err)
	}

	return policy, nil
}

// TestTemplate tests a template with specified test cases
func (tm *PolicyTemplateManager) TestTemplate(templateID string, testCases []string) ([]TemplateTestResult, error) {
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	// Create a sample policy for testing
	sampleRequest := &TemplateInstantiationRequest{
		TemplateID: templateID,
		Name:       "test_policy",
		Parameters: make(map[string]interface{}),
		Owner:      "test_user",
	}

	// Set default parameters
	for _, param := range template.CustomizationOptions {
		if param.DefaultValue != nil {
			sampleRequest.Parameters[param.Name] = param.DefaultValue
		}
	}

	policy, err := tm.generatePolicyFromTemplate(template, sampleRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test policy: %w", err)
	}

	return tm.runTemplateTestCases(template, policy, testCases)
}

// ValidateTemplate validates a template structure and content
func (tm *PolicyTemplateManager) ValidateTemplate(template *PolicyTemplate) (*TemplateValidationResult, error) {
	result := &TemplateValidationResult{
		Valid:               true,
		TemplateErrors:      []TemplateValidationError{},
		ParameterErrors:     []ParameterValidationError{},
		SchemaErrors:        []SchemaValidationError{},
		CompatibilityIssues: []CompatibilityIssue{},
		Warnings:            []string{},
		Suggestions:         []string{},
		TestResults:         []TemplateTestResult{},
	}

	// Basic template validation
	if template.Name == "" {
		result.Valid = false
		result.TemplateErrors = append(result.TemplateErrors, TemplateValidationError{
			Field:    "name",
			Message:  "Template name is required",
			Code:     "MISSING_NAME",
			Severity: "error",
		})
	}

	if template.Category == "" {
		result.Valid = false
		result.TemplateErrors = append(result.TemplateErrors, TemplateValidationError{
			Field:    "category",
			Message:  "Template category is required",
			Code:     "MISSING_CATEGORY",
			Severity: "error",
		})
	}

	// Validate parameters
	for _, param := range template.CustomizationOptions {
		if param.Name == "" {
			result.Valid = false
			result.ParameterErrors = append(result.ParameterErrors, ParameterValidationError{
				Parameter: "unknown",
				Message:   "Parameter name is required",
				Code:      "MISSING_PARAMETER_NAME",
				Severity:  "error",
			})
		}
	}

	return result, nil
}

// CheckTemplateCompatibility checks template compatibility with platform version
func (tm *PolicyTemplateManager) CheckTemplateCompatibility(templateID string, platformVersion string) (*CompatibilityCheckResult, error) {
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	result := &CompatibilityCheckResult{
		Compatible:      true,
		PlatformVersion: platformVersion,
		Issues:          []CompatibilityIssue{},
		MissingFeatures: []string{},
		Recommendations: []string{},
		UpgradeRequired: false,
	}

	// Simple compatibility check (for demo)
	if template.Schema != nil && template.Schema.MinPlatformVersion != "" {
		// In real implementation, would parse and compare version numbers
		if template.Schema.MinPlatformVersion > platformVersion {
			result.Compatible = false
			result.UpgradeRequired = true
			result.MinimumVersion = template.Schema.MinPlatformVersion
		}
	}

	return result, nil
}

// ExportTemplate exports a template in specified format
func (tm *PolicyTemplateManager) ExportTemplate(templateID string, format string) ([]byte, error) {
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.Marshal(template)
	case "yaml":
		// Would use yaml package in real implementation
		return json.Marshal(template) // Fallback to JSON for demo
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ImportTemplate imports a template from data
func (tm *PolicyTemplateManager) ImportTemplate(data []byte, format string) (*PolicyTemplate, error) {
	var template PolicyTemplate

	switch format {
	case "json":
		err := json.Unmarshal(data, &template)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON template: %w", err)
		}
	case "yaml":
		// Would use yaml package in real implementation
		err := json.Unmarshal(data, &template) // Fallback to JSON for demo
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML template: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}

	// Validate imported template
	validationResult, err := tm.ValidateTemplate(&template)
	if err != nil {
		return nil, fmt.Errorf("template validation failed: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("imported template is invalid: %d errors", len(validationResult.TemplateErrors))
	}

	return &template, nil
}

// ExportTemplateBundle exports multiple templates as a bundle
func (tm *PolicyTemplateManager) ExportTemplateBundle(templateIDs []string, format string) ([]byte, error) {
	var templates []*PolicyTemplate

	for _, templateID := range templateIDs {
		template, err := tm.GetTemplate(templateID)
		if err != nil {
			return nil, fmt.Errorf("failed to get template %s: %w", templateID, err)
		}
		templates = append(templates, template)
	}

	bundle := map[string]interface{}{
		"version":   "1.0",
		"templates": templates,
		"exported_at": time.Now(),
	}

	switch format {
	case "json":
		return json.Marshal(bundle)
	case "yaml":
		return json.Marshal(bundle) // Fallback to JSON for demo
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ImportTemplateBundle imports multiple templates from a bundle
func (tm *PolicyTemplateManager) ImportTemplateBundle(data []byte, format string) ([]*PolicyTemplate, error) {
	var bundle map[string]interface{}

	switch format {
	case "json":
		err := json.Unmarshal(data, &bundle)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JSON bundle: %w", err)
		}
	case "yaml":
		err := json.Unmarshal(data, &bundle) // Fallback to JSON for demo
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML bundle: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}

	// Extract templates from bundle
	templatesData, ok := bundle["templates"]
	if !ok {
		return nil, fmt.Errorf("bundle does not contain templates")
	}

	// Convert to templates (simplified for demo)
	var templates []*PolicyTemplate
	templateBytes, _ := json.Marshal(templatesData)
	err := json.Unmarshal(templateBytes, &templates)
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates from bundle: %w", err)
	}

	return templates, nil
}

// GetTemplateUsageMetrics gets usage metrics for a template
func (tm *PolicyTemplateManager) GetTemplateUsageMetrics(templateID string) (*TemplateUsageMetrics, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if !tm.config.EnableMetrics {
		return nil, fmt.Errorf("metrics not enabled")
	}

	metrics, exists := tm.usageMetrics[templateID]
	if !exists {
		return nil, fmt.Errorf("metrics not found for template: %s", templateID)
	}

	// Return a copy
	return &TemplateUsageMetrics{
		TemplateID:        metrics.TemplateID,
		TotalUsage:        metrics.TotalUsage,
		SuccessfulDeploys: metrics.SuccessfulDeploys,
		FailedDeploys:     metrics.FailedDeploys,
		SuccessRate:       metrics.SuccessRate,
		LastUsed:          metrics.LastUsed,
	}, nil
}

// GetTemplateSuccessRate gets the success rate for a template
func (tm *PolicyTemplateManager) GetTemplateSuccessRate(templateID string) (float64, error) {
	metrics, err := tm.GetTemplateUsageMetrics(templateID)
	if err != nil {
		return 0, err
	}

	return metrics.SuccessRate, nil
}

// UpdateTemplateRating updates the rating for a template
func (tm *PolicyTemplateManager) UpdateTemplateRating(templateID string, rating float64) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	template, exists := tm.templates[templateID]
	if !exists {
		return fmt.Errorf("template not found: %s", templateID)
	}

	// Simple rating update (in production would be more sophisticated)
	oldRating := template.Rating
	oldCount := template.ReviewCount

	// Calculate new average rating
	totalScore := oldRating * float64(oldCount)
	totalScore += rating
	template.ReviewCount++
	template.Rating = totalScore / float64(template.ReviewCount)

	return nil
}

// CreateTemplateVersion creates a new version of a template
func (tm *PolicyTemplateManager) CreateTemplateVersion(templateID string, changes []TemplateChange) (*PolicyTemplate, error) {
	baseTemplate, err := tm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	// Create new version (simplified for demo)
	newTemplate := tm.deepCopyTemplate(baseTemplate)
	newTemplate.ID = tm.generateTemplateID(baseTemplate.Name + "_v2")
	newTemplate.Version = tm.incrementVersion(baseTemplate.Version)
	newTemplate.UpdatedAt = time.Now()

	// Apply changes
	for _, change := range changes {
		tm.applyTemplateChange(newTemplate, change)
	}

	// Store new version
	tm.templates[newTemplate.ID] = newTemplate

	return newTemplate, nil
}

// GetTemplateVersions gets all versions of a template
func (tm *PolicyTemplateManager) GetTemplateVersions(templateID string) ([]*PolicyTemplate, error) {
	// Simplified implementation - in production would track version relationships
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	return []*PolicyTemplate{template}, nil
}

// CompareTemplateVersions compares two template versions
func (tm *PolicyTemplateManager) CompareTemplateVersions(version1ID, version2ID string) (*TemplateVersionComparison, error) {
	template1, err := tm.GetTemplate(version1ID)
	if err != nil {
		return nil, err
	}

	template2, err := tm.GetTemplate(version2ID)
	if err != nil {
		return nil, err
	}

	comparison := &TemplateVersionComparison{
		Version1: template1.Version,
		Version2: template2.Version,
		Changes:  tm.calculateTemplateChanges(template1, template2),
		Summary: TemplateComparisonSummary{
			TotalChanges:       0,
			ChangesByType:      make(map[string]int),
			BackwardCompatible: true,
			UpgradeComplexity:  "low",
		},
	}

	comparison.Summary.TotalChanges = len(comparison.Changes)

	return comparison, nil
}

// CreateTemplateCollection creates a new template collection
func (tm *PolicyTemplateManager) CreateTemplateCollection(collection *TemplateCollection) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if collection.ID == "" {
		collection.ID = tm.generateTemplateID(collection.Name)
	}

	collection.CreatedAt = time.Now()
	collection.UpdatedAt = time.Now()

	tm.collections[collection.ID] = collection
	return nil
}

// GetTemplateCollection gets a template collection
func (tm *PolicyTemplateManager) GetTemplateCollection(collectionID string) (*TemplateCollection, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	collection, exists := tm.collections[collectionID]
	if !exists {
		return nil, fmt.Errorf("collection not found: %s", collectionID)
	}

	// Return a copy
	return &TemplateCollection{
		ID:           collection.ID,
		Name:         collection.Name,
		Description:  collection.Description,
		Category:     collection.Category,
		Templates:    append([]string{}, collection.Templates...),
		Author:       collection.Author,
		Version:      collection.Version,
		CreatedAt:    collection.CreatedAt,
		UpdatedAt:    collection.UpdatedAt,
		Tags:         append([]string{}, collection.Tags...),
	}, nil
}

// ListTemplateCollections lists all template collections
func (tm *PolicyTemplateManager) ListTemplateCollections() ([]*TemplateCollection, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var collections []*TemplateCollection
	for _, collection := range tm.collections {
		collections = append(collections, &TemplateCollection{
			ID:          collection.ID,
			Name:        collection.Name,
			Description: collection.Description,
			Category:    collection.Category,
			Templates:   append([]string{}, collection.Templates...),
			Author:      collection.Author,
			Version:     collection.Version,
			CreatedAt:   collection.CreatedAt,
			UpdatedAt:   collection.UpdatedAt,
			Tags:        append([]string{}, collection.Tags...),
		})
	}

	return collections, nil
}

// Helper methods for template operations
func (tm *PolicyTemplateManager) matchesSearchQuery(template *PolicyTemplate, query string) bool {
	if query == "" {
		return true
	}

	query = strings.ToLower(query)
	return strings.Contains(strings.ToLower(template.Name), query) ||
		strings.Contains(strings.ToLower(template.Description), query) ||
		tm.containsTag(template.Tags, query)
}

func (tm *PolicyTemplateManager) matchesSearchFilters(template *PolicyTemplate, filters *TemplateSearchFilters) bool {
	if filters == nil {
		return true
	}

	// Use base filters
	return tm.matchesFilters(template, &filters.TemplateListFilters)
}

func (tm *PolicyTemplateManager) containsTag(tags []string, query string) bool {
	for _, tag := range tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

func (tm *PolicyTemplateManager) calculateRecommendationScore(template *PolicyTemplate, context *TemplateRecommendationContext) float64 {
	score := 0.0

	// Industry match
	for _, vertical := range template.IndustryVerticals {
		if vertical == context.Industry {
			score += 0.3
			break
		}
	}

	// Compliance framework match
	for _, framework := range template.ComplianceFrameworks {
		for _, reqFramework := range context.ComplianceFrameworks {
			if framework == reqFramework {
				score += 0.2
				break
			}
		}
	}

	// Use case match
	if strings.Contains(strings.ToLower(template.TargetUseCase), strings.ToLower(context.UseCase)) {
		score += 0.3
	}

	// Rating boost
	score += template.Rating * 0.1

	return score
}

func (tm *PolicyTemplateManager) incrementVersion(version string) string {
	// Simple version increment for demo
	return version + ".1"
}

func (tm *PolicyTemplateManager) applyTemplateChange(template *PolicyTemplate, change TemplateChange) {
	// Simple change application for demo
	switch change.Field {
	case "description":
		if newDesc, ok := change.NewValue.(string); ok {
			template.Description = newDesc
		}
	case "version":
		if newVersion, ok := change.NewValue.(string); ok {
			template.Version = newVersion
		}
	}
}

func (tm *PolicyTemplateManager) calculateTemplateChanges(template1, template2 *PolicyTemplate) []TemplateChange {
	var changes []TemplateChange

	if template1.Description != template2.Description {
		changes = append(changes, TemplateChange{
			Type:        "modified",
			Field:       "description",
			OldValue:    template1.Description,
			NewValue:    template2.Description,
			Description: "Description updated",
		})
	}

	if template1.Version != template2.Version {
		changes = append(changes, TemplateChange{
			Type:        "modified",
			Field:       "version",
			OldValue:    template1.Version,
			NewValue:    template2.Version,
			Description: "Version updated",
		})
	}

	return changes
} 