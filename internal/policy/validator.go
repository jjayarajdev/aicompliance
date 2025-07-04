package policy

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NewPolicyValidator creates a new policy validator with default schema
func NewPolicyValidator() *PolicyValidator {
	return &PolicyValidator{
		schema:           getDefaultPolicySchema(),
		customValidators: getDefaultCustomValidators(),
	}
}

// ValidatePolicy validates a policy against the schema
func (v *PolicyValidator) ValidatePolicy(policy *Policy) *PolicyValidationResult {
	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Suggestions: []ValidationSuggestion{},
	}

	// Validate required fields
	v.validateRequiredFields(policy, result)
	
	// Validate field types and constraints
	v.validateFieldTypes(policy, result)
	
	// Validate policy structure
	v.validatePolicyStructure(policy, result)
	
	// Validate rules
	v.validateRules(policy, result)
	
	// Validate actions
	v.validateActions(policy, result)
	
	// Run custom validations
	v.runCustomValidations(policy, result)
	
	// Generate suggestions
	v.generateSuggestions(policy, result)

	result.Valid = len(result.Errors) == 0

	return result
}

// ValidateRule validates a single policy rule
func (v *PolicyValidator) ValidateRule(rule *PolicyRule) *PolicyValidationResult {
	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Suggestions: []ValidationSuggestion{},
	}

	// Validate rule structure
	if rule.ID == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "id",
			Message:  "Rule ID is required",
			Code:     "REQUIRED_FIELD",
			Severity: "error",
		})
	}

	if rule.Name == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "name",
			Message:  "Rule name is required",
			Code:     "REQUIRED_FIELD",
			Severity: "error",
		})
	}

	// Validate condition
	if rule.Condition != nil {
		conditionResult := v.validateCondition(rule.Condition)
		result.Errors = append(result.Errors, conditionResult.Errors...)
		result.Warnings = append(result.Warnings, conditionResult.Warnings...)
	}

	// Validate action
	actionResult := v.validateAction(&rule.Action)
	result.Errors = append(result.Errors, actionResult.Errors...)
	result.Warnings = append(result.Warnings, actionResult.Warnings...)

	result.Valid = len(result.Errors) == 0
	return result
}

// ValidateCondition validates a policy condition recursively
func (v *PolicyValidator) ValidateCondition(condition *PolicyCondition) *PolicyValidationResult {
	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Suggestions: []ValidationSuggestion{},
	}

	conditionResult := v.validateCondition(condition)
	result.Errors = append(result.Errors, conditionResult.Errors...)
	result.Warnings = append(result.Warnings, conditionResult.Warnings...)
	result.Valid = len(result.Errors) == 0

	return result
}

// validateCondition validates a condition structure
func (v *PolicyValidator) validateCondition(condition *PolicyCondition) *PolicyValidationResult {
	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Suggestions: []ValidationSuggestion{},
	}

	if condition == nil {
		return result
	}

	// Validate condition type
	if !v.isValidConditionType(condition.Type) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "type",
			Message:  fmt.Sprintf("Invalid condition type: %s", condition.Type),
			Code:     "INVALID_CONDITION_TYPE",
			Severity: "error",
		})
	}

	// Validate logical conditions
	if condition.Type == ConditionAnd || condition.Type == ConditionOr {
		if len(condition.Children) < 2 {
			result.Errors = append(result.Errors, ValidationError{
				Field:    "children",
				Message:  fmt.Sprintf("%s condition requires at least 2 children", condition.Type),
				Code:     "INSUFFICIENT_CHILDREN",
				Severity: "error",
			})
		}

		// Recursively validate children
		for i, child := range condition.Children {
			childResult := v.validateCondition(child)
			for _, err := range childResult.Errors {
				err.Field = fmt.Sprintf("children[%d].%s", i, err.Field)
				result.Errors = append(result.Errors, err)
			}
		}
	}

	// Only validate field requirement for certain conditions that actually need fields
	if v.requiresField(condition.Type) {
		if condition.Field == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:    "field",
				Message:  "Field is required for field-based conditions",
				Code:     "REQUIRED_FIELD",
				Severity: "error",
			})
		}
	}

	return result
}

// requiresField checks if a condition type requires a field
func (v *PolicyValidator) requiresField(condType ConditionType) bool {
	// These conditions work on analysis results directly and don't need explicit fields
	analysisConditions := []ConditionType{
		ConditionPIIDetected, ConditionSensitivityLevel, ConditionConfidenceAbove,
		ConditionRiskLevel, ConditionEntityCount, ConditionSentiment, ConditionBusinessCategory,
	}
	
	for _, analysisType := range analysisConditions {
		if condType == analysisType {
			return false
		}
	}
	
	// These conditions require explicit fields
	fieldRequiredConditions := []ConditionType{
		ConditionEquals, ConditionNotEquals, ConditionContains, ConditionNotContains,
		ConditionStartsWith, ConditionEndsWith, ConditionMatches, ConditionNotMatches,
		ConditionGreaterThan, ConditionLessThan, ConditionIn, ConditionNotIn,
	}
	
	for _, fieldType := range fieldRequiredConditions {
		if condType == fieldType {
			return true
		}
	}
	
	return false
}

// validateAction validates a policy action
func (v *PolicyValidator) validateAction(action *PolicyAction) *PolicyValidationResult {
	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Suggestions: []ValidationSuggestion{},
	}

	// Validate action type
	if !v.isValidActionType(action.Type) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "type",
			Message:  fmt.Sprintf("Invalid action type: %s", action.Type),
			Code:     "INVALID_ACTION_TYPE",
			Severity: "error",
		})
	}

	// Validate action severity
	if !v.isValidActionSeverity(action.Severity) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "severity",
			Message:  fmt.Sprintf("Invalid action severity: %s", action.Severity),
			Code:     "INVALID_SEVERITY",
			Severity: "error",
		})
	}

	// Validate webhook configuration
	if action.Type == ActionWebhook && action.Webhook != nil {
		webhookResult := v.validateWebhookConfig(action.Webhook)
		result.Errors = append(result.Errors, webhookResult.Errors...)
		result.Warnings = append(result.Warnings, webhookResult.Warnings...)
	}

	// Validate custom handler
	if action.Type == ActionCustom && action.CustomHandler == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "custom_handler",
			Message:  "Custom handler is required for custom action type",
			Code:     "REQUIRED_FIELD",
			Severity: "error",
		})
	}

	return result
}

// validateWebhookConfig validates webhook configuration
func (v *PolicyValidator) validateWebhookConfig(webhook *WebhookConfig) *PolicyValidationResult {
	result := &PolicyValidationResult{
		Valid:       true,
		Errors:      []ValidationError{},
		Warnings:    []ValidationWarning{},
		Suggestions: []ValidationSuggestion{},
	}

	if webhook.URL == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "webhook.url",
			Message:  "Webhook URL is required",
			Code:     "REQUIRED_FIELD",
			Severity: "error",
		})
	}

	if webhook.Method == "" {
		webhook.Method = "POST" // Default to POST
	} else if !v.isValidHTTPMethod(webhook.Method) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "webhook.method",
			Message:  fmt.Sprintf("Invalid HTTP method: %s", webhook.Method),
			Code:     "INVALID_HTTP_METHOD",
			Severity: "error",
		})
	}

	if webhook.Timeout <= 0 {
		webhook.Timeout = 30 * time.Second // Default timeout
	}

	if webhook.RetryCount < 0 {
		webhook.RetryCount = 0
	}

	return result
}

// validateRequiredFields validates required policy fields
func (v *PolicyValidator) validateRequiredFields(policy *Policy, result *PolicyValidationResult) {
	requiredFields := v.schema.RequiredFields
	
	policyValue := reflect.ValueOf(policy).Elem()
	policyType := policyValue.Type()

	for _, fieldName := range requiredFields {
		field, found := policyType.FieldByName(fieldName)
		if !found {
			continue
		}

		fieldValue := policyValue.FieldByName(fieldName)
		if v.isEmptyValue(fieldValue) {
			result.Errors = append(result.Errors, ValidationError{
				Field:    strings.ToLower(field.Tag.Get("json")),
				Message:  fmt.Sprintf("Field '%s' is required", fieldName),
				Code:     "REQUIRED_FIELD",
				Severity: "error",
			})
		}
	}
}

// validateFieldTypes validates field types and constraints
func (v *PolicyValidator) validateFieldTypes(policy *Policy, result *PolicyValidationResult) {
	// Validate priority
	if policy.Priority < 0 || policy.Priority > 1000 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "priority",
			Message: "Priority should be between 0 and 1000",
			Code:    "INVALID_RANGE",
		})
	}

	// Validate version format
	if policy.Version != "" && !v.isValidVersionFormat(policy.Version) {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "version",
			Message: "Version should follow semantic versioning (e.g., 1.0.0)",
			Code:    "INVALID_FORMAT",
		})
	}

	// Validate status
	if !v.isValidPolicyStatus(policy.Status) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "status",
			Message:  fmt.Sprintf("Invalid policy status: %s", policy.Status),
			Code:     "INVALID_STATUS",
			Severity: "error",
		})
	}
}

// validatePolicyStructure validates the overall policy structure
func (v *PolicyValidator) validatePolicyStructure(policy *Policy, result *PolicyValidationResult) {
	// Check for duplicate rule IDs
	ruleIDs := make(map[string]bool)
	for i, rule := range policy.Rules {
		if ruleIDs[rule.ID] {
			result.Errors = append(result.Errors, ValidationError{
				Field:    fmt.Sprintf("rules[%d].id", i),
				Message:  fmt.Sprintf("Duplicate rule ID: %s", rule.ID),
				Code:     "DUPLICATE_ID",
				Severity: "error",
			})
		}
		ruleIDs[rule.ID] = true
	}

	// Validate rule priorities
	if len(policy.Rules) > 1 {
		for i := 0; i < len(policy.Rules)-1; i++ {
			for j := i + 1; j < len(policy.Rules); j++ {
				if policy.Rules[i].Priority == policy.Rules[j].Priority {
					result.Warnings = append(result.Warnings, ValidationWarning{
						Field:   fmt.Sprintf("rules[%d].priority", j),
						Message: "Multiple rules have the same priority",
						Code:    "DUPLICATE_PRIORITY",
					})
				}
			}
		}
	}

	// Validate effective dates
	if policy.EffectiveAt != nil && policy.ExpiresAt != nil {
		if policy.EffectiveAt.After(*policy.ExpiresAt) {
			result.Errors = append(result.Errors, ValidationError{
				Field:    "effective_at",
				Message:  "Effective date cannot be after expiration date",
				Code:     "INVALID_DATE_RANGE",
				Severity: "error",
			})
		}
	}
}

// validateRules validates all rules in a policy
func (v *PolicyValidator) validateRules(policy *Policy, result *PolicyValidationResult) {
	if len(policy.Rules) == 0 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "rules",
			Message: "Policy has no rules defined",
			Code:    "NO_RULES",
		})
	}

	for i, rule := range policy.Rules {
		ruleResult := v.ValidateRule(&rule)
		for _, err := range ruleResult.Errors {
			err.Field = fmt.Sprintf("rules[%d].%s", i, err.Field)
			result.Errors = append(result.Errors, err)
		}
		for _, warning := range ruleResult.Warnings {
			warning.Field = fmt.Sprintf("rules[%d].%s", i, warning.Field)
			result.Warnings = append(result.Warnings, warning)
		}
	}
}

// validateActions validates actions in rules
func (v *PolicyValidator) validateActions(policy *Policy, result *PolicyValidationResult) {
	// Validate default action
	defaultActionResult := v.validateAction(&policy.DefaultAction)
	for _, err := range defaultActionResult.Errors {
		err.Field = fmt.Sprintf("default_action.%s", err.Field)
		result.Errors = append(result.Errors, err)
	}
}

// runCustomValidations runs custom validation functions
func (v *PolicyValidator) runCustomValidations(policy *Policy, result *PolicyValidationResult) {
	for _, validation := range v.schema.CustomValidations {
		if validator, exists := v.customValidators[validation.Function]; exists {
			fieldValue := v.getFieldValue(policy, validation.Field)
			if err := validator(fieldValue, validation.Parameters); err != nil {
				result.Errors = append(result.Errors, ValidationError{
					Field:    validation.Field,
					Message:  validation.ErrorMessage,
					Code:     "CUSTOM_VALIDATION",
					Severity: "error",
				})
			}
		}
	}
}

// generateSuggestions generates helpful suggestions for policy improvement
func (v *PolicyValidator) generateSuggestions(policy *Policy, result *PolicyValidationResult) {
	// Suggest adding description if missing
	if policy.Description == "" {
		result.Suggestions = append(result.Suggestions, ValidationSuggestion{
			Field:      "description",
			Message:    "Consider adding a description for better documentation",
			Suggestion: "Add a clear description of what this policy does",
		})
	}

	// Suggest adding tags if missing
	if len(policy.Tags) == 0 {
		result.Suggestions = append(result.Suggestions, ValidationSuggestion{
			Field:      "tags",
			Message:    "Consider adding tags for better organization",
			Suggestion: "Add relevant tags like 'security', 'compliance', etc.",
		})
	}

	// Suggest rule organization
	if len(policy.Rules) > 5 {
		result.Suggestions = append(result.Suggestions, ValidationSuggestion{
			Field:      "rules",
			Message:    "Consider splitting large policies into smaller, focused policies",
			Suggestion: "Break down into multiple policies by category or function",
		})
	}
}

// Helper methods for validation

func (v *PolicyValidator) isValidConditionType(condType ConditionType) bool {
	validTypes := []ConditionType{
		ConditionEquals, ConditionNotEquals, ConditionContains, ConditionNotContains,
		ConditionStartsWith, ConditionEndsWith, ConditionMatches, ConditionNotMatches,
		ConditionGreaterThan, ConditionGreaterEqual, ConditionLessThan, ConditionLessEqual,
		ConditionBetween, ConditionNotBetween, ConditionIn, ConditionNotIn,
		ConditionEmpty, ConditionNotEmpty, ConditionCount, ConditionAnd, ConditionOr,
		ConditionNot, ConditionAny, ConditionAll, ConditionNone, ConditionPIIDetected,
		ConditionSensitivityLevel, ConditionConfidenceAbove, ConditionRiskLevel,
		ConditionEntityCount, ConditionSentiment, ConditionBusinessCategory,
	}

	for _, valid := range validTypes {
		if condType == valid {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isValidActionType(actionType ActionType) bool {
	validTypes := []ActionType{
		ActionAllow, ActionBlock, ActionWarn, ActionLog, ActionRedact, ActionMask,
		ActionTokenize, ActionSanitize, ActionRoute, ActionQueue, ActionDelay,
		ActionRetry, ActionQuarantine, ActionFlag, ActionEncrypt, ActionAudit,
		ActionCustom, ActionWebhook,
	}

	for _, valid := range validTypes {
		if actionType == valid {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isValidActionSeverity(severity ActionSeverity) bool {
	validSeverities := []ActionSeverity{
		SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical,
	}

	for _, valid := range validSeverities {
		if severity == valid {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isValidPolicyStatus(status PolicyStatus) bool {
	validStatuses := []PolicyStatus{
		PolicyStatusDraft, PolicyStatusActive, PolicyStatusInactive,
		PolicyStatusArchived, PolicyStatusTesting,
	}

	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isValidHTTPMethod(method string) bool {
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	method = strings.ToUpper(method)
	
	for _, valid := range validMethods {
		if method == valid {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isFieldBasedCondition(condType ConditionType) bool {
	fieldBasedTypes := []ConditionType{
		ConditionEquals, ConditionNotEquals, ConditionContains, ConditionNotContains,
		ConditionStartsWith, ConditionEndsWith, ConditionMatches, ConditionNotMatches,
		ConditionGreaterThan, ConditionGreaterEqual, ConditionLessThan, ConditionLessEqual,
		ConditionBetween, ConditionNotBetween, ConditionIn, ConditionNotIn,
		ConditionEmpty, ConditionNotEmpty, ConditionCount, ConditionPIIDetected,
		ConditionSensitivityLevel, ConditionConfidenceAbove, ConditionRiskLevel,
		ConditionEntityCount, ConditionSentiment, ConditionBusinessCategory,
	}

	for _, fieldType := range fieldBasedTypes {
		if condType == fieldType {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isNumericCondition(condType ConditionType) bool {
	numericTypes := []ConditionType{
		ConditionGreaterThan, ConditionGreaterEqual, ConditionLessThan,
		ConditionLessEqual, ConditionBetween, ConditionNotBetween,
		ConditionCount, ConditionConfidenceAbove, ConditionEntityCount,
	}

	for _, numType := range numericTypes {
		if condType == numType {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isValidAnalysisField(field string) bool {
	validFields := []string{
		"pii_detection.has_pii", "pii_detection.matches", "pii_detection.statistics.confidence_avg",
		"classification.level", "classification.confidence", "ml_analysis.confidence_score",
		"ml_analysis.business_categories", "ml_analysis.entities.count", "ml_analysis.sentiment.overall",
		"overall_risk_level", "confidence", "processing_time_ms",
	}

	for _, valid := range validFields {
		if field == valid {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isNumericValue(value interface{}) bool {
	switch value.(type) {
	case int, int8, int16, int32, int64:
		return true
	case uint, uint8, uint16, uint32, uint64:
		return true
	case float32, float64:
		return true
	case string:
		if _, err := strconv.ParseFloat(value.(string), 64); err == nil {
			return true
		}
	}
	return false
}

func (v *PolicyValidator) isValidVersionFormat(version string) bool {
	// Simple semantic version check (major.minor.patch)
	pattern := `^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+)?$`
	matched, _ := regexp.MatchString(pattern, version)
	return matched
}

func (v *PolicyValidator) isEmptyValue(val reflect.Value) bool {
	switch val.Kind() {
	case reflect.String:
		return val.Len() == 0
	case reflect.Slice, reflect.Map, reflect.Array:
		return val.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return val.IsNil()
	default:
		return false
	}
}

func (v *PolicyValidator) getFieldValue(policy *Policy, fieldPath string) interface{} {
	// Simple field extraction - in production, use reflection or JSONPath
	parts := strings.Split(fieldPath, ".")
	
	policyValue := reflect.ValueOf(policy).Elem()
	
	for _, part := range parts {
		if policyValue.Kind() == reflect.Ptr {
			if policyValue.IsNil() {
				return nil
			}
			policyValue = policyValue.Elem()
		}
		
		if policyValue.Kind() == reflect.Struct {
			policyValue = policyValue.FieldByName(part)
			if !policyValue.IsValid() {
				return nil
			}
		}
	}
	
	return policyValue.Interface()
}

// getDefaultPolicySchema returns the default validation schema
func getDefaultPolicySchema() *PolicySchema {
	return &PolicySchema{
		RequiredFields: []string{"ID", "Name", "Status"},
		FieldTypes: map[string]string{
			"ID":          "string",
			"Name":        "string",
			"Description": "string",
			"Version":     "string",
			"Status":      "string",
			"Priority":    "int",
			"Category":    "string",
			"Owner":       "string",
			"CreatedBy":   "string",
		},
		FieldConstraints: map[string]FieldConstraint{
			"ID": {
				MinLength: intPtr(1),
				MaxLength: intPtr(50),
				Pattern:   "^[a-zA-Z0-9_-]+$",
				Required:  true,
			},
			"Name": {
				MinLength: intPtr(1),
				MaxLength: intPtr(100),
				Required:  true,
			},
			"Priority": {
				MinValue: float64Ptr(0),
				MaxValue: float64Ptr(1000),
			},
		},
		CustomValidations: []CustomValidation{
			{
				Name:         "unique_policy_id",
				Field:        "ID",
				Function:     "validate_unique_id",
				Parameters:   map[string]interface{}{},
				ErrorMessage: "Policy ID must be unique",
			},
		},
	}
}

// getDefaultCustomValidators returns default custom validation functions
func getDefaultCustomValidators() map[string]ValidatorFunc {
	return map[string]ValidatorFunc{
		"validate_unique_id": func(value interface{}, params map[string]interface{}) error {
			if str, ok := value.(string); ok {
				if len(str) == 0 {
					return fmt.Errorf("ID cannot be empty")
				}
				matched, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", str)
				if !matched {
					return fmt.Errorf("ID can only contain alphanumeric characters, underscores, and hyphens")
				}
			}
			return nil
		},
	}
}

// Helper functions for pointer creation
func intPtr(i int) *int {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
} 