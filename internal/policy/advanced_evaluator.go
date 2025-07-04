package policy

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// NewAdvancedConditionEvaluator creates a new advanced condition evaluator
func NewAdvancedConditionEvaluator(config *AdvancedEvaluatorConfig) *AdvancedConditionEvaluator {
	if config == nil {
		config = &AdvancedEvaluatorConfig{
			EnableRegexCaching:     true,
			EnableMLModels:         true,
			EnableExpressions:      true,
			RegexCacheSize:         1000,
			ExpressionCacheSize:    500,
			ModelCacheSize:         50,
			EvaluationTimeout:      5 * time.Second,
			MaxRegexComplexity:     10000,
			MaxExpressionDepth:     20,
			EnablePerformanceStats: true,
		}
	}

	evaluator := &AdvancedConditionEvaluator{
		regexCache:        make(map[string]*regexp.Regexp),
		mlModelCache:      make(map[string]MLModelInterface),
		functionRegistry:  make(map[string]BuiltinFunction),
		expressionCache:   make(map[string]*CompiledExpression),
		config:            config,
		performanceMetrics: &ConditionMetrics{
			FunctionCalls: make(map[string]int64),
			ErrorsByType:  make(map[string]int64),
		},
	}

	// Initialize built-in functions
	evaluator.initializeBuiltinFunctions()

	return evaluator
}

// EvaluateAdvancedCondition evaluates an advanced condition with comprehensive features
func (ace *AdvancedConditionEvaluator) EvaluateAdvancedCondition(condition *PolicyCondition, request *PolicyEvaluationRequest) (*ConditionEvaluationResult, error) {
	start := time.Now()

	// Create evaluation context
	ctx := &EvaluationContext{
		Request:         request,
		Variables:       make(map[string]interface{}),
		Functions:       make(map[string]interface{}),
		TrustedSources:  []string{},
		SecurityLevel:   SecurityLevelMedium,
		PerformanceMode: ace.config.EnablePerformanceStats,
	}

	// Set up context variables from request
	ace.setupContextVariables(ctx, request)

	// Evaluate with timeout
	timeoutCtx, cancel := context.WithTimeout(context.Background(), ace.config.EvaluationTimeout)
	defer cancel()

	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	// Channel for result to handle timeout
	resultChan := make(chan *ConditionEvaluationResult, 1)
	errorChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errorChan <- fmt.Errorf("panic during condition evaluation: %v", r)
			}
		}()

		evalResult, err := ace.doEvaluateCondition(ctx, condition)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- evalResult
	}()

	select {
	case result = <-resultChan:
		// Success
	case err := <-errorChan:
		result.ErrorMessage = err.Error()
		result.Matched = false
		ace.recordError("evaluation_error")
	case <-timeoutCtx.Done():
		result.ErrorMessage = "evaluation timeout"
		result.Matched = false
		ace.recordError("timeout")
	}

	// Record metrics
	result.ExecutionTime = time.Since(start)
	ace.recordEvaluation(result.ExecutionTime, result.ErrorMessage == "")

	return result, nil
}

// doEvaluateCondition performs the actual condition evaluation
func (ace *AdvancedConditionEvaluator) doEvaluateCondition(ctx *EvaluationContext, condition *PolicyCondition) (*ConditionEvaluationResult, error) {
	if condition == nil {
		return &ConditionEvaluationResult{
			Matched:    true,
			Confidence: 1.0,
			Details:    "No condition specified",
		}, nil
	}

	// Handle advanced condition types
	if advancedType := ace.getAdvancedConditionType(condition); advancedType != "" {
		return ace.evaluateAdvancedConditionType(ctx, condition, advancedType)
	}

	// Handle basic condition types
	return ace.evaluateBasicCondition(ctx, condition)
}

// getAdvancedConditionType determines if this is an advanced condition type
func (ace *AdvancedConditionEvaluator) getAdvancedConditionType(condition *PolicyCondition) AdvancedConditionType {
	// Check if the condition type matches an advanced condition
	switch condition.Type {
	case "regex_match", "regex_find", "regex_extract":
		return AdvancedConditionType(condition.Type)
	case "ml_classify", "ml_score", "ml_sentiment":
		return AdvancedConditionType(condition.Type)
	case "expression", "formula", "function":
		return AdvancedConditionType(condition.Type)
	}

	// Check if condition has regex flag
	if condition.Regex {
		return ConditionRegexMatch
	}

	// Check for expression in value
	if value, ok := condition.Value.(string); ok {
		if strings.HasPrefix(value, "expr:") || strings.HasPrefix(value, "fn:") {
			return ConditionExpression
		}
	}

	return ""
}

// evaluateAdvancedConditionType evaluates advanced condition types
func (ace *AdvancedConditionEvaluator) evaluateAdvancedConditionType(ctx *EvaluationContext, condition *PolicyCondition, advancedType AdvancedConditionType) (*ConditionEvaluationResult, error) {
	switch advancedType {
	case ConditionRegexMatch, ConditionRegexFind, ConditionRegexExtract:
		return ace.evaluateRegexCondition(ctx, condition, advancedType)
	case ConditionMLClassify, ConditionMLScore, ConditionMLSentiment:
		return ace.evaluateMLCondition(ctx, condition, advancedType)
	case ConditionExpression, ConditionFormula, ConditionFunction:
		return ace.evaluateExpressionCondition(ctx, condition, advancedType)
	case ConditionStringLength, ConditionStringWords, ConditionStringLines:
		return ace.evaluateStringCondition(ctx, condition, advancedType)
	case ConditionMathExpression, ConditionStatistical:
		return ace.evaluateMathCondition(ctx, condition, advancedType)
	default:
		return ace.evaluateBasicCondition(ctx, condition)
	}
}

// evaluateRegexCondition evaluates regex-based conditions
func (ace *AdvancedConditionEvaluator) evaluateRegexCondition(ctx *EvaluationContext, condition *PolicyCondition, conditionType AdvancedConditionType) (*ConditionEvaluationResult, error) {
	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	// Get the text to match against
	text := ace.getFieldValue(ctx, condition.Field)
	textStr, ok := text.(string)
	if !ok {
		return result, fmt.Errorf("field value is not a string for regex evaluation")
	}

	// Get regex pattern
	pattern, ok := condition.Value.(string)
	if !ok {
		return result, fmt.Errorf("regex pattern must be a string")
	}

	// Get or compile regex
	regex, err := ace.getCompiledRegex(pattern, condition.CaseSensitive)
	if err != nil {
		return result, fmt.Errorf("failed to compile regex: %v", err)
	}

	// Perform regex operation based on type
	switch conditionType {
	case ConditionRegexMatch:
		matched := regex.MatchString(textStr)
		result.Matched = matched
		result.Confidence = 1.0
		result.Value = matched
		result.Details = fmt.Sprintf("Regex pattern '%s' %s match text", pattern, map[bool]string{true: "did", false: "did not"}[matched])

	case ConditionRegexFind:
		matches := regex.FindAllString(textStr, -1)
		result.Matched = len(matches) > 0
		result.Confidence = 1.0
		result.Value = matches
		result.IntermediateResults["matches"] = matches
		result.IntermediateResults["match_count"] = len(matches)
		result.Details = fmt.Sprintf("Found %d matches with regex pattern '%s'", len(matches), pattern)

	case ConditionRegexExtract:
		submatches := regex.FindStringSubmatch(textStr)
		result.Matched = len(submatches) > 0
		result.Confidence = 1.0
		result.Value = submatches
		result.IntermediateResults["submatches"] = submatches
		if len(submatches) > 1 {
			result.IntermediateResults["captured_groups"] = submatches[1:]
		}
		result.Details = fmt.Sprintf("Extracted %d groups with regex pattern '%s'", len(submatches), pattern)
	}

	ace.recordRegexEvaluation()
	return result, nil
}

// evaluateMLCondition evaluates ML-based conditions
func (ace *AdvancedConditionEvaluator) evaluateMLCondition(ctx *EvaluationContext, condition *PolicyCondition, conditionType AdvancedConditionType) (*ConditionEvaluationResult, error) {
	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	// For demonstration, we'll implement a mock ML evaluation
	// In a real implementation, this would integrate with actual ML models
	text := ace.getFieldValue(ctx, condition.Field)
	textStr, ok := text.(string)
	if !ok {
		return result, fmt.Errorf("field value is not a string for ML evaluation")
	}

	switch conditionType {
	case ConditionMLClassify:
		// Mock classification - classify as sensitive/non-sensitive based on keywords
		sensitiveKeywords := []string{"confidential", "secret", "private", "personal", "ssn", "credit card"}
		sensitivity := 0.0
		matchedKeywords := []string{}
		
		lowerText := strings.ToLower(textStr)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(lowerText, keyword) {
				sensitivity += 0.3
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}
		
		if sensitivity > 1.0 {
			sensitivity = 1.0
		}
		
		threshold := 0.5
		if condition.Threshold != nil {
			threshold = *condition.Threshold
		}
		
		result.Matched = sensitivity >= threshold
		result.Confidence = sensitivity
		result.Value = map[string]interface{}{
			"classification": map[bool]string{true: "sensitive", false: "non-sensitive"}[result.Matched],
			"score":          sensitivity,
		}
		result.IntermediateResults["matched_keywords"] = matchedKeywords
		result.IntermediateResults["sensitivity_score"] = sensitivity
		result.Details = fmt.Sprintf("ML classification: %s (score: %.2f, threshold: %.2f)", 
			result.Value.(map[string]interface{})["classification"], sensitivity, threshold)

	case ConditionMLSentiment:
		// Mock sentiment analysis - simple keyword-based approach
		positiveWords := []string{"good", "great", "excellent", "positive", "happy", "love"}
		negativeWords := []string{"bad", "terrible", "awful", "negative", "sad", "hate"}
		
		lowerText := strings.ToLower(textStr)
		positiveCount := 0
		negativeCount := 0
		
		for _, word := range positiveWords {
			if strings.Contains(lowerText, word) {
				positiveCount++
			}
		}
		
		for _, word := range negativeWords {
			if strings.Contains(lowerText, word) {
				negativeCount++
			}
		}
		
		sentiment := "neutral"
		confidence := 0.5
		
		if positiveCount > negativeCount {
			sentiment = "positive"
			confidence = math.Min(0.5 + float64(positiveCount)*0.2, 1.0)
		} else if negativeCount > positiveCount {
			sentiment = "negative"
			confidence = math.Min(0.5 + float64(negativeCount)*0.2, 1.0)
		}
		
		expectedSentiment, ok := condition.Value.(string)
		result.Matched = ok && sentiment == expectedSentiment
		result.Confidence = confidence
		result.Value = sentiment
		result.IntermediateResults["positive_words"] = positiveCount
		result.IntermediateResults["negative_words"] = negativeCount
		result.Details = fmt.Sprintf("ML sentiment: %s (confidence: %.2f)", sentiment, confidence)

	case ConditionMLScore:
		// Mock ML scoring - length and complexity based scoring
		length := len(textStr)
		words := len(strings.Fields(textStr))
		complexityScore := float64(length) / 100.0
		if words > 0 {
			complexityScore += float64(length) / float64(words) / 10.0
		}
		
		if complexityScore > 1.0 {
			complexityScore = 1.0
		}
		
		threshold := 0.5
		if condition.Threshold != nil {
			threshold = *condition.Threshold
		}
		
		result.Matched = complexityScore >= threshold
		result.Confidence = complexityScore
		result.Value = complexityScore
		result.IntermediateResults["text_length"] = length
		result.IntermediateResults["word_count"] = words
		result.IntermediateResults["complexity_score"] = complexityScore
		result.Details = fmt.Sprintf("ML score: %.2f (threshold: %.2f)", complexityScore, threshold)
	}

	ace.recordMLEvaluation()
	return result, nil
}

// evaluateExpressionCondition evaluates expression-based conditions
func (ace *AdvancedConditionEvaluator) evaluateExpressionCondition(ctx *EvaluationContext, condition *PolicyCondition, conditionType AdvancedConditionType) (*ConditionEvaluationResult, error) {
	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	expression, ok := condition.Value.(string)
	if !ok {
		return result, fmt.Errorf("expression must be a string")
	}

	// Remove prefix if present
	if strings.HasPrefix(expression, "expr:") {
		expression = strings.TrimPrefix(expression, "expr:")
	} else if strings.HasPrefix(expression, "fn:") {
		expression = strings.TrimPrefix(expression, "fn:")
	}

	// Simple expression evaluation for demonstration
	switch conditionType {
	case ConditionExpression:
		evalResult, err := ace.evaluateSimpleExpression(ctx, expression)
		if err != nil {
			return result, err
		}
		
		// Convert result to boolean if possible
		if boolVal, ok := evalResult.(bool); ok {
			result.Matched = boolVal
		} else if numVal, ok := evalResult.(float64); ok {
			result.Matched = numVal > 0
		} else if strVal, ok := evalResult.(string); ok {
			result.Matched = strVal != ""
		} else {
			result.Matched = evalResult != nil
		}
		
		result.Confidence = 1.0
		result.Value = evalResult
		result.Details = fmt.Sprintf("Expression '%s' evaluated to: %v", expression, evalResult)

	case ConditionFunction:
		evalResult, err := ace.evaluateBuiltinFunction(ctx, expression)
		if err != nil {
			return result, err
		}
		
		if boolVal, ok := evalResult.(bool); ok {
			result.Matched = boolVal
		} else {
			result.Matched = evalResult != nil
		}
		
		result.Confidence = 1.0
		result.Value = evalResult
		result.Details = fmt.Sprintf("Function '%s' returned: %v", expression, evalResult)
	}

	ace.recordExpressionEvaluation()
	return result, nil
}

// evaluateStringCondition evaluates string-based advanced conditions
func (ace *AdvancedConditionEvaluator) evaluateStringCondition(ctx *EvaluationContext, condition *PolicyCondition, conditionType AdvancedConditionType) (*ConditionEvaluationResult, error) {
	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	text := ace.getFieldValue(ctx, condition.Field)
	textStr, ok := text.(string)
	if !ok {
		return result, fmt.Errorf("field value is not a string")
	}

	switch conditionType {
	case ConditionStringLength:
		length := len(textStr)
		expectedLength, ok := condition.Value.(float64)
		if !ok {
			if intVal, ok := condition.Value.(int); ok {
				expectedLength = float64(intVal)
			} else {
				return result, fmt.Errorf("expected length must be a number")
			}
		}
		
		result.Matched = float64(length) >= expectedLength
		result.Confidence = 1.0
		result.Value = length
		result.IntermediateResults["actual_length"] = length
		result.IntermediateResults["expected_length"] = expectedLength
		result.Details = fmt.Sprintf("String length: %d (expected >= %.0f)", length, expectedLength)

	case ConditionStringWords:
		words := strings.Fields(textStr)
		wordCount := len(words)
		expectedCount, ok := condition.Value.(float64)
		if !ok {
			if intVal, ok := condition.Value.(int); ok {
				expectedCount = float64(intVal)
			} else {
				return result, fmt.Errorf("expected word count must be a number")
			}
		}
		
		result.Matched = float64(wordCount) >= expectedCount
		result.Confidence = 1.0
		result.Value = wordCount
		result.IntermediateResults["actual_words"] = wordCount
		result.IntermediateResults["expected_words"] = expectedCount
		result.IntermediateResults["words"] = words
		result.Details = fmt.Sprintf("Word count: %d (expected >= %.0f)", wordCount, expectedCount)

	case ConditionStringLines:
		lines := strings.Split(textStr, "\n")
		lineCount := len(lines)
		expectedCount, ok := condition.Value.(float64)
		if !ok {
			if intVal, ok := condition.Value.(int); ok {
				expectedCount = float64(intVal)
			} else {
				return result, fmt.Errorf("expected line count must be a number")
			}
		}
		
		result.Matched = float64(lineCount) >= expectedCount
		result.Confidence = 1.0
		result.Value = lineCount
		result.IntermediateResults["actual_lines"] = lineCount
		result.IntermediateResults["expected_lines"] = expectedCount
		result.Details = fmt.Sprintf("Line count: %d (expected >= %.0f)", lineCount, expectedCount)
	}

	return result, nil
}

// evaluateMathCondition evaluates mathematical conditions
func (ace *AdvancedConditionEvaluator) evaluateMathCondition(ctx *EvaluationContext, condition *PolicyCondition, conditionType AdvancedConditionType) (*ConditionEvaluationResult, error) {
	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	switch conditionType {
	case ConditionMathExpression:
		expression, ok := condition.Value.(string)
		if !ok {
			return result, fmt.Errorf("math expression must be a string")
		}
		
		evalResult, err := ace.evaluateMathExpression(ctx, expression)
		if err != nil {
			return result, err
		}
		
		// Threshold comparison
		threshold := 0.0
		if condition.Threshold != nil {
			threshold = *condition.Threshold
		}
		
		result.Matched = evalResult >= threshold
		result.Confidence = 1.0
		result.Value = evalResult
		result.IntermediateResults["expression_result"] = evalResult
		result.IntermediateResults["threshold"] = threshold
		result.Details = fmt.Sprintf("Math expression result: %.2f (threshold: %.2f)", evalResult, threshold)

	case ConditionStatistical:
		// Mock statistical evaluation
		text := ace.getFieldValue(ctx, condition.Field)
		if textStr, ok := text.(string); ok {
			// Calculate some basic statistics
			length := len(textStr)
			words := len(strings.Fields(textStr))
			avgWordLength := 0.0
			if words > 0 {
				avgWordLength = float64(length) / float64(words)
			}
			
			result.Value = map[string]interface{}{
				"length":          length,
				"words":           words,
				"avg_word_length": avgWordLength,
			}
			
			threshold := 5.0 // Average word length threshold
			if condition.Threshold != nil {
				threshold = *condition.Threshold
			}
			
			result.Matched = avgWordLength >= threshold
			result.Confidence = 1.0
			result.IntermediateResults["statistics"] = result.Value
			result.Details = fmt.Sprintf("Statistical analysis: avg word length %.2f (threshold: %.2f)", avgWordLength, threshold)
		} else {
			return result, fmt.Errorf("field value is not a string for statistical analysis")
		}
	}

	return result, nil
}

// Helper methods for advanced condition evaluation

// getCompiledRegex gets or compiles a regex pattern with caching
func (ace *AdvancedConditionEvaluator) getCompiledRegex(pattern string, caseSensitive bool) (*regexp.Regexp, error) {
	cacheKey := pattern
	if !caseSensitive {
		cacheKey = "(?i)" + pattern
	}

	ace.mu.RLock()
	if regex, exists := ace.regexCache[cacheKey]; exists {
		ace.mu.RUnlock()
		ace.recordCacheHit()
		return regex, nil
	}
	ace.mu.RUnlock()

	// Compile regex
	finalPattern := pattern
	if !caseSensitive {
		finalPattern = "(?i)" + pattern
	}

	regex, err := regexp.Compile(finalPattern)
	if err != nil {
		return nil, err
	}

	// Cache the compiled regex
	ace.mu.Lock()
	if len(ace.regexCache) >= ace.config.RegexCacheSize {
		// Simple cache eviction - remove oldest (first) entry
		for k := range ace.regexCache {
			delete(ace.regexCache, k)
			break
		}
	}
	ace.regexCache[cacheKey] = regex
	ace.mu.Unlock()

	ace.recordCacheMiss()
	return regex, nil
}

// getFieldValue extracts a field value from the evaluation context
func (ace *AdvancedConditionEvaluator) getFieldValue(ctx *EvaluationContext, fieldName string) interface{} {
	if fieldName == "" || fieldName == "content" {
		return ctx.Request.Content
	}

	// Check context variables first
	if value, exists := ctx.Variables[fieldName]; exists {
		return value
	}

	// Check request fields
	switch fieldName {
	case "content_type":
		return ctx.Request.ContentType
	case "source":
		return ctx.Request.Source
	case "user":
		return ctx.Request.User
	case "organization":
		return ctx.Request.Organization
	default:
		// Check request context
		if ctx.Request.Context != nil {
			if value, exists := ctx.Request.Context[fieldName]; exists {
				return value
			}
		}
		
		// Check analysis results
		if ctx.Request.Analysis != nil {
			return ace.getAnalysisField(ctx.Request.Analysis, fieldName)
		}
	}

	return nil
}

// getAnalysisField extracts a field from analysis results
func (ace *AdvancedConditionEvaluator) getAnalysisField(analysis interface{}, fieldName string) interface{} {
	// This would need to be implemented based on the actual analysis structure
	// For now, return nil
	return nil
}

// setupContextVariables sets up variables in the evaluation context
func (ace *AdvancedConditionEvaluator) setupContextVariables(ctx *EvaluationContext, request *PolicyEvaluationRequest) {
	ctx.Variables["content"] = request.Content
	ctx.Variables["content_type"] = request.ContentType
	ctx.Variables["source"] = request.Source
	ctx.Variables["user"] = request.User
	ctx.Variables["organization"] = request.Organization
	ctx.Variables["timestamp"] = request.Timestamp
	
	// Add request context variables
	if request.Context != nil {
		for k, v := range request.Context {
			ctx.Variables[k] = v
		}
	}
	
	// Add utility variables
	ctx.Variables["now"] = time.Now()
	ctx.Variables["today"] = time.Now().Format("2006-01-02")
}

// evaluateBasicCondition evaluates basic condition types (fallback)
func (ace *AdvancedConditionEvaluator) evaluateBasicCondition(ctx *EvaluationContext, condition *PolicyCondition) (*ConditionEvaluationResult, error) {
	result := &ConditionEvaluationResult{
		IntermediateResults: make(map[string]interface{}),
		Metadata:           make(map[string]interface{}),
	}

	// Get field value
	fieldValue := ace.getFieldValue(ctx, condition.Field)
	
	// Perform basic comparisons based on condition type
	switch condition.Type {
	case ConditionEquals:
		result.Matched = ace.compareValues(fieldValue, condition.Value, "equals")
	case ConditionNotEquals:
		result.Matched = !ace.compareValues(fieldValue, condition.Value, "equals")
	case ConditionContains:
		result.Matched = ace.compareValues(fieldValue, condition.Value, "contains")
	case ConditionNotContains:
		result.Matched = !ace.compareValues(fieldValue, condition.Value, "contains")
	case ConditionStartsWith:
		result.Matched = ace.compareValues(fieldValue, condition.Value, "starts_with")
	case ConditionEndsWith:
		result.Matched = ace.compareValues(fieldValue, condition.Value, "ends_with")
	case ConditionGreaterThan:
		result.Matched = ace.compareValues(fieldValue, condition.Value, "greater_than")
	case ConditionLessThan:
		result.Matched = ace.compareValues(fieldValue, condition.Value, "less_than")
	default:
		result.Matched = false
		result.ErrorMessage = fmt.Sprintf("unsupported condition type: %s", condition.Type)
	}

	result.Confidence = 1.0
	result.Value = fieldValue
	result.Details = fmt.Sprintf("Basic condition evaluation: %s %s %v = %t", 
		condition.Field, condition.Type, condition.Value, result.Matched)

	return result, nil
}

// compareValues compares two values based on the operation type
func (ace *AdvancedConditionEvaluator) compareValues(actual, expected interface{}, operation string) bool {
	switch operation {
	case "equals":
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
	case "contains":
		actualStr := fmt.Sprintf("%v", actual)
		expectedStr := fmt.Sprintf("%v", expected)
		return strings.Contains(actualStr, expectedStr)
	case "starts_with":
		actualStr := fmt.Sprintf("%v", actual)
		expectedStr := fmt.Sprintf("%v", expected)
		return strings.HasPrefix(actualStr, expectedStr)
	case "ends_with":
		actualStr := fmt.Sprintf("%v", actual)
		expectedStr := fmt.Sprintf("%v", expected)
		return strings.HasSuffix(actualStr, expectedStr)
	case "greater_than":
		actualNum := ace.toFloat64(actual)
		expectedNum := ace.toFloat64(expected)
		return actualNum > expectedNum
	case "less_than":
		actualNum := ace.toFloat64(actual)
		expectedNum := ace.toFloat64(expected)
		return actualNum < expectedNum
	default:
		return false
	}
}

// toFloat64 converts a value to float64 for numeric comparisons
func (ace *AdvancedConditionEvaluator) toFloat64(value interface{}) float64 {
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

// evaluateSimpleExpression evaluates a simple expression
func (ace *AdvancedConditionEvaluator) evaluateSimpleExpression(ctx *EvaluationContext, expression string) (interface{}, error) {
	// Simple expression evaluation for demonstration
	// In a real implementation, this would use a proper expression parser
	
	// Handle simple variable substitution
	if strings.HasPrefix(expression, "$") {
		varName := strings.TrimPrefix(expression, "$")
		if value, exists := ctx.Variables[varName]; exists {
			return value, nil
		}
		return nil, fmt.Errorf("variable not found: %s", varName)
	}
	
	// Handle simple function calls
	if strings.Contains(expression, "(") && strings.Contains(expression, ")") {
		return ace.evaluateBuiltinFunction(ctx, expression)
	}
	
	// Handle simple comparisons
	if strings.Contains(expression, "==") {
		parts := strings.Split(expression, "==")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			
			leftVal := ace.getVariableValue(ctx, left)
			rightVal := ace.getVariableValue(ctx, right)
			
			return fmt.Sprintf("%v", leftVal) == fmt.Sprintf("%v", rightVal), nil
		}
	}
	
	// Return the expression as-is if not recognized
	return expression, nil
}

// getVariableValue gets a variable value, handling simple cases
func (ace *AdvancedConditionEvaluator) getVariableValue(ctx *EvaluationContext, name string) interface{} {
	name = strings.TrimSpace(name)
	
	// Handle quoted strings
	if strings.HasPrefix(name, "\"") && strings.HasSuffix(name, "\"") {
		return strings.Trim(name, "\"")
	}
	
	// Handle variables
	if strings.HasPrefix(name, "$") {
		varName := strings.TrimPrefix(name, "$")
		if value, exists := ctx.Variables[varName]; exists {
			return value
		}
	}
	
	// Handle numeric values
	if f, err := strconv.ParseFloat(name, 64); err == nil {
		return f
	}
	
	// Handle boolean values
	if name == "true" {
		return true
	}
	if name == "false" {
		return false
	}
	
	return name
}

// evaluateBuiltinFunction evaluates a built-in function call
func (ace *AdvancedConditionEvaluator) evaluateBuiltinFunction(ctx *EvaluationContext, expression string) (interface{}, error) {
	// Simple function parsing for demonstration
	if !strings.Contains(expression, "(") || !strings.Contains(expression, ")") {
		return nil, fmt.Errorf("invalid function call: %s", expression)
	}
	
	openParen := strings.Index(expression, "(")
	closeParen := strings.LastIndex(expression, ")")
	
	funcName := strings.TrimSpace(expression[:openParen])
	argsStr := expression[openParen+1 : closeParen]
	
	// Parse arguments
	var args []interface{}
	if argsStr != "" {
		argParts := strings.Split(argsStr, ",")
		for _, arg := range argParts {
			args = append(args, ace.getVariableValue(ctx, arg))
		}
	}
	
	// Call built-in function
	if function, exists := ace.functionRegistry[funcName]; exists {
		ace.recordFunctionCall(funcName)
		return function.Implementation(ctx, args)
	}
	
	return nil, fmt.Errorf("unknown function: %s", funcName)
}

// evaluateMathExpression evaluates a mathematical expression
func (ace *AdvancedConditionEvaluator) evaluateMathExpression(ctx *EvaluationContext, expression string) (float64, error) {
	// Simple math expression evaluation for demonstration
	// In a real implementation, this would use a proper math expression parser
	
	// Handle simple addition
	if strings.Contains(expression, "+") {
		parts := strings.Split(expression, "+")
		if len(parts) == 2 {
			left := ace.toFloat64(ace.getVariableValue(ctx, parts[0]))
			right := ace.toFloat64(ace.getVariableValue(ctx, parts[1]))
			return left + right, nil
		}
	}
	
	// Handle simple subtraction
	if strings.Contains(expression, "-") {
		parts := strings.Split(expression, "-")
		if len(parts) == 2 {
			left := ace.toFloat64(ace.getVariableValue(ctx, parts[0]))
			right := ace.toFloat64(ace.getVariableValue(ctx, parts[1]))
			return left - right, nil
		}
	}
	
	// Handle simple multiplication
	if strings.Contains(expression, "*") {
		parts := strings.Split(expression, "*")
		if len(parts) == 2 {
			left := ace.toFloat64(ace.getVariableValue(ctx, parts[0]))
			right := ace.toFloat64(ace.getVariableValue(ctx, parts[1]))
			return left * right, nil
		}
	}
	
	// Handle simple division
	if strings.Contains(expression, "/") {
		parts := strings.Split(expression, "/")
		if len(parts) == 2 {
			left := ace.toFloat64(ace.getVariableValue(ctx, parts[0]))
			right := ace.toFloat64(ace.getVariableValue(ctx, parts[1]))
			if right != 0 {
				return left / right, nil
			}
		}
	}
	
	// Try to parse as a single number
	if f, err := strconv.ParseFloat(strings.TrimSpace(expression), 64); err == nil {
		return f, nil
	}
	
	return 0, fmt.Errorf("unable to evaluate math expression: %s", expression)
}

// Performance and metrics methods

func (ace *AdvancedConditionEvaluator) recordEvaluation(duration time.Duration, success bool) {
	ace.mu.Lock()
	defer ace.mu.Unlock()
	
	ace.performanceMetrics.TotalEvaluations++
	if success {
		ace.performanceMetrics.SuccessfulEvaluations++
	} else {
		ace.performanceMetrics.FailedEvaluations++
	}
	
	// Update latency metrics
	if ace.performanceMetrics.TotalEvaluations == 1 {
		ace.performanceMetrics.AverageLatency = duration
		ace.performanceMetrics.MaxLatency = duration
		ace.performanceMetrics.MinLatency = duration
	} else {
		// Update average
		totalTime := time.Duration(float64(ace.performanceMetrics.AverageLatency) * float64(ace.performanceMetrics.TotalEvaluations-1))
		ace.performanceMetrics.AverageLatency = (totalTime + duration) / time.Duration(ace.performanceMetrics.TotalEvaluations)
		
		// Update max/min
		if duration > ace.performanceMetrics.MaxLatency {
			ace.performanceMetrics.MaxLatency = duration
		}
		if duration < ace.performanceMetrics.MinLatency {
			ace.performanceMetrics.MinLatency = duration
		}
	}
	
	// Update cache hit ratio
	total := ace.performanceMetrics.CacheHits + ace.performanceMetrics.CacheMisses
	if total > 0 {
		ace.performanceMetrics.CacheHitRatio = float64(ace.performanceMetrics.CacheHits) / float64(total)
	}
	
	ace.performanceMetrics.LastUpdated = time.Now()
}

func (ace *AdvancedConditionEvaluator) recordError(errorType string) {
	ace.mu.Lock()
	ace.performanceMetrics.ErrorsByType[errorType]++
	ace.mu.Unlock()
}

func (ace *AdvancedConditionEvaluator) recordCacheHit() {
	ace.mu.Lock()
	ace.performanceMetrics.CacheHits++
	ace.mu.Unlock()
}

func (ace *AdvancedConditionEvaluator) recordCacheMiss() {
	ace.mu.Lock()
	ace.performanceMetrics.CacheMisses++
	ace.mu.Unlock()
}

func (ace *AdvancedConditionEvaluator) recordRegexEvaluation() {
	ace.mu.Lock()
	ace.performanceMetrics.RegexEvaluations++
	ace.mu.Unlock()
}

func (ace *AdvancedConditionEvaluator) recordMLEvaluation() {
	ace.mu.Lock()
	ace.performanceMetrics.MLEvaluations++
	ace.mu.Unlock()
}

func (ace *AdvancedConditionEvaluator) recordExpressionEvaluation() {
	ace.mu.Lock()
	ace.performanceMetrics.ExpressionEvaluations++
	ace.mu.Unlock()
}

func (ace *AdvancedConditionEvaluator) recordFunctionCall(functionName string) {
	ace.mu.Lock()
	ace.performanceMetrics.FunctionCalls[functionName]++
	ace.mu.Unlock()
}

// GetMetrics returns the current performance metrics
func (ace *AdvancedConditionEvaluator) GetMetrics() *ConditionMetrics {
	ace.mu.RLock()
	defer ace.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := &ConditionMetrics{
		TotalEvaluations:      ace.performanceMetrics.TotalEvaluations,
		SuccessfulEvaluations: ace.performanceMetrics.SuccessfulEvaluations,
		FailedEvaluations:     ace.performanceMetrics.FailedEvaluations,
		AverageLatency:        ace.performanceMetrics.AverageLatency,
		MaxLatency:            ace.performanceMetrics.MaxLatency,
		MinLatency:            ace.performanceMetrics.MinLatency,
		RegexEvaluations:      ace.performanceMetrics.RegexEvaluations,
		MLEvaluations:         ace.performanceMetrics.MLEvaluations,
		ExpressionEvaluations: ace.performanceMetrics.ExpressionEvaluations,
		CacheHits:             ace.performanceMetrics.CacheHits,
		CacheMisses:           ace.performanceMetrics.CacheMisses,
		CacheHitRatio:         ace.performanceMetrics.CacheHitRatio,
		TimeoutCount:          ace.performanceMetrics.TimeoutCount,
		SecurityViolations:    ace.performanceMetrics.SecurityViolations,
		LastUpdated:           ace.performanceMetrics.LastUpdated,
		FunctionCalls:         make(map[string]int64),
		ErrorsByType:          make(map[string]int64),
	}
	
	// Copy maps
	for k, v := range ace.performanceMetrics.FunctionCalls {
		metrics.FunctionCalls[k] = v
	}
	for k, v := range ace.performanceMetrics.ErrorsByType {
		metrics.ErrorsByType[k] = v
	}
	
	return metrics
}

// GetCacheStats returns cache statistics
func (ace *AdvancedConditionEvaluator) GetCacheStats() map[string]interface{} {
	ace.mu.RLock()
	defer ace.mu.RUnlock()
	
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	return map[string]interface{}{
		"regex_cache_size":      len(ace.regexCache),
		"regex_cache_limit":     ace.config.RegexCacheSize,
		"expression_cache_size": len(ace.expressionCache),
		"expression_cache_limit": ace.config.ExpressionCacheSize,
		"ml_model_cache_size":   len(ace.mlModelCache),
		"ml_model_cache_limit":  ace.config.ModelCacheSize,
		"cache_hit_ratio":       ace.performanceMetrics.CacheHitRatio,
		"memory_usage_bytes":    memStats.Alloc,
		"total_cache_hits":      ace.performanceMetrics.CacheHits,
		"total_cache_misses":    ace.performanceMetrics.CacheMisses,
	}
}

// ClearCaches clears all caches
func (ace *AdvancedConditionEvaluator) ClearCaches() {
	ace.mu.Lock()
	defer ace.mu.Unlock()
	
	ace.regexCache = make(map[string]*regexp.Regexp)
	ace.expressionCache = make(map[string]*CompiledExpression)
	ace.mlModelCache = make(map[string]MLModelInterface)
} 