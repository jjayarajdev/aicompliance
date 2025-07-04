package policy

import (
	"testing"
	"time"
)

func TestAdvancedConditionEvaluator_RegexConditions(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	tests := []struct {
		name      string
		condition *PolicyCondition
		content   string
		expected  bool
	}{
		{
			name: "regex match email",
			condition: &PolicyCondition{
				Type:   "regex_match",
				Field:  "content",
				Value:  `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
				Regex:  true,
			},
			content:  "Contact us at support@example.com for help",
			expected: true,
		},
		{
			name: "regex match SSN",
			condition: &PolicyCondition{
				Type:  "regex_match",
				Field: "content",
				Value: `\b\d{3}-\d{2}-\d{4}\b`,
				Regex: true,
			},
			content:  "My SSN is 123-45-6789",
			expected: true,
		},
		{
			name: "regex no match",
			condition: &PolicyCondition{
				Type:  "regex_match",
				Field: "content",
				Value: `\b\d{3}-\d{2}-\d{4}\b`,
				Regex: true,
			},
			content:  "No sensitive data here",
			expected: false,
		},
		{
			name: "regex find multiple",
			condition: &PolicyCondition{
				Type:  "regex_find",
				Field: "content",
				Value: `\d+`,
				Regex: true,
			},
			content:  "Numbers: 123 and 456",
			expected: true,
		},
		{
			name: "regex extract groups",
			condition: &PolicyCondition{
				Type:  "regex_extract",
				Field: "content",
				Value: `(\d{3})-(\d{3})-(\d{4})`,
				Regex: true,
			},
			content:  "Phone: 555-123-4567",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: tt.content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Matched)
			}

			// Check that execution time is recorded
			if result.ExecutionTime <= 0 {
				t.Error("Expected execution time to be recorded")
			}

			// Check intermediate results for specific types
			if tt.condition.Type == "regex_find" && result.Matched {
				if matches, ok := result.IntermediateResults["matches"]; !ok || matches == nil {
					t.Error("Expected matches in intermediate results")
				}
			}
		})
	}
}

func TestAdvancedConditionEvaluator_MLConditions(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	tests := []struct {
		name      string
		condition *PolicyCondition
		content   string
		expected  bool
	}{
		{
			name: "ML classify sensitive",
			condition: &PolicyCondition{
				Type:      "ml_classify",
				Field:     "content",
				Threshold: &[]float64{0.5}[0],
			},
			content:  "This document contains confidential information about our secret project",
			expected: true,
		},
		{
			name: "ML classify non-sensitive",
			condition: &PolicyCondition{
				Type:      "ml_classify",
				Field:     "content",
				Threshold: &[]float64{0.5}[0],
			},
			content:  "This is a public announcement about our upcoming event",
			expected: false,
		},
		{
			name: "ML sentiment positive",
			condition: &PolicyCondition{
				Type:  "ml_sentiment",
				Field: "content",
				Value: "positive",
			},
			content:  "I love this product! It's excellent and makes me happy",
			expected: true,
		},
		{
			name: "ML sentiment negative",
			condition: &PolicyCondition{
				Type:  "ml_sentiment",
				Field: "content",
				Value: "negative",
			},
			content:  "This is terrible and awful. I hate it",
			expected: true,
		},
		{
			name: "ML score complexity",
			condition: &PolicyCondition{
				Type:      "ml_score",
				Field:     "content",
				Threshold: &[]float64{0.3}[0],
			},
			content:  "This is a very long and complex document with many technical terms and detailed explanations that require significant processing",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: tt.content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Matched != tt.expected {
				t.Errorf("Expected %v, got %v for content: %s", tt.expected, result.Matched, tt.content)
			}

			// Check confidence is set
			if result.Confidence <= 0 {
				t.Error("Expected confidence to be greater than 0")
			}

			// Check ML-specific intermediate results
			if tt.condition.Type == "ml_classify" && result.IntermediateResults != nil {
				if _, ok := result.IntermediateResults["sensitivity_score"]; !ok {
					t.Error("Expected sensitivity_score in intermediate results")
				}
			}
		})
	}
}

func TestAdvancedConditionEvaluator_ExpressionConditions(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	tests := []struct {
		name      string
		condition *PolicyCondition
		request   *PolicyEvaluationRequest
		expected  bool
	}{
		{
			name: "simple variable expression",
			condition: &PolicyCondition{
				Type:  "expression",
				Value: "expr:$content == \"test content\"",
			},
			request: &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: "test content",
			},
			expected: true,
		},
		{
			name: "function call expression",
			condition: &PolicyCondition{
				Type:  "function",
				Value: "length($content)",
			},
			request: &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: "hello",
			},
			expected: true, // length > 0
		},
		{
			name: "complex expression with context",
			condition: &PolicyCondition{
				Type:  "expression",
				Value: "expr:$user == \"admin\"",
			},
			request: &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: "sensitive data",
				User:    "admin",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, tt.request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Matched)
			}

			// Check that result value is set
			if result.Value == nil {
				t.Error("Expected result value to be set")
			}
		})
	}
}

func TestAdvancedConditionEvaluator_StringConditions(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	tests := []struct {
		name      string
		condition *PolicyCondition
		content   string
		expected  bool
	}{
		{
			name: "string length check",
			condition: &PolicyCondition{
				Type:  "string_length",
				Field: "content",
				Value: 10.0,
			},
			content:  "this is a long string",
			expected: true,
		},
		{
			name: "word count check",
			condition: &PolicyCondition{
				Type:  "string_words",
				Field: "content",
				Value: 3.0,
			},
			content:  "this has many words here",
			expected: true,
		},
		{
			name: "line count check",
			condition: &PolicyCondition{
				Type:  "string_lines",
				Field: "content",
				Value: 2.0,
			},
			content:  "line one\nline two\nline three",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: tt.content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Matched)
			}

			// Check intermediate results contain actual values
			if result.IntermediateResults == nil {
				t.Error("Expected intermediate results to be set")
			}
		})
	}
}

func TestAdvancedConditionEvaluator_MathConditions(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	tests := []struct {
		name      string
		condition *PolicyCondition
		expected  bool
	}{
		{
			name: "math expression addition",
			condition: &PolicyCondition{
				Type:      "math_expression",
				Value:     "5 + 3",
				Threshold: &[]float64{7.0}[0],
			},
			expected: true,
		},
		{
			name: "math expression below threshold",
			condition: &PolicyCondition{
				Type:      "math_expression",
				Value:     "2 + 1",
				Threshold: &[]float64{5.0}[0],
			},
			expected: false,
		},
		{
			name: "statistical analysis",
			condition: &PolicyCondition{
				Type:      "statistical",
				Field:     "content",
				Threshold: &[]float64{4.0}[0],
			},
			expected: true, // avg word length should be > 4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: "this has words",
			}

			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Matched)
			}

			// Check that result value is numeric
			if result.Value == nil {
				t.Error("Expected numeric result value")
			}
		})
	}
}

func TestAdvancedConditionEvaluator_BuiltinFunctions(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	// Test that functions are properly initialized
	functions := evaluator.GetAvailableFunctions()
	
	expectedFunctions := []string{
		"length", "upper", "lower", "trim", "contains", "starts_with", "ends_with", "word_count",
		"abs", "max", "min", "round",
		"now", "time_diff",
		"regex_match", "regex_extract",
		"hash_md5", "hash_sha256",
		"detect_pii", "detect_credit_card",
		"is_email", "is_url", "is_ip",
		"coalesce", "type_of",
	}

	for _, funcName := range expectedFunctions {
		if _, exists := functions[funcName]; !exists {
			t.Errorf("Expected function %s to be available", funcName)
		}
	}

	// Test function execution through conditions
	tests := []struct {
		name      string
		condition *PolicyCondition
		content   string
		expected  bool
	}{
		{
			name: "length function",
			condition: &PolicyCondition{
				Type:  "function",
				Value: "fn:length($content) >= 5",
			},
			content:  "hello world",
			expected: true,
		},
		{
			name: "contains function",
			condition: &PolicyCondition{
				Type:  "function",
				Value: "fn:contains($content, \"world\")",
			},
			content:  "hello world",
			expected: true,
		},
		{
			name: "detect_pii function",
			condition: &PolicyCondition{
				Type:  "function",
				Value: "fn:detect_pii($content)",
			},
			content:  "My SSN is 123-45-6789",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: tt.content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, request)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Matched != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result.Matched)
			}
		})
	}
}

func TestAdvancedConditionEvaluator_Performance(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(&AdvancedEvaluatorConfig{
		EnableRegexCaching:     true,
		EnablePerformanceStats: true,
		RegexCacheSize:         100,
		EvaluationTimeout:      1 * time.Second,
	})

	condition := &PolicyCondition{
		Type:  "regex_match",
		Field: "content",
		Value: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		Regex: true,
	}

	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Contact support@example.com for help",
	}

	// First evaluation (cache miss)
	result1, err := evaluator.EvaluateAdvancedCondition(condition, request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Second evaluation (cache hit)
	result2, err := evaluator.EvaluateAdvancedCondition(condition, request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Both should match
	if !result1.Matched || !result2.Matched {
		t.Error("Both evaluations should match")
	}

	// Check performance metrics
	metrics := evaluator.GetMetrics()
	if metrics.TotalEvaluations != 2 {
		t.Errorf("Expected 2 evaluations, got %d", metrics.TotalEvaluations)
	}

	if metrics.RegexEvaluations != 2 {
		t.Errorf("Expected 2 regex evaluations, got %d", metrics.RegexEvaluations)
	}

	// Check cache stats
	cacheStats := evaluator.GetCacheStats()
	if cacheStats["regex_cache_size"].(int) == 0 {
		t.Error("Expected regex cache to contain compiled patterns")
	}
}

func TestAdvancedConditionEvaluator_ErrorHandling(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)

	tests := []struct {
		name      string
		condition *PolicyCondition
		expectErr bool
	}{
		{
			name: "invalid regex pattern",
			condition: &PolicyCondition{
				Type:  "regex_match",
				Field: "content",
				Value: "[",
				Regex: true,
			},
			expectErr: true,
		},
		{
			name: "non-string regex pattern",
			condition: &PolicyCondition{
				Type:  "regex_match",
				Field: "content",
				Value: 123,
				Regex: true,
			},
			expectErr: true,
		},
		{
			name: "invalid field for string operation",
			condition: &PolicyCondition{
				Type:  "string_length",
				Field: "non_existent_field",
				Value: 10,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &PolicyEvaluationRequest{
				ID:      "test-request",
				Content: "test content",
			}

			result, err := evaluator.EvaluateAdvancedCondition(tt.condition, request)
			
			if tt.expectErr {
				if err == nil && result.ErrorMessage == "" {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAdvancedConditionEvaluator_Timeout(t *testing.T) {
	// Create evaluator with very short timeout
	evaluator := NewAdvancedConditionEvaluator(&AdvancedEvaluatorConfig{
		EvaluationTimeout: 1 * time.Nanosecond, // Very short timeout
	})

	condition := &PolicyCondition{
		Type:  "regex_match",
		Field: "content",
		Value: `.*`,
		Regex: true,
	}

	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "test content",
	}

	result, err := evaluator.EvaluateAdvancedCondition(condition, request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should handle timeout gracefully
	if result.ErrorMessage == "" {
		t.Error("Expected timeout error message")
	}

	// Check that timeout is recorded in metrics
	metrics := evaluator.GetMetrics()
	if metrics.TimeoutCount == 0 {
		t.Error("Expected timeout to be recorded in metrics")
	}
}

func TestAdvancedConditionEvaluator_CacheManagement(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(&AdvancedEvaluatorConfig{
		EnableRegexCaching: true,
		RegexCacheSize:     2, // Small cache size to test eviction
	})

	patterns := []string{`\d+`, `[a-z]+`, `[A-Z]+`}
	
	for i, pattern := range patterns {
		condition := &PolicyCondition{
			Type:  "regex_match",
			Field: "content",
			Value: pattern,
			Regex: true,
		}

		request := &PolicyEvaluationRequest{
			ID:      "test-request",
			Content: "Test123",
		}

		_, err := evaluator.EvaluateAdvancedCondition(condition, request)
		if err != nil {
			t.Fatalf("Unexpected error for pattern %d: %v", i, err)
		}
	}

	// Check cache size doesn't exceed limit
	cacheStats := evaluator.GetCacheStats()
	cacheSize := cacheStats["regex_cache_size"].(int)
	if cacheSize > 2 {
		t.Errorf("Cache size %d exceeds limit of 2", cacheSize)
	}

	// Test cache clearing
	evaluator.ClearCaches()
	cacheStats = evaluator.GetCacheStats()
	if cacheStats["regex_cache_size"].(int) != 0 {
		t.Error("Cache should be empty after clearing")
	}
}

func TestAdvancedConditionEvaluator_SecurityLevels(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	// Test that security levels are properly assigned to functions
	functions := evaluator.GetAvailableFunctions()
	
	securityChecks := map[string]SecurityLevel{
		"length":      SecurityLevelLow,
		"detect_pii":  SecurityLevelHigh,
		"hash_md5":    SecurityLevelMedium,
		"regex_match": SecurityLevelMedium,
	}

	for funcName, expectedLevel := range securityChecks {
		if function, exists := functions[funcName]; exists {
			if function.SecurityLevel != expectedLevel {
				t.Errorf("Function %s expected security level %s, got %s", 
					funcName, expectedLevel, function.SecurityLevel)
			}
		}
	}
}

func TestAdvancedConditionEvaluator_FunctionsByCategory(t *testing.T) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	functionsByCategory := evaluator.GetFunctionsByCategory()
	
	expectedCategories := []FunctionCategory{
		CategoryString, CategoryMath, CategoryDate, CategoryRegex,
		CategorySecurity, CategoryAnalysis, CategoryValidation, CategoryUtility,
	}

	for _, category := range expectedCategories {
		if functions, exists := functionsByCategory[category]; !exists || len(functions) == 0 {
			t.Errorf("Expected functions in category %s", category)
		}
	}

	// Check specific function categorization
	stringFunctions := functionsByCategory[CategoryString]
	foundLength := false
	for _, fn := range stringFunctions {
		if fn.Name == "length" {
			foundLength = true
			break
		}
	}
	if !foundLength {
		t.Error("Expected 'length' function in string category")
	}
}

func BenchmarkAdvancedConditionEvaluator_RegexMatch(b *testing.B) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	condition := &PolicyCondition{
		Type:  "regex_match",
		Field: "content",
		Value: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
		Regex: true,
	}

	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "Contact support@example.com for help",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.EvaluateAdvancedCondition(condition, request)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkAdvancedConditionEvaluator_MLClassification(b *testing.B) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	condition := &PolicyCondition{
		Type:      "ml_classify",
		Field:     "content",
		Threshold: &[]float64{0.5}[0],
	}

	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "This document contains confidential information",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.EvaluateAdvancedCondition(condition, request)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkAdvancedConditionEvaluator_FunctionCall(b *testing.B) {
	evaluator := NewAdvancedConditionEvaluator(nil)
	
	condition := &PolicyCondition{
		Type:  "function",
		Value: "length($content)",
	}

	request := &PolicyEvaluationRequest{
		ID:      "test-request",
		Content: "This is a test string for benchmarking",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := evaluator.EvaluateAdvancedCondition(condition, request)
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
} 