package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("=== AI Gateway Advanced Condition Evaluation Demo ===")
	fmt.Println()

	// Create advanced condition evaluator
	evaluator := policy.NewAdvancedConditionEvaluator(&policy.AdvancedEvaluatorConfig{
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
	})

	// Create policy engine with advanced evaluator
	engine := policy.NewPolicyEngine()

	// Run all demo sections
	demoRegexConditions(evaluator)
	fmt.Println()
	
	demoMLConditions(evaluator)
	fmt.Println()
	
	demoExpressionConditions(evaluator)
	fmt.Println()
	
	demoBuiltinFunctions(evaluator)
	fmt.Println()
	
	demoAdvancedPolicies(engine)
	fmt.Println()
	
	demoPerformanceMetrics(evaluator)
}

func demoRegexConditions(evaluator *policy.AdvancedConditionEvaluator) {
	fmt.Println("🔍 === REGEX CONDITION EVALUATION ===")
	
	testCases := []struct {
		name        string
		condition   *policy.PolicyCondition
		testContent []string
	}{
		{
			name: "Email Detection",
			condition: &policy.PolicyCondition{
				Type:  "regex_match",
				Field: "content",
				Value: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
				Regex: true,
			},
			testContent: []string{
				"Contact us at support@example.com",
				"Email admin@company.org for help",
				"No email address in this text",
			},
		},
		{
			name: "Social Security Number Detection",
			condition: &policy.PolicyCondition{
				Type:  "regex_match",
				Field: "content",
				Value: `\b\d{3}-\d{2}-\d{4}\b`,
				Regex: true,
			},
			testContent: []string{
				"My SSN is 123-45-6789",
				"SSN: 987-65-4321 for verification",
				"No sensitive numbers here",
			},
		},
		{
			name: "Credit Card Number Detection",
			condition: &policy.PolicyCondition{
				Type:  "regex_find",
				Field: "content",
				Value: `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`,
				Regex: true,
			},
			testContent: []string{
				"Card number: 4532-1234-5678-9012",
				"Payment via 4532 1234 5678 9012",
				"No payment information",
			},
		},
		{
			name: "Phone Number Extraction",
			condition: &policy.PolicyCondition{
				Type:  "regex_extract",
				Field: "content",
				Value: `(\d{3})-(\d{3})-(\d{4})`,
				Regex: true,
			},
			testContent: []string{
				"Call us at 555-123-4567",
				"Phone: 800-555-0123 for support",
				"No phone number here",
			},
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n📋 %s:\n", tc.name)
		
		for i, content := range tc.testContent {
			request := &policy.PolicyEvaluationRequest{
				ID:      fmt.Sprintf("regex-test-%d", i),
				Content: content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tc.condition, request)
			if err != nil {
				fmt.Printf("   ❌ Error: %v\n", err)
				continue
			}

			status := "❌ No Match"
			if result.Matched {
				status = "✅ Match Found"
			}

			fmt.Printf("   %s | Content: \"%s\"\n", status, content)
			fmt.Printf("      Confidence: %.2f | Time: %v\n", result.Confidence, result.ExecutionTime)

			// Show extracted data for specific types
			if tc.condition.Type == "regex_find" && result.IntermediateResults != nil {
				if matches, ok := result.IntermediateResults["matches"]; ok {
					fmt.Printf("      Matches: %v\n", matches)
				}
			}
			if tc.condition.Type == "regex_extract" && result.IntermediateResults != nil {
				if submatches, ok := result.IntermediateResults["submatches"]; ok {
					fmt.Printf("      Extracted: %v\n", submatches)
				}
			}
		}
	}
}

func demoMLConditions(evaluator *policy.AdvancedConditionEvaluator) {
	fmt.Println("🤖 === MACHINE LEARNING CONDITION EVALUATION ===")
	
	testCases := []struct {
		name        string
		condition   *policy.PolicyCondition
		testContent []string
	}{
		{
			name: "Content Sensitivity Classification",
			condition: &policy.PolicyCondition{
				Type:      "ml_classify",
				Field:     "content",
				Threshold: &[]float64{0.5}[0],
			},
			testContent: []string{
				"This document contains confidential information about our secret project",
				"Internal private data for authorized personnel only",
				"This is a public announcement about our upcoming event",
			},
		},
		{
			name: "Sentiment Analysis",
			condition: &policy.PolicyCondition{
				Type:  "ml_sentiment",
				Field: "content",
				Value: "positive",
			},
			testContent: []string{
				"I love this product! It's excellent and great",
				"This is terrible and awful, I hate it",
				"This is a neutral statement about the product",
			},
		},
		{
			name: "Content Complexity Scoring",
			condition: &policy.PolicyCondition{
				Type:      "ml_score",
				Field:     "content",
				Threshold: &[]float64{0.4}[0],
			},
			testContent: []string{
				"This is a very long and complex document with many technical terms and detailed explanations",
				"Short text",
				"Medium length document with some technical content",
			},
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n📊 %s:\n", tc.name)
		
		for i, content := range tc.testContent {
			request := &policy.PolicyEvaluationRequest{
				ID:      fmt.Sprintf("ml-test-%d", i),
				Content: content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tc.condition, request)
			if err != nil {
				fmt.Printf("   ❌ Error: %v\n", err)
				continue
			}

			status := "❌ Below Threshold"
			if result.Matched {
				status = "✅ Above Threshold"
			}

			fmt.Printf("   %s | Content: \"%.50s...\"\n", status, content)
			fmt.Printf("      Confidence: %.2f | Time: %v\n", result.Confidence, result.ExecutionTime)
			fmt.Printf("      ML Result: %v\n", result.Value)

			// Show ML-specific details
			if result.IntermediateResults != nil {
				if tc.condition.Type == "ml_classify" {
					if score, ok := result.IntermediateResults["sensitivity_score"]; ok {
						fmt.Printf("      Sensitivity Score: %.2f\n", score)
					}
					if keywords, ok := result.IntermediateResults["matched_keywords"]; ok {
						fmt.Printf("      Matched Keywords: %v\n", keywords)
					}
				}
				if tc.condition.Type == "ml_sentiment" {
					if pos, ok := result.IntermediateResults["positive_words"]; ok {
						if neg, ok := result.IntermediateResults["negative_words"]; ok {
							fmt.Printf("      Word Analysis: +%v, -%v\n", pos, neg)
						}
					}
				}
				if tc.condition.Type == "ml_score" {
					if length, ok := result.IntermediateResults["text_length"]; ok {
						if words, ok := result.IntermediateResults["word_count"]; ok {
							fmt.Printf("      Text Stats: %v chars, %v words\n", length, words)
						}
					}
				}
			}
		}
	}
}

func demoExpressionConditions(evaluator *policy.AdvancedConditionEvaluator) {
	fmt.Println("⚡ === EXPRESSION CONDITION EVALUATION ===")
	
	testCases := []struct {
		name      string
		condition *policy.PolicyCondition
		request   *policy.PolicyEvaluationRequest
	}{
		{
			name: "Simple Variable Expression",
			condition: &policy.PolicyCondition{
				Type:  "expression",
				Value: "expr:$content == \"sensitive data\"",
			},
			request: &policy.PolicyEvaluationRequest{
				ID:      "expr-test-1",
				Content: "sensitive data",
				User:    "admin",
			},
		},
		{
			name: "User Permission Check",
			condition: &policy.PolicyCondition{
				Type:  "expression",
				Value: "expr:$user == \"admin\"",
			},
			request: &policy.PolicyEvaluationRequest{
				ID:      "expr-test-2",
				Content: "restricted content",
				User:    "admin",
			},
		},
		{
			name: "Function Call Expression",
			condition: &policy.PolicyCondition{
				Type:  "function",
				Value: "length($content)",
			},
			request: &policy.PolicyEvaluationRequest{
				ID:      "expr-test-3",
				Content: "This is a test content string",
			},
		},
		{
			name: "Complex Organization Check",
			condition: &policy.PolicyCondition{
				Type:  "expression",
				Value: "expr:$organization == \"internal\"",
			},
			request: &policy.PolicyEvaluationRequest{
				ID:           "expr-test-4",
				Content:      "internal document",
				Organization: "internal",
				User:         "employee",
			},
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n💡 %s:\n", tc.name)
		
		result, err := evaluator.EvaluateAdvancedCondition(tc.condition, tc.request)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		status := "❌ False"
		if result.Matched {
			status = "✅ True"
		}

		fmt.Printf("   %s | Expression: \"%s\"\n", status, tc.condition.Value)
		fmt.Printf("      Request Context: User=%s, Org=%s\n", tc.request.User, tc.request.Organization)
		fmt.Printf("      Confidence: %.2f | Time: %v\n", result.Confidence, result.ExecutionTime)
		fmt.Printf("      Result Value: %v\n", result.Value)
	}
}

func demoBuiltinFunctions(evaluator *policy.AdvancedConditionEvaluator) {
	fmt.Println("🔧 === BUILT-IN FUNCTION EVALUATION ===")
	
	// Display available functions by category
	functionsByCategory := evaluator.GetFunctionsByCategory()
	fmt.Printf("\n📚 Available Function Categories:\n")
	for category, functions := range functionsByCategory {
		fmt.Printf("   %s: %d functions\n", category, len(functions))
		for _, fn := range functions[:min(3, len(functions))] { // Show first 3 functions
			fmt.Printf("      - %s: %s\n", fn.Name, fn.Description)
		}
		if len(functions) > 3 {
			fmt.Printf("      ... and %d more\n", len(functions)-3)
		}
	}

	// Test specific functions
	testCases := []struct {
		name        string
		condition   *policy.PolicyCondition
		testContent []string
	}{
		{
			name: "String Length Function",
			condition: &policy.PolicyCondition{
				Type:  "function",
				Value: "length($content)",
			},
			testContent: []string{
				"short",
				"this is a medium length string",
				"this is a very long string with many words and characters",
			},
		},
		{
			name: "PII Detection Function",
			condition: &policy.PolicyCondition{
				Type:  "function",
				Value: "detect_pii($content)",
			},
			testContent: []string{
				"My SSN is 123-45-6789",
				"Contact john.doe@example.com",
				"Regular text without PII",
			},
		},
		{
			name: "Email Validation Function",
			condition: &policy.PolicyCondition{
				Type:  "function",
				Value: "is_email($content)",
			},
			testContent: []string{
				"user@example.com",
				"invalid-email",
				"test.user+tag@domain.co.uk",
			},
		},
		{
			name: "Word Count Function",
			condition: &policy.PolicyCondition{
				Type:  "function",
				Value: "word_count($content)",
			},
			testContent: []string{
				"one",
				"two words",
				"this is a longer sentence with multiple words",
			},
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n🛠️  %s:\n", tc.name)
		
		for i, content := range tc.testContent {
			request := &policy.PolicyEvaluationRequest{
				ID:      fmt.Sprintf("func-test-%d", i),
				Content: content,
			}

			result, err := evaluator.EvaluateAdvancedCondition(tc.condition, request)
			if err != nil {
				fmt.Printf("   ❌ Error: %v\n", err)
				continue
			}

			status := "📊 Result"
			if boolVal, ok := result.Value.(bool); ok {
				if boolVal {
					status = "✅ True"
				} else {
					status = "❌ False"
				}
			}

			fmt.Printf("   %s | Content: \"%s\"\n", status, content)
			fmt.Printf("      Function Result: %v | Time: %v\n", result.Value, result.ExecutionTime)
		}
	}
}

func demoAdvancedPolicies(engine *policy.PolicyEngine) {
	fmt.Println("🏛️  === ADVANCED POLICY EVALUATION ===")

	// Create policies with advanced conditions
	policies := []*policy.Policy{
		{
			ID:          "regex-pii-policy",
			Name:        "Regex PII Detection Policy",
			Description: "Uses regex to detect PII patterns",
			Version:     "1.0.0",
			Status:      policy.PolicyStatusActive,
			Priority:    100,
			Category:    "security",
			Owner:       "security-team",
			CreatedBy:   "admin",
			Rules: []policy.PolicyRule{
				{
					ID:          "regex-ssn-block",
					Name:        "Block SSN Pattern",
					Description: "Block content with SSN patterns using regex",
					Priority:    10,
					Enabled:     true,
					Condition: &policy.PolicyCondition{
						Type:  "regex_match",
						Field: "content",
						Value: `\b\d{3}-\d{2}-\d{4}\b`,
						Regex: true,
					},
					Action: policy.PolicyAction{
						Type:     policy.ActionBlock,
						Severity: policy.SeverityHigh,
						Message:  "Content blocked due to SSN pattern detection",
					},
				},
			},
			DefaultAction: policy.PolicyAction{
				Type:     policy.ActionAllow,
				Severity: policy.SeverityInfo,
			},
		},
		{
			ID:          "ml-sensitivity-policy",
			Name:        "ML Content Sensitivity Policy",
			Description: "Uses ML to classify content sensitivity",
			Version:     "1.0.0",
			Status:      policy.PolicyStatusActive,
			Priority:    90,
			Category:    "compliance",
			Owner:       "compliance-team",
			CreatedBy:   "admin",
			Rules: []policy.PolicyRule{
				{
					ID:          "ml-sensitive-redact",
					Name:        "Redact Sensitive Content",
					Description: "Redact content classified as sensitive by ML",
					Priority:    10,
					Enabled:     true,
					Condition: &policy.PolicyCondition{
						Type:      "ml_classify",
						Field:     "content",
						Threshold: &[]float64{0.7}[0],
					},
					Action: policy.PolicyAction{
						Type:     policy.ActionRedact,
						Severity: policy.SeverityMedium,
						Message:  "Content redacted due to ML sensitivity classification",
					},
				},
			},
			DefaultAction: policy.PolicyAction{
				Type:     policy.ActionAllow,
				Severity: policy.SeverityInfo,
			},
		},
		{
			ID:          "function-length-policy",
			Name:        "Function-Based Length Policy",
			Description: "Uses built-in functions to check content length",
			Version:     "1.0.0",
			Status:      policy.PolicyStatusActive,
			Priority:    80,
			Category:    "content",
			Owner:       "content-team",
			CreatedBy:   "admin",
			Rules: []policy.PolicyRule{
				{
					ID:          "function-length-warn",
					Name:        "Warn on Long Content",
					Description: "Warn when content length exceeds threshold",
					Priority:    10,
					Enabled:     true,
					Condition: &policy.PolicyCondition{
						Type:  "function",
						Value: "fn:length($content) > 100",
					},
					Action: policy.PolicyAction{
						Type:     policy.ActionWarn,
						Severity: policy.SeverityLow,
						Message:  "Content length exceeds recommended limit",
					},
				},
			},
			DefaultAction: policy.PolicyAction{
				Type:     policy.ActionAllow,
				Severity: policy.SeverityInfo,
			},
		},
	}

	// Add policies to engine
	for _, pol := range policies {
		if err := engine.AddPolicy(pol); err != nil {
			fmt.Printf("❌ Failed to add policy %s: %v\n", pol.Name, err)
			continue
		}
	}

	// Test requests against policies
	testRequests := []*policy.PolicyEvaluationRequest{
		{
			ID:           "policy-test-1",
			Content:      "My social security number is 123-45-6789",
			ContentType:  "text/plain",
			Source:       "user-input",
			User:         "john.doe",
			Organization: "acme-corp",
			Timestamp:    time.Now(),
		},
		{
			ID:           "policy-test-2",
			Content:      "This document contains highly confidential and private information about our secret project",
			ContentType:  "text/plain",
			Source:       "document",
			User:         "jane.smith",
			Organization: "acme-corp",
			Timestamp:    time.Now(),
		},
		{
			ID:           "policy-test-3",
			Content:      "This is a very long document that exceeds the normal length limit and should trigger a warning due to its excessive size and verbosity",
			ContentType:  "text/plain",
			Source:       "user-input",
			User:         "bob.wilson",
			Organization: "acme-corp",
			Timestamp:    time.Now(),
		},
		{
			ID:           "policy-test-4",
			Content:      "Short safe text",
			ContentType:  "text/plain",
			Source:       "user-input",
			User:         "alice.brown",
			Organization: "acme-corp",
			Timestamp:    time.Now(),
		},
	}

	fmt.Printf("\n📋 Evaluating %d test requests against %d advanced policies:\n", len(testRequests), len(policies))

	for i, request := range testRequests {
		fmt.Printf("\n🔍 Request %d: \"%s\"\n", i+1, truncateString(request.Content, 50))
		
		result, err := engine.EvaluateRequest(context.Background(), request)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		// Display decision
		actionColor := getActionColor(result.Decision.Action)
		fmt.Printf("   %s Decision: %s\n", actionColor, result.Decision.Action)
		fmt.Printf("      Reason: %s\n", result.Decision.Reason)
		fmt.Printf("      Confidence: %.2f | Severity: %s\n", result.Decision.Confidence, result.Decision.Severity)
		fmt.Printf("      Processing Time: %v\n", result.ProcessingTime)

		// Display matched policies
		if len(result.MatchedPolicies) > 0 {
			fmt.Printf("      Matched Policies:\n")
			for _, match := range result.MatchedPolicies {
				fmt.Printf("        - %s (Priority: %d, Confidence: %.2f)\n", 
					match.PolicyName, match.Priority, match.Confidence)
			}
		}

		// Display conflicts if any
		if len(result.Conflicts) > 0 {
			fmt.Printf("      Conflicts Detected: %d\n", len(result.Conflicts))
		}
	}
}

func demoPerformanceMetrics(evaluator *policy.AdvancedConditionEvaluator) {
	fmt.Println("📊 === PERFORMANCE METRICS ===")

	metrics := evaluator.GetMetrics()
	cacheStats := evaluator.GetCacheStats()

	fmt.Printf("\n📈 Evaluation Metrics:\n")
	fmt.Printf("   Total Evaluations: %d\n", metrics.TotalEvaluations)
	fmt.Printf("   Successful: %d | Failed: %d\n", metrics.SuccessfulEvaluations, metrics.FailedEvaluations)
	fmt.Printf("   Average Latency: %v\n", metrics.AverageLatency)
	fmt.Printf("   Max Latency: %v | Min Latency: %v\n", metrics.MaxLatency, metrics.MinLatency)

	fmt.Printf("\n🏷️  Evaluation Types:\n")
	fmt.Printf("   Regex Evaluations: %d\n", metrics.RegexEvaluations)
	fmt.Printf("   ML Evaluations: %d\n", metrics.MLEvaluations)
	fmt.Printf("   Expression Evaluations: %d\n", metrics.ExpressionEvaluations)

	fmt.Printf("\n💾 Cache Performance:\n")
	fmt.Printf("   Cache Hits: %d | Cache Misses: %d\n", metrics.CacheHits, metrics.CacheMisses)
	fmt.Printf("   Cache Hit Ratio: %.2f%%\n", metrics.CacheHitRatio*100)

	fmt.Printf("\n🗂️  Cache Stats:\n")
	fmt.Printf("   Regex Cache: %v/%v patterns\n", 
		cacheStats["regex_cache_size"], cacheStats["regex_cache_limit"])
	fmt.Printf("   Expression Cache: %v/%v expressions\n", 
		cacheStats["expression_cache_size"], cacheStats["expression_cache_limit"])
	fmt.Printf("   ML Model Cache: %v/%v models\n", 
		cacheStats["ml_model_cache_size"], cacheStats["ml_model_cache_limit"])

	if len(metrics.FunctionCalls) > 0 {
		fmt.Printf("\n🔧 Function Call Stats:\n")
		for funcName, count := range metrics.FunctionCalls {
			fmt.Printf("   %s: %d calls\n", funcName, count)
		}
	}

	if len(metrics.ErrorsByType) > 0 {
		fmt.Printf("\n❌ Error Stats:\n")
		for errorType, count := range metrics.ErrorsByType {
			fmt.Printf("   %s: %d errors\n", errorType, count)
		}
	}

	fmt.Printf("\n🔄 Last Updated: %v\n", metrics.LastUpdated.Format(time.RFC3339))
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getActionColor(action policy.ActionType) string {
	switch action {
	case policy.ActionAllow:
		return "✅"
	case policy.ActionBlock:
		return "🚫"
	case policy.ActionWarn:
		return "⚠️"
	case policy.ActionRedact:
		return "✂️"
	case policy.ActionMask:
		return "🎭"
	case policy.ActionQuarantine:
		return "🔒"
	default:
		return "📋"
	}
} 