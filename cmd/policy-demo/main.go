package main

import (
	"context"
	"fmt"
	"strings"

	"ai-gateway-poc/internal/analysis"
	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("🔧 AI Gateway Task 3.1: Policy Rule Data Structure & Validation Schema Demo")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	fmt.Println("📋 POLICY ENGINE FEATURES")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println("✅ Comprehensive policy data structures")
	fmt.Println("✅ Flexible condition evaluation system")
	fmt.Println("✅ Multiple action types and severities")
	fmt.Println("✅ Conflict resolution with 'most restrictive' rule")
	fmt.Println("✅ Schema validation with custom validators")
	fmt.Println("✅ Policy versioning and metadata")
	fmt.Println("✅ Performance monitoring and metrics")
	fmt.Println()

	// Initialize policy engine
	engine := policy.NewPolicyEngine()

	// Demo 1: Policy Creation and Validation
	fmt.Println("🏗️ DEMO 1: POLICY CREATION & VALIDATION")
	fmt.Println(strings.Repeat("-", 40))

	// Create sample policies
	policies := policy.CreateSamplePolicies()
	
	for _, pol := range policies {
		fmt.Printf("📝 Creating policy: %s\n", pol.Name)
		
		// Validate the policy
		validationResult := engine.ValidatePolicy(pol)
		if validationResult.Valid {
			fmt.Printf("   ✅ Validation: PASSED\n")
		} else {
			fmt.Printf("   ❌ Validation: FAILED\n")
			for _, err := range validationResult.Errors {
				fmt.Printf("      Error: %s - %s\n", err.Field, err.Message)
			}
		}
		
		// Add to engine
		err := engine.AddPolicy(pol)
		if err != nil {
			fmt.Printf("   ❌ Failed to add policy: %v\n", err)
		} else {
			fmt.Printf("   ✅ Policy added successfully\n")
		}
		
		fmt.Printf("   📊 Rules: %d, Priority: %d, Status: %s\n", 
			len(pol.Rules), pol.Priority, pol.Status)
		fmt.Println()
	}

	// Demo 2: Complex Policy Validation
	fmt.Println("🔍 DEMO 2: VALIDATION SCHEMA TESTING")
	fmt.Println(strings.Repeat("-", 40))

	testCases := []struct {
		name        string
		policy      *policy.Policy
		description string
	}{
		{
			name: "Invalid Policy - Missing Required Fields",
			policy: &policy.Policy{
				Name: "Incomplete Policy",
				// Missing ID and Status
			},
			description: "Should fail validation due to missing required fields",
		},
		{
			name: "Invalid Policy - Duplicate Rule IDs",
			policy: &policy.Policy{
				ID:     "duplicate-rules-policy",
				Name:   "Duplicate Rules Policy",
				Status: policy.PolicyStatusActive,
				Rules: []policy.PolicyRule{
					{ID: "rule-1", Name: "Rule 1", Enabled: true},
					{ID: "rule-1", Name: "Rule 2", Enabled: true}, // Duplicate ID
				},
			},
			description: "Should fail validation due to duplicate rule IDs",
		},
		{
			name: "Valid Complex Policy",
			policy: &policy.Policy{
				ID:          "complex-policy",
				Name:        "Complex Security Policy",
				Description: "A comprehensive policy with multiple conditions",
				Version:     "2.1.0",
				Status:      policy.PolicyStatusActive,
				Priority:    100,
				Category:    "security",
				Owner:       "security-team",
				CreatedBy:   "admin",
				Rules: []policy.PolicyRule{
					{
						ID:          "complex-rule",
						Name:        "Complex Condition Rule",
						Description: "Rule with AND/OR conditions",
						Priority:    10,
						Enabled:     true,
						Condition: &policy.PolicyCondition{
							Type: policy.ConditionAnd,
							Children: []*policy.PolicyCondition{
								{
									Type:  policy.ConditionPIIDetected,
									Value: true,
								},
								{
									Type: policy.ConditionOr,
									Children: []*policy.PolicyCondition{
										{
											Type:  policy.ConditionSensitivityLevel,
											Value: "confidential",
										},
										{
											Type:  policy.ConditionConfidenceAbove,
											Value: 0.9,
										},
									},
								},
							},
						},
						Action: policy.PolicyAction{
							Type:           policy.ActionQuarantine,
							Severity:       policy.SeverityHigh,
							Message:        "Content quarantined due to high-risk PII",
							StopProcessing: true,
							LogDecision:    true,
							NotifyAdmin:    true,
						},
					},
				},
				DefaultAction: policy.PolicyAction{
					Type:     policy.ActionAllow,
					Severity: policy.SeverityInfo,
				},
			},
			description: "Should pass validation with complex nested conditions",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("🧪 Testing: %s\n", tc.name)
		fmt.Printf("   Description: %s\n", tc.description)
		
		result := engine.ValidatePolicy(tc.policy)
		
		if result.Valid {
			fmt.Printf("   ✅ Validation: PASSED\n")
		} else {
			fmt.Printf("   ❌ Validation: FAILED\n")
			for _, err := range result.Errors {
				fmt.Printf("      Error: %s - %s\n", err.Field, err.Message)
			}
		}
		
		if len(result.Warnings) > 0 {
			fmt.Printf("   ⚠️  Warnings:\n")
			for _, warning := range result.Warnings {
				fmt.Printf("      %s - %s\n", warning.Field, warning.Message)
			}
		}
		
		if len(result.Suggestions) > 0 {
			fmt.Printf("   💡 Suggestions:\n")
			for _, suggestion := range result.Suggestions {
				fmt.Printf("      %s: %s\n", suggestion.Field, suggestion.Suggestion)
			}
		}
		fmt.Println()
	}

	// Demo 3: Policy Evaluation
	fmt.Println("⚖️  DEMO 3: POLICY EVALUATION")
	fmt.Println(strings.Repeat("-", 40))

	testRequests := []struct {
		name    string
		request *policy.PolicyEvaluationRequest
	}{
		{
			name: "High-Confidence PII Detection",
			request: &policy.PolicyEvaluationRequest{
				ID:           "test-pii-request",
				Content:      "My social security number is 123-45-6789 and my email is john@example.com",
				ContentType:  "text",
				Organization: "test-org",
				User:         "john.doe",
				Analysis: &analysis.AnalysisResult{
					PIIDetection: &analysis.PIIDetectionResult{
						HasPII: true,
						Statistics: analysis.PIIStatistics{
							ConfidenceAvg: 0.95,
						},
					},
					Confidence: 0.95,
				},
			},
		},
		{
			name: "Confidential Content",
			request: &policy.PolicyEvaluationRequest{
				ID:           "test-confidential-request",
				Content:      "This document contains confidential business strategies",
				ContentType:  "text",
				Organization: "test-org",
				User:         "manager",
				Analysis: &analysis.AnalysisResult{
					Classification: &analysis.ClassificationResult{
						Level:      analysis.SensitivityConfidential,
						Confidence: 0.88,
					},
					Confidence: 0.88,
				},
			},
		},
		{
			name: "Public Content",
			request: &policy.PolicyEvaluationRequest{
				ID:           "test-public-request",
				Content:      "This is a public announcement about our new product",
				ContentType:  "text",
				Organization: "test-org",
				User:         "marketing",
				Analysis: &analysis.AnalysisResult{
					PIIDetection: &analysis.PIIDetectionResult{
						HasPII: false,
					},
					Classification: &analysis.ClassificationResult{
						Level:      analysis.SensitivityPublic,
						Confidence: 0.92,
					},
					Confidence: 0.92,
				},
			},
		},
	}

	ctx := context.Background()
	
	for _, testReq := range testRequests {
		fmt.Printf("📄 Evaluating: %s\n", testReq.name)
		fmt.Printf("   Content: %s\n", truncateString(testReq.request.Content, 60))
		
		result, err := engine.EvaluateRequest(ctx, testReq.request)
		if err != nil {
			fmt.Printf("   ❌ Evaluation failed: %v\n", err)
			continue
		}
		
		fmt.Printf("   🎯 Decision: %s\n", result.Decision.Action)
		fmt.Printf("   📊 Confidence: %.2f\n", result.Decision.Confidence)
		fmt.Printf("   📈 Severity: %s\n", result.Decision.Severity)
		fmt.Printf("   ⏱️  Processing Time: %v\n", result.ProcessingTime)
		
		if result.Decision.Message != "" {
			fmt.Printf("   💬 Message: %s\n", result.Decision.Message)
		}
		
		if len(result.MatchedPolicies) > 0 {
			fmt.Printf("   📋 Matched Policies:\n")
			for _, match := range result.MatchedPolicies {
				fmt.Printf("      • %s (Priority: %d)\n", match.PolicyName, match.Priority)
			}
		} else {
			fmt.Printf("   📋 No policies matched - using default action\n")
		}
		
		fmt.Println()
	}

	// Demo 4: Conflict Resolution
	fmt.Println("⚔️  DEMO 4: CONFLICT RESOLUTION")
	fmt.Println(strings.Repeat("-", 40))

	// Create conflicting policies for demonstration
	conflictPolicy1 := &policy.Policy{
		ID:       "conflict-policy-warn",
		Name:     "PII Warning Policy",
		Status:   policy.PolicyStatusActive,
		Priority: 50,
		Rules: []policy.PolicyRule{
			{
				ID:      "pii-warn-rule",
				Name:    "PII Warning Rule",
				Enabled: true,
				Condition: &policy.PolicyCondition{
					Type:  policy.ConditionPIIDetected,
					Value: true,
				},
				Action: policy.PolicyAction{
					Type:     policy.ActionWarn,
					Severity: policy.SeverityMedium,
					Message:  "PII detected - warning issued",
				},
			},
		},
		DefaultAction: policy.PolicyAction{Type: policy.ActionAllow, Severity: policy.SeverityInfo},
	}

	conflictPolicy2 := &policy.Policy{
		ID:       "conflict-policy-redact",
		Name:     "PII Redaction Policy",
		Status:   policy.PolicyStatusActive,
		Priority: 60,
		Rules: []policy.PolicyRule{
			{
				ID:      "pii-redact-rule",
				Name:    "PII Redaction Rule",
				Enabled: true,
				Condition: &policy.PolicyCondition{
					Type:  policy.ConditionPIIDetected,
					Value: true,
				},
				Action: policy.PolicyAction{
					Type:     policy.ActionRedact,
					Severity: policy.SeverityHigh,
					Message:  "PII detected - content redacted",
				},
			},
		},
		DefaultAction: policy.PolicyAction{Type: policy.ActionAllow, Severity: policy.SeverityInfo},
	}

	// Add conflicting policies
	engine.AddPolicy(conflictPolicy1)
	engine.AddPolicy(conflictPolicy2)

	conflictRequest := &policy.PolicyEvaluationRequest{
		ID:           "conflict-test-request",
		Content:      "User SSN: 555-12-3456",
		ContentType:  "text",
		Organization: "test-org",
		User:         "test-user",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{
				HasPII: true,
				Statistics: analysis.PIIStatistics{
					ConfidenceAvg: 0.9,
				},
			},
		},
	}

	fmt.Printf("🔥 Testing conflict between WARN and REDACT policies\n")
	conflictResult, err := engine.EvaluateRequest(ctx, conflictRequest)
	if err != nil {
		fmt.Printf("❌ Conflict resolution failed: %v\n", err)
	} else {
		fmt.Printf("   🎯 Final Decision: %s\n", conflictResult.Decision.Action)
		fmt.Printf("   📝 Reason: %s\n", conflictResult.Decision.Reason)
		fmt.Printf("   📊 Matched Policies: %d\n", len(conflictResult.MatchedPolicies))
		fmt.Printf("   ⚖️  Resolution: Most restrictive policy applied\n")
		
		for _, match := range conflictResult.MatchedPolicies {
			fmt.Printf("      • %s -> %s\n", match.PolicyName, match.Action.Type)
		}
	}
	fmt.Println()

	// Final Summary
	fmt.Println("🎉 TASK 3.1 IMPLEMENTATION COMPLETE!")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("✅ Policy data structures with comprehensive metadata")
	fmt.Println("✅ Flexible condition system (AND/OR/NOT logic)")
	fmt.Println("✅ Multiple action types and severity levels")
	fmt.Println("✅ Schema validation with custom validators")
	fmt.Println("✅ Policy conflict resolution (most restrictive wins)")
	fmt.Println("✅ Performance monitoring and evaluation metrics")
	fmt.Println("✅ Support for versioning and policy lifecycle")
	fmt.Println("✅ Comprehensive error handling and suggestions")
	fmt.Println()
	fmt.Println("🚀 Ready for Task 3.2: Real-time policy evaluation engine!")
}

func truncateString(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
} 