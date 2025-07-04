package policy

import (
	"context"
	"testing"

	"ai-gateway-poc/internal/analysis"
)

func TestPolicyEngine_NewPolicyEngine(t *testing.T) {
	engine := NewPolicyEngine()
	
	if engine == nil {
		t.Fatal("Expected non-nil policy engine")
	}
	
	if engine.validator == nil {
		t.Fatal("Expected validator to be initialized")
	}
	
	if engine.policies == nil {
		t.Fatal("Expected policies map to be initialized")
	}
}

func TestPolicyEngine_AddPolicy(t *testing.T) {
	engine := NewPolicyEngine()
	
	policy := &Policy{
		ID:          "test-policy",
		Name:        "Test Policy",
		Description: "A test policy",
		Version:     "1.0.0",
		Status:      PolicyStatusActive,
		Priority:    10,
		Category:    "test",
		Owner:       "test-team",
		CreatedBy:   "test-user",
		Rules: []PolicyRule{
			{
				ID:          "test-rule",
				Name:        "Test Rule",
				Description: "A test rule",
				Priority:    10,
				Enabled:     true,
				Condition: &PolicyCondition{
					Type:  ConditionPIIDetected,
					Value: true,
				},
				Action: PolicyAction{
					Type:     ActionBlock,
					Severity: SeverityHigh,
					Message:  "Blocked due to PII",
				},
			},
		},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}
	
	err := engine.AddPolicy(policy)
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}
	
	// Verify policy was stored
	stored, err := engine.GetPolicy(policy.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve policy: %v", err)
	}
	
	if stored.Name != policy.Name {
		t.Errorf("Expected name %s, got %s", policy.Name, stored.Name)
	}
	
	if stored.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
}

func TestPolicyEngine_ValidatePolicy(t *testing.T) {
	engine := NewPolicyEngine()
	
	testCases := []struct {
		name        string
		policy      *Policy
		shouldError bool
	}{
		{
			name: "Valid Policy",
			policy: &Policy{
				ID:     "valid-policy",
				Name:   "Valid Policy",
				Status: PolicyStatusActive,
				DefaultAction: PolicyAction{
					Type:     ActionAllow,
					Severity: SeverityInfo,
				},
			},
			shouldError: false,
		},
		{
			name: "Missing ID",
			policy: &Policy{
				Name:   "No ID Policy",
				Status: PolicyStatusActive,
				DefaultAction: PolicyAction{
					Type:     ActionAllow,
					Severity: SeverityInfo,
				},
			},
			shouldError: true,
		},
		{
			name: "Invalid Status",
			policy: &Policy{
				ID:     "invalid-status-policy",
				Name:   "Invalid Status Policy",
				Status: PolicyStatus("invalid"),
				DefaultAction: PolicyAction{
					Type:     ActionAllow,
					Severity: SeverityInfo,
				},
			},
			shouldError: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := engine.ValidatePolicy(tc.policy)
			
			if tc.shouldError && result.Valid {
				t.Error("Expected validation to fail but it passed")
			}
			
			if !tc.shouldError && !result.Valid {
				t.Errorf("Expected validation to pass but it failed: %v", result.Errors)
			}
		})
	}
}

func TestPolicyEngine_EvaluateRequest(t *testing.T) {
	engine := NewPolicyEngine()
	
	// Add test policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		err := engine.AddPolicy(policy)
		if err != nil {
			t.Fatalf("Failed to add policy: %v", err)
		}
	}
	
	testCases := []struct {
		name             string
		request          *PolicyEvaluationRequest
		expectedAction   ActionType
		expectedPolicies int
	}{
		{
			name: "PII Detected - Should Block",
			request: &PolicyEvaluationRequest{
				ID:           "test-request-1",
				Content:      "My SSN is 123-45-6789",
				ContentType:  "text",
				Organization: "test-org",
				User:         "test-user",
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
			expectedAction:   ActionBlock,
			expectedPolicies: 1,
		},
		{
			name: "Confidential Content - Should Redact",
			request: &PolicyEvaluationRequest{
				ID:           "test-request-2",
				Content:      "Confidential business plan",
				ContentType:  "text",
				Organization: "test-org",
				User:         "test-user",
				Analysis: &analysis.AnalysisResult{
					Classification: &analysis.ClassificationResult{
						Level: analysis.SensitivityConfidential,
					},
					Confidence: 0.8,
				},
			},
			expectedAction:   ActionRedact,
			expectedPolicies: 1,
		},
		{
			name: "Normal Content - Should Allow",
			request: &PolicyEvaluationRequest{
				ID:           "test-request-3",
				Content:      "Hello world",
				ContentType:  "text",
				Organization: "test-org",
				User:         "test-user",
				Analysis: &analysis.AnalysisResult{
					PIIDetection: &analysis.PIIDetectionResult{
						HasPII: false,
					},
					Classification: &analysis.ClassificationResult{
						Level: analysis.SensitivityPublic,
					},
					Confidence: 0.9,
				},
			},
			expectedAction:   ActionAllow,
			expectedPolicies: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := engine.EvaluateRequest(ctx, tc.request)
			
			if err != nil {
				t.Fatalf("Failed to evaluate request: %v", err)
			}
			
			if result.Decision.Action != tc.expectedAction {
				t.Errorf("Expected action %s, got %s", tc.expectedAction, result.Decision.Action)
			}
			
			if len(result.MatchedPolicies) != tc.expectedPolicies {
				t.Errorf("Expected %d matched policies, got %d", tc.expectedPolicies, len(result.MatchedPolicies))
			}
			
			if result.ProcessingTime <= 0 {
				t.Error("Expected positive processing time")
			}
		})
	}
}

func TestPolicyValidator_ValidatePolicy(t *testing.T) {
	validator := NewPolicyValidator()
	
	policy := &Policy{
		ID:          "test-policy",
		Name:        "Test Policy",
		Description: "A comprehensive test policy",
		Version:     "1.0.0",
		Status:      PolicyStatusActive,
		Priority:    50,
		Category:    "security",
		Owner:       "security-team",
		CreatedBy:   "admin",
		Rules: []PolicyRule{
			{
				ID:          "rule-1",
				Name:        "Test Rule 1",
				Description: "First test rule",
				Priority:    10,
				Enabled:     true,
				Condition: &PolicyCondition{
					Type:  ConditionPIIDetected,
					Value: true,
				},
				Action: PolicyAction{
					Type:     ActionBlock,
					Severity: SeverityHigh,
				},
			},
		},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}
	
	result := validator.ValidatePolicy(policy)
	
	if !result.Valid {
		t.Errorf("Expected policy to be valid, but got errors: %v", result.Errors)
	}
	
	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors, got: %v", result.Errors)
	}
	
	// Check suggestions
	if len(result.Suggestions) == 0 {
		t.Log("No suggestions generated - this is fine")
	}
}

func TestPolicyValidator_ValidateConditions(t *testing.T) {
	validator := NewPolicyValidator()
	
	testCases := []struct {
		name        string
		condition   *PolicyCondition
		shouldError bool
	}{
		{
			name: "Valid AND condition",
			condition: &PolicyCondition{
				Type: ConditionAnd,
				Children: []*PolicyCondition{
					{Type: ConditionPIIDetected, Value: true},
					{Type: ConditionConfidenceAbove, Value: 0.8},
				},
			},
			shouldError: false,
		},
		{
			name: "Invalid AND condition - insufficient children",
			condition: &PolicyCondition{
				Type: ConditionAnd,
				Children: []*PolicyCondition{
					{Type: ConditionPIIDetected, Value: true},
				},
			},
			shouldError: true,
		},
		{
			name: "Valid simple condition",
			condition: &PolicyCondition{
				Type:  ConditionSensitivityLevel,
				Value: "confidential",
			},
			shouldError: false,
		},
		{
			name: "Invalid condition type",
			condition: &PolicyCondition{
				Type:  ConditionType("invalid_type"),
				Value: true,
			},
			shouldError: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := validator.ValidateCondition(tc.condition)
			
			if tc.shouldError && result.Valid {
				t.Error("Expected validation to fail but it passed")
			}
			
			if !tc.shouldError && !result.Valid {
				t.Errorf("Expected validation to pass but it failed: %v", result.Errors)
			}
		})
	}
}

func TestPolicyEngine_ConflictResolution(t *testing.T) {
	engine := NewPolicyEngine()
	
	// Create conflicting policies
	blockPolicy := &Policy{
		ID:       "block-policy",
		Name:     "Block Policy",
		Status:   PolicyStatusActive,
		Priority: 100,
		Rules: []PolicyRule{
			{
				ID:      "block-rule",
				Name:    "Block Rule",
				Enabled: true,
				Condition: &PolicyCondition{
					Type:  ConditionPIIDetected,
					Value: true,
				},
				Action: PolicyAction{
					Type:     ActionBlock,
					Severity: SeverityHigh,
				},
			},
		},
		DefaultAction: PolicyAction{Type: ActionAllow, Severity: SeverityInfo},
	}
	
	warnPolicy := &Policy{
		ID:       "warn-policy",
		Name:     "Warn Policy",
		Status:   PolicyStatusActive,
		Priority: 90,
		Rules: []PolicyRule{
			{
				ID:      "warn-rule",
				Name:    "Warn Rule",
				Enabled: true,
				Condition: &PolicyCondition{
					Type:  ConditionPIIDetected,
					Value: true,
				},
				Action: PolicyAction{
					Type:     ActionWarn,
					Severity: SeverityMedium,
				},
			},
		},
		DefaultAction: PolicyAction{Type: ActionAllow, Severity: SeverityInfo},
	}
	
	engine.AddPolicy(blockPolicy)
	engine.AddPolicy(warnPolicy)
	
	// Test conflict resolution
	request := &PolicyEvaluationRequest{
		ID:           "conflict-test",
		Content:      "SSN: 123-45-6789",
		Organization: "test-org",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{HasPII: true},
		},
	}
	
	ctx := context.Background()
	result, err := engine.EvaluateRequest(ctx, request)
	
	if err != nil {
		t.Fatalf("Failed to evaluate request: %v", err)
	}
	
	// Should choose the most restrictive action (Block over Warn)
	if result.Decision.Action != ActionBlock {
		t.Errorf("Expected Block action due to conflict resolution, got %s", result.Decision.Action)
	}
	
	if len(result.MatchedPolicies) != 2 {
		t.Errorf("Expected 2 matched policies, got %d", len(result.MatchedPolicies))
	}
}

func TestCreateSamplePolicies(t *testing.T) {
	policies := CreateSamplePolicies()
	
	if len(policies) == 0 {
		t.Fatal("Expected sample policies to be created")
	}
	
	validator := NewPolicyValidator()
	
	// Validate all sample policies
	for _, policy := range policies {
		result := validator.ValidatePolicy(policy)
		if !result.Valid {
			t.Errorf("Sample policy %s is invalid: %v", policy.ID, result.Errors)
		}
	}
}

func BenchmarkPolicyEngine_EvaluateRequest(b *testing.B) {
	engine := NewPolicyEngine()
	
	// Add sample policies
	policies := CreateSamplePolicies()
	for _, policy := range policies {
		engine.AddPolicy(policy)
	}
	
	request := &PolicyEvaluationRequest{
		ID:           "benchmark-request",
		Content:      "Test content with SSN 123-45-6789",
		Organization: "test-org",
		User:         "test-user",
		Analysis: &analysis.AnalysisResult{
			PIIDetection: &analysis.PIIDetectionResult{
				HasPII: true,
				Statistics: analysis.PIIStatistics{
					ConfidenceAvg: 0.95,
				},
			},
			Confidence: 0.95,
		},
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluateRequest(ctx, request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyValidator_ValidatePolicy(b *testing.B) {
	validator := NewPolicyValidator()
	
	policy := &Policy{
		ID:          "benchmark-policy",
		Name:        "Benchmark Policy",
		Description: "A policy for benchmarking",
		Version:     "1.0.0",
		Status:      PolicyStatusActive,
		Priority:    50,
		Rules: []PolicyRule{
			{
				ID:      "benchmark-rule",
				Name:    "Benchmark Rule",
				Enabled: true,
				Condition: &PolicyCondition{
					Type: ConditionAnd,
					Children: []*PolicyCondition{
						{Type: ConditionPIIDetected, Value: true},
						{Type: ConditionConfidenceAbove, Value: 0.8},
					},
				},
				Action: PolicyAction{
					Type:     ActionBlock,
					Severity: SeverityHigh,
				},
			},
		},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := validator.ValidatePolicy(policy)
		if !result.Valid {
			b.Fatal("Policy validation failed")
		}
	}
} 