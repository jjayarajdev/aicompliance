package analysis

import (
	"context"
	"strings"
	"testing"

	"ai-gateway-poc/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewContentClassifier(t *testing.T) {
	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	piiDetector, _ := createTestPIIDetector()

	tests := []struct {
		name      string
		config    *ContentClassifierConfig
		expectErr bool
	}{
		{
			name:      "default config",
			config:    nil,
			expectErr: false,
		},
		{
			name: "valid config",
			config: &ContentClassifierConfig{
				Enabled:       true,
				DefaultLevel:  SensitivityInternal,
				MinConfidence: 0.5,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifier, err := NewContentClassifier(tt.config, piiDetector, logger)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, classifier)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, classifier)
			}
		})
	}
}

func TestClassifyContent_SensitivityLevels(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	tests := []struct {
		name          string
		text          string
		expectedLevel SensitivityLevel
		expectPII     bool
	}{
		{
			name:          "public announcement",
			text:          "This is a public announcement for our new product launch. Marketing materials available.",
			expectedLevel: SensitivityPublic,
			expectPII:     false,
		},
		{
			name:          "internal communication",
			text:          "Internal team meeting notes: Project status update for Q4. Employee handbook updates required.",
			expectedLevel: SensitivityInternal,
			expectPII:     false,
		},
		{
			name:          "confidential business plan",
			text:          "Confidential strategic business plan. Trade secret information about merger and acquisition targets. Financial data included.",
			expectedLevel: SensitivityConfidential,
			expectPII:     false,
		},
		{
			name:          "restricted security audit",
			text:          "Restricted security audit report. Password database review. Classified investigation findings.",
			expectedLevel: SensitivityRestricted,
			expectPII:     false,
		},
		{
			name:          "customer data with PII",
			text:          "Customer database contains email john@example.com, phone 555-123-4567, SSN 123-45-6789",
			expectedLevel: SensitivityConfidential,
			expectPII:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := classifier.ClassifyContent(context.Background(), tt.text)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedLevel, result.Level)
			assert.Greater(t, result.Confidence, 0.0)
			
			if tt.expectPII {
				assert.NotNil(t, result.PIIResult)
				assert.True(t, result.PIIResult.HasPII)
			}

			assert.NotEmpty(t, result.RecommendedActions)
			assert.NotEmpty(t, result.Metadata)
		})
	}
}

func TestClassifyContent_PIIIntegration(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	tests := []struct {
		name          string
		text          string
		expectedBoost bool // Should PII boost the sensitivity level
	}{
		{
			name:          "public content with PII should be flagged",
			text:          "Public blog post with author email contact@company.com",
			expectedBoost: false, // Email in public context might be okay
		},
		{
			name:          "document with sensitive PII",
			text:          "Employee record with SSN 123-45-6789 and credit card 4111-1111-1111-1111",
			expectedBoost: true,
		},
		{
			name:          "multiple PII types",
			text:          "Contact: john@example.com, Phone: 555-123-4567, Account: 1234567890123456",
			expectedBoost: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := classifier.ClassifyContent(context.Background(), tt.text)
			require.NoError(t, err)

			if tt.expectedBoost {
				// Should classify as at least Internal due to PII
				assert.True(t, 
					result.Level == SensitivityInternal || 
					result.Level == SensitivityConfidential || 
					result.Level == SensitivityRestricted)
			}

			assert.NotNil(t, result.PIIResult)
			assert.Contains(t, result.Metadata, "pii_detected")
		})
	}
}

func TestClassifyContent_CustomRules(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	// Add custom rule
	customRule := ClassificationRule{
		Name:   "API Key Detection",
		Level:  SensitivityRestricted,
		Weight: 2.0,
		Conditions: []Condition{
			{
				Type:     "pattern",
				Operator: "matches",
				Value:    `(?i)api[_-]?key[:=]\s*[a-zA-Z0-9]+`,
			},
		},
		Enabled: true,
	}
	classifier.AddCustomRule(customRule)

	text := "Configuration: API_KEY=abc123xyz789 for production access"
	result, err := classifier.ClassifyContent(context.Background(), text)
	require.NoError(t, err)

	assert.Equal(t, SensitivityRestricted, result.Level)
	assert.Greater(t, len(result.MatchedRules), 0)
	assert.Equal(t, "API Key Detection", result.MatchedRules[0].RuleName)
}

func TestClassifyContent_ScoreCalculation(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	text := "Confidential financial report with proprietary trade secrets"
	result, err := classifier.ClassifyContent(context.Background(), text)
	require.NoError(t, err)

	// Should have scores for multiple levels
	assert.Contains(t, result.Scores, SensitivityPublic)
	assert.Contains(t, result.Scores, SensitivityInternal)
	assert.Contains(t, result.Scores, SensitivityConfidential)
	assert.Contains(t, result.Scores, SensitivityRestricted)

	// Confidential should have highest score
	assert.Greater(t, result.Scores[SensitivityConfidential], result.Scores[SensitivityPublic])
	assert.Greater(t, result.Scores[SensitivityConfidential], result.Scores[SensitivityInternal])
}

func TestClassifyContent_KeywordMatching(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	tests := []struct {
		name     string
		text     string
		level    SensitivityLevel
		keywords []string
	}{
		{
			name:     "public keywords",
			text:     "Press release for marketing campaign",
			level:    SensitivityPublic,
			keywords: []string{"press", "marketing"},
		},
		{
			name:     "internal keywords",
			text:     "Employee training materials for team",
			level:    SensitivityInternal,
			keywords: []string{"employee", "team"},
		},
		{
			name:     "confidential keywords",
			text:     "Proprietary financial data for merger",
			level:    SensitivityConfidential,
			keywords: []string{"proprietary", "financial", "merger"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := classifier.ClassifyContent(context.Background(), tt.text)
			require.NoError(t, err)

			// Check that keywords were matched for the expected level
			matched := result.MatchedKeywords[tt.level]
			assert.Greater(t, len(matched), 0, "Should match keywords for level %s", tt.level)
		})
	}
}

func TestClassifyContent_EdgeCases(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	tests := []struct {
		name     string
		text     string
		expected SensitivityLevel
	}{
		{
			name:     "empty text",
			text:     "",
			expected: SensitivityInternal, // default level
		},
		{
			name:     "mixed signals",
			text:     "Public announcement about confidential merger", // conflicting keywords
			expected: SensitivityConfidential, // higher sensitivity wins
		},
		{
			name:     "case insensitive",
			text:     "CONFIDENTIAL INFORMATION PROPRIETARY",
			expected: SensitivityConfidential,
		},
		{
			name:     "no matching keywords",
			text:     "Random text without classification keywords xyz abc 123",
			expected: SensitivityInternal, // default level
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := classifier.ClassifyContent(context.Background(), tt.text)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result.Level)
		})
	}
}

func TestClassifyContent_Recommendations(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	tests := []struct {
		name                string
		text                string
		level               SensitivityLevel
		expectedRecommendations []string
	}{
		{
			name:  "public content",
			text:  "Public announcement",
			level: SensitivityPublic,
			expectedRecommendations: []string{"shared publicly"},
		},
		{
			name:  "restricted content",
			text:  "Classified security audit",
			level: SensitivityRestricted,
			expectedRecommendations: []string{"CRITICAL", "maximum security", "authorized personnel"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := classifier.ClassifyContent(context.Background(), tt.text)
			require.NoError(t, err)

			assert.NotEmpty(t, result.RecommendedActions)
			
			// Check for expected recommendation content
			recommendationText := strings.Join(result.RecommendedActions, " ")
			for _, expected := range tt.expectedRecommendations {
				assert.Contains(t, strings.ToLower(recommendationText), strings.ToLower(expected))
			}
		})
	}
}

func TestDisabledClassifier(t *testing.T) {
	config := &ContentClassifierConfig{
		Enabled:      false,
		DefaultLevel: SensitivityInternal,
	}

	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	classifier, err := NewContentClassifier(config, nil, logger)
	require.NoError(t, err)

	text := "Confidential information with trade secrets"
	result, err := classifier.ClassifyContent(context.Background(), text)
	require.NoError(t, err)

	assert.Equal(t, SensitivityInternal, result.Level)
	assert.Equal(t, 0.0, result.Confidence)
}

func TestSupportedLevels(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	levels := classifier.GetSupportedLevels()
	assert.Greater(t, len(levels), 0)

	expectedLevels := []SensitivityLevel{
		SensitivityPublic, SensitivityInternal, 
		SensitivityConfidential, SensitivityRestricted,
	}

	for _, expected := range expectedLevels {
		found := false
		for _, actual := range levels {
			if actual == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected level %s not found", expected)
	}
}

func TestCustomRuleManagement(t *testing.T) {
	classifier, err := createTestClassifier()
	require.NoError(t, err)

	// Add custom rule
	rule := ClassificationRule{
		Name:   "Test Rule",
		Level:  SensitivityRestricted,
		Weight: 1.0,
		Conditions: []Condition{
			{
				Type:     "keyword",
				Operator: "contains",
				Value:    "test-secret",
			},
		},
		Enabled: true,
	}

	classifier.AddCustomRule(rule)

	// Test that rule works
	text := "Document contains test-secret information"
	result, err := classifier.ClassifyContent(context.Background(), text)
	require.NoError(t, err)

	assert.Equal(t, SensitivityRestricted, result.Level)
	assert.Greater(t, len(result.MatchedRules), 0)

	// Remove rule
	classifier.RemoveCustomRule("Test Rule")

	// Test that rule no longer applies
	result2, err := classifier.ClassifyContent(context.Background(), text)
	require.NoError(t, err)

	assert.NotEqual(t, SensitivityRestricted, result2.Level)
}

// Helper function to create test classifier
func createTestClassifier() (*ContentClassifier, error) {
	config := getDefaultClassifierConfig()
	
	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	piiDetector, _ := createTestPIIDetector()

	return NewContentClassifier(config, piiDetector, logger)
}

// Helper function to create test PII detector
func createTestPIIDetector() (*PIIDetector, error) {
	config := &PIIDetectorConfig{
		Enabled:          true,
		SensitivityLevel: "medium",
		RedactionMode:    "mask",
		MaxTextSize:      1048576,
	}

	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	return NewPIIDetector(config, logger)
} 