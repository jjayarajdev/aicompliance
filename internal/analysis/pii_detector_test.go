package analysis

import (
	"context"
	"testing"
	"time"

	"ai-gateway-poc/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPIIDetector(t *testing.T) {
	tests := []struct {
		name      string
		config    *PIIDetectorConfig
		expectErr bool
	}{
		{
			name:      "default config",
			config:    nil,
			expectErr: false,
		},
		{
			name: "valid config",
			config: &PIIDetectorConfig{
				Enabled:          true,
				SensitivityLevel: "high",
				RedactionMode:    "mask",
			},
			expectErr: false,
		},
		{
			name: "config with custom patterns",
			config: &PIIDetectorConfig{
				Enabled: true,
				CustomPatterns: map[string]string{
					"test_pattern": `\bTEST\d+\b`,
				},
			},
			expectErr: false,
		},
		{
			name: "invalid custom pattern",
			config: &PIIDetectorConfig{
				Enabled: true,
				CustomPatterns: map[string]string{
					"invalid": `[invalid regex`,
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := logging.New(&logging.Config{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			})

			detector, err := NewPIIDetector(tt.config, logger)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, detector)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, detector)
			}
		})
	}
}

func TestDetectPII_SSN(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	tests := []struct {
		name     string
		text     string
		expected int
		piiType  PIIType
	}{
		{
			name:     "valid SSN with dashes",
			text:     "My SSN is 123-45-6789",
			expected: 1,
			piiType:  PIITypeSSN,
		},
		{
			name:     "valid SSN without dashes",
			text:     "My SSN is 123456789",
			expected: 1,
			piiType:  PIITypeSSN,
		},
		{
			name:     "invalid SSN",
			text:     "This is not an SSN: 12-34-567",
			expected: 0,
		},
		{
			name:     "multiple SSNs",
			text:     "SSN1: 123-45-6789, SSN2: 987-65-4321",
			expected: 2,
			piiType:  PIITypeSSN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.DetectPII(context.Background(), tt.text)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, len(result.Matches))
			assert.Equal(t, tt.expected > 0, result.HasPII)

			if tt.expected > 0 {
				assert.Equal(t, tt.piiType, result.Matches[0].Type)
				assert.Greater(t, result.Matches[0].Confidence, 0.0)
			}
		})
	}
}

func TestDetectPII_CreditCard(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{
			name:     "Visa card",
			text:     "Credit card: 4111111111111111",
			expected: 1,
		},
		{
			name:     "MasterCard",
			text:     "Card number: 5555555555554444",
			expected: 1,
		},
		{
			name:     "American Express",
			text:     "Amex: 378282246310005",
			expected: 1,
		},
		{
			name:     "card with spaces",
			text:     "My card: 4111 1111 1111 1111",
			expected: 1,
		},
		{
			name:     "card with dashes",
			text:     "Card: 4111-1111-1111-1111",
			expected: 1,
		},
		{
			name:     "invalid card",
			text:     "Not a card: 1234567890123456",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.DetectPII(context.Background(), tt.text)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, len(result.Matches))

			if tt.expected > 0 {
				assert.Equal(t, PIITypeCreditCard, result.Matches[0].Type)
			}
		})
	}
}

func TestDetectPII_Phone(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{
			name:     "phone with parentheses",
			text:     "Call me at (555) 123-4567",
			expected: 1,
		},
		{
			name:     "phone with dashes",
			text:     "Phone: 555-123-4567",
			expected: 1,
		},
		{
			name:     "phone with dots",
			text:     "Number: 555.123.4567",
			expected: 1,
		},
		{
			name:     "phone without formatting",
			text:     "Contact: 5551234567",
			expected: 1,
		},
		{
			name:     "international format",
			text:     "Call +1 555-123-4567",
			expected: 1,
		},
		{
			name:     "invalid phone",
			text:     "Not a phone: 123-45-67",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.DetectPII(context.Background(), tt.text)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, len(result.Matches))

			if tt.expected > 0 {
				assert.Equal(t, PIITypePhone, result.Matches[0].Type)
			}
		})
	}
}

func TestDetectPII_Email(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{
			name:     "simple email",
			text:     "Email me at john@example.com",
			expected: 1,
		},
		{
			name:     "email with subdomain",
			text:     "Contact: user@mail.example.com",
			expected: 1,
		},
		{
			name:     "email with numbers",
			text:     "Email: user123@example.org",
			expected: 1,
		},
		{
			name:     "email with special chars",
			text:     "Email: john.doe+test@example-site.co.uk",
			expected: 1,
		},
		{
			name:     "multiple emails",
			text:     "Emails: john@example.com and jane@test.org",
			expected: 2,
		},
		{
			name:     "invalid email",
			text:     "Not an email: user@",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := detector.DetectPII(context.Background(), tt.text)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, len(result.Matches))

			if tt.expected > 0 {
				assert.Equal(t, PIITypeEmail, result.Matches[0].Type)
			}
		})
	}
}

func TestDetectPII_MixedContent(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	text := `
	Personal Information:
	Name: John Doe
	Email: john.doe@example.com
	Phone: (555) 123-4567
	SSN: 123-45-6789
	Credit Card: 4111-1111-1111-1111
	Date of Birth: 01/15/1990
	IP Address: 192.168.1.100
	`

	result, err := detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	assert.True(t, result.HasPII)
	assert.Greater(t, len(result.Matches), 4) // At least email, phone, SSN, credit card

	// Check that we have different types
	typesSeen := make(map[PIIType]bool)
	for _, match := range result.Matches {
		typesSeen[match.Type] = true
	}

	expectedTypes := []PIIType{PIITypeEmail, PIITypePhone, PIITypeSSN, PIITypeCreditCard}
	for _, expectedType := range expectedTypes {
		assert.True(t, typesSeen[expectedType], "Expected to find PII type: %s", expectedType)
	}
}

func TestRedactionModes(t *testing.T) {
	tests := []struct {
		name          string
		redactionMode string
		text          string
		shouldRedact  bool
	}{
		{
			name:          "mask mode",
			redactionMode: "mask",
			text:          "SSN: 123-45-6789",
			shouldRedact:  true,
		},
		{
			name:          "remove mode",
			redactionMode: "remove",
			text:          "Email: john@example.com",
			shouldRedact:  true,
		},
		{
			name:          "hash mode",
			redactionMode: "hash",
			text:          "Phone: 555-123-4567",
			shouldRedact:  true,
		},
		{
			name:          "no redaction",
			redactionMode: "",
			text:          "SSN: 123-45-6789",
			shouldRedact:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PIIDetectorConfig{
				Enabled:       true,
				RedactionMode: tt.redactionMode,
			}

			logger, _ := logging.New(&logging.Config{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			})

			detector, err := NewPIIDetector(config, logger)
			require.NoError(t, err)

			result, err := detector.DetectPII(context.Background(), tt.text)
			require.NoError(t, err)

			if tt.shouldRedact {
				assert.NotEqual(t, tt.text, result.Text, "Text should be redacted")
				if len(result.Matches) > 0 {
					assert.NotEmpty(t, result.Matches[0].Redacted, "Match should have redacted value")
				}
			} else {
				assert.Equal(t, tt.text, result.Text, "Text should not be redacted")
			}
		})
	}
}

func TestCustomPatterns(t *testing.T) {
	config := &PIIDetectorConfig{
		Enabled: true,
		CustomPatterns: map[string]string{
			"employee_id": `\bEMP\d{6}\b`,
			"product_key": `\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`,
		},
	}

	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	detector, err := NewPIIDetector(config, logger)
	require.NoError(t, err)

	text := "Employee ID: EMP123456, Product Key: ABCDE-12345-FGHIJ"

	result, err := detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	assert.True(t, result.HasPII)
	assert.Equal(t, 2, len(result.Matches))

	// Check that custom patterns were detected
	foundEmployeeID := false
	foundProductKey := false
	for _, match := range result.Matches {
		if match.Type == PIIType("employee_id") {
			foundEmployeeID = true
			assert.Equal(t, "EMP123456", match.Value)
		}
		if match.Type == PIIType("product_key") {
			foundProductKey = true
			assert.Equal(t, "ABCDE-12345-FGHIJ", match.Value)
		}
	}

	assert.True(t, foundEmployeeID, "Should detect employee ID")
	assert.True(t, foundProductKey, "Should detect product key")
}

func TestExcludePatterns(t *testing.T) {
	config := &PIIDetectorConfig{
		Enabled: true,
		ExcludePatterns: []string{
			`test@example\.com`,
			`555-0123`,
		},
	}

	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	detector, err := NewPIIDetector(config, logger)
	require.NoError(t, err)

	text := "Real email: john@company.com, Test email: test@example.com, Phone: 555-0123, Real phone: 555-9876"

	result, err := detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	assert.True(t, result.HasPII)
	
	// Should only detect the non-excluded items
	foundExcluded := false
	for _, match := range result.Matches {
		if match.Value == "test@example.com" || match.Value == "555-0123" {
			foundExcluded = true
		}
	}

	assert.False(t, foundExcluded, "Excluded patterns should not be detected")
}

func TestSensitivityLevels(t *testing.T) {
	levels := []string{"low", "medium", "high"}
	
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			config := &PIIDetectorConfig{
				Enabled:          true,
				SensitivityLevel: level,
			}

			logger, _ := logging.New(&logging.Config{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			})

			detector, err := NewPIIDetector(config, logger)
			require.NoError(t, err)

			text := "Email: john@example.com"
			result, err := detector.DetectPII(context.Background(), text)
			require.NoError(t, err)

			if len(result.Matches) > 0 {
				match := result.Matches[0]
				assert.Greater(t, match.Confidence, 0.0)
				assert.LessOrEqual(t, match.Confidence, 1.0)
			}
		})
	}
}

func TestPerformance(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	// Large text with multiple PII instances
	text := ""
	for i := 0; i < 1000; i++ {
		text += "Email: user" + string(rune(i)) + "@example.com, Phone: 555-123-" + string(rune(4567+i%10)) + " "
	}

	start := time.Now()
	result, err := detector.DetectPII(context.Background(), text)
	duration := time.Since(start)

	require.NoError(t, err)
	assert.True(t, result.HasPII)
	assert.Greater(t, len(result.Matches), 0)
	assert.Less(t, duration.Milliseconds(), int64(1000), "Detection should complete within 1 second")

	t.Logf("Processed %d characters in %v, found %d matches", 
		len(text), duration, len(result.Matches))
}

func TestDisabledDetector(t *testing.T) {
	config := &PIIDetectorConfig{
		Enabled: false,
	}

	logger, _ := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})

	detector, err := NewPIIDetector(config, logger)
	require.NoError(t, err)

	text := "SSN: 123-45-6789, Email: john@example.com"
	result, err := detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	assert.False(t, result.HasPII)
	assert.Equal(t, 0, len(result.Matches))
	assert.Equal(t, text, result.Text)
}

func TestStatistics(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	text := "Email: john@example.com, Phone: 555-123-4567, SSN: 123-45-6789"
	result, err := detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	stats := result.Statistics
	assert.Equal(t, 3, stats.TotalMatches)
	assert.Equal(t, len(text), stats.TextLength)
	assert.Greater(t, stats.ConfidenceAvg, 0.0)
	assert.Greater(t, stats.ConfidenceMax, stats.ConfidenceMin)
	assert.Equal(t, 3, len(stats.MatchesByType))
}

func TestAddRemoveCustomPattern(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	// Add custom pattern
	err = detector.AddCustomPattern("custom_id", `\bCUST\d{4}\b`)
	require.NoError(t, err)

	text := "Customer ID: CUST1234"
	result, err := detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	assert.True(t, result.HasPII)
	assert.Equal(t, 1, len(result.Matches))
	assert.Equal(t, PIIType("custom_id"), result.Matches[0].Type)

	// Remove custom pattern
	detector.RemoveCustomPattern("custom_id")

	result, err = detector.DetectPII(context.Background(), text)
	require.NoError(t, err)

	assert.False(t, result.HasPII)
	assert.Equal(t, 0, len(result.Matches))
}

func TestGetSupportedTypes(t *testing.T) {
	detector, err := createTestDetector()
	require.NoError(t, err)

	types := detector.GetSupportedTypes()
	assert.Greater(t, len(types), 0)

	// Check for expected default types
	expectedTypes := []PIIType{PIITypeSSN, PIITypeEmail, PIITypePhone, PIITypeCreditCard}
	for _, expectedType := range expectedTypes {
		found := false
		for _, actualType := range types {
			if actualType == expectedType {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected type %s not found in supported types", expectedType)
	}
}

// Helper function to create a test detector
func createTestDetector() (*PIIDetector, error) {
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

// Benchmark tests
func BenchmarkDetectPII_Small(b *testing.B) {
	detector, _ := createTestDetector()
	text := "Email: john@example.com, Phone: 555-123-4567"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectPII(context.Background(), text)
	}
}

func BenchmarkDetectPII_Large(b *testing.B) {
	detector, _ := createTestDetector()
	
	// Create large text with PII
	text := ""
	for i := 0; i < 100; i++ {
		text += "This is a sample text with email john@example.com and phone 555-123-4567. "
		text += "SSN: 123-45-6789 and credit card 4111-1111-1111-1111. "
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectPII(context.Background(), text)
	}
} 