package analysis

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"ai-gateway-poc/internal/logging"
	"github.com/sirupsen/logrus"
)

// PIIDetector represents the PII detection engine
type PIIDetector struct {
	patterns map[PIIType]*regexp.Regexp
	logger   *logging.Logger
	config   *PIIDetectorConfig
}

// PIIType represents different types of PII that can be detected
type PIIType string

const (
	PIITypeSSN           PIIType = "ssn"
	PIITypeCreditCard    PIIType = "credit_card"
	PIITypePhone         PIIType = "phone"
	PIITypeEmail         PIIType = "email"
	PIITypeDriversLicense PIIType = "drivers_license"
	PIITypePassport      PIIType = "passport"
	PIITypeBankAccount   PIIType = "bank_account"
	PIITypeIPAddress     PIIType = "ip_address"
	PIITypeDateOfBirth   PIIType = "date_of_birth"
	PIITypeCustom        PIIType = "custom"
)

// PIIDetectorConfig holds configuration for the PII detector
type PIIDetectorConfig struct {
	Enabled        bool                `mapstructure:"enabled"`
	Patterns       map[string]string   `mapstructure:"patterns"`
	SensitivityLevel string            `mapstructure:"sensitivity_level"` // low, medium, high
	RedactionMode  string              `mapstructure:"redaction_mode"`    // mask, remove, hash
	CustomPatterns map[string]string   `mapstructure:"custom_patterns"`
	ExcludePatterns []string           `mapstructure:"exclude_patterns"`
	MaxTextSize    int                 `mapstructure:"max_text_size"`
}

// PIIMatch represents a detected PII instance
type PIIMatch struct {
	Type        PIIType `json:"type"`
	Value       string  `json:"value"`
	Position    int     `json:"position"`
	Length      int     `json:"length"`
	Confidence  float64 `json:"confidence"`
	Redacted    string  `json:"redacted,omitempty"`
	Context     string  `json:"context,omitempty"`
}

// PIIDetectionResult represents the result of PII detection
type PIIDetectionResult struct {
	Text         string     `json:"text"`
	OriginalText string     `json:"original_text"`
	Matches      []PIIMatch `json:"matches"`
	HasPII       bool       `json:"has_pii"`
	ProcessedAt  time.Time  `json:"processed_at"`
	Duration     time.Duration `json:"duration"`
	Statistics   PIIStatistics `json:"statistics"`
}

// PIIStatistics provides statistics about detected PII
type PIIStatistics struct {
	TotalMatches   int                `json:"total_matches"`
	MatchesByType  map[PIIType]int    `json:"matches_by_type"`
	ConfidenceAvg  float64            `json:"confidence_avg"`
	ConfidenceMin  float64            `json:"confidence_min"`
	ConfidenceMax  float64            `json:"confidence_max"`
	TextLength     int                `json:"text_length"`
	RedactedLength int                `json:"redacted_length"`
}

// Default regex patterns for various PII types
var defaultPatterns = map[PIIType]string{
	// Social Security Numbers (US format: XXX-XX-XXXX or XXXXXXXXX)
	PIITypeSSN: `\b(?:\d{3}-?\d{2}-?\d{4})\b`,
	
	// Credit Card Numbers (with optional spaces/dashes)
	PIITypeCreditCard: `\b(?:4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}|3[0-9]\d{2}[\s\-]?\d{6}[\s\-]?\d{4}|6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b`,
	
	// Phone Numbers (US format: (XXX) XXX-XXXX, XXX-XXX-XXXX, XXXXXXXXXX)
	PIITypePhone: `\b(?:\+?1[\s\-\.]?)?\(?([0-9]{3})\)?[\s\-\.]?([0-9]{3})[\s\-\.]?([0-9]{4})\b`,
	
	// Email Addresses
	PIITypeEmail: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
	
	// Driver's License (basic pattern, varies by state)
	PIITypeDriversLicense: `\b[A-Z]{1,2}[0-9]{6,8}\b`,
	
	// Passport Numbers (basic pattern)
	PIITypePassport: `\b[A-Z0-9]{6,9}\b`,
	
	// Bank Account Numbers (8-17 digits)
	PIITypeBankAccount: `\b\d{8,17}\b`,
	
	// IP Addresses (IPv4)
	PIITypeIPAddress: `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
	
	// Date of Birth (MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD)
	PIITypeDateOfBirth: `\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12][0-9]|3[01])[\/\-](?:19|20)\d{2}\b|\b(?:19|20)\d{2}[\/\-](?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12][0-9]|3[01])\b`,
}

// Confidence scores for different PII types
var confidenceScores = map[PIIType]float64{
	PIITypeSSN:            0.95,
	PIITypeCreditCard:     0.90,
	PIITypePhone:          0.85,
	PIITypeEmail:          0.95,
	PIITypeDriversLicense: 0.70,
	PIITypePassport:       0.75,
	PIITypeBankAccount:    0.65,
	PIITypeIPAddress:      0.80,
	PIITypeDateOfBirth:    0.60,
}

// NewPIIDetector creates a new PII detector instance
func NewPIIDetector(config *PIIDetectorConfig, logger *logging.Logger) (*PIIDetector, error) {
	if config == nil {
		config = getDefaultPIIConfig()
	}

	if logger == nil {
		logger = logging.GetGlobalLogger()
	}

	detector := &PIIDetector{
		patterns: make(map[PIIType]*regexp.Regexp),
		logger:   logger.WithComponent("pii_detector"),
		config:   config,
	}

	// Compile regex patterns
	if err := detector.compilePatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile PII patterns: %w", err)
	}

	detector.logger.Info("PII detector initialized successfully")
	return detector, nil
}

// compilePatterns compiles all regex patterns for PII detection
func (p *PIIDetector) compilePatterns() error {
	// Compile default patterns
	for piiType, pattern := range defaultPatterns {
		// Check if custom pattern exists
		if customPattern, exists := p.config.Patterns[string(piiType)]; exists {
			pattern = customPattern
		}

		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern for %s: %w", piiType, err)
		}
		p.patterns[piiType] = compiled
	}

	// Compile custom patterns
	for name, pattern := range p.config.CustomPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			p.logger.WithError(err).Warnf("Failed to compile custom pattern %s", name)
			continue
		}
		p.patterns[PIIType(name)] = compiled
	}

	p.logger.WithFields(logrus.Fields{
		"patterns_count": len(p.patterns),
		"custom_patterns": len(p.config.CustomPatterns),
	}).Info("PII patterns compiled successfully")

	return nil
}

// DetectPII analyzes text for PII and returns detection results
func (p *PIIDetector) DetectPII(ctx context.Context, text string) (*PIIDetectionResult, error) {
	start := time.Now()

	// Check if detection is enabled
	if !p.config.Enabled {
		return &PIIDetectionResult{
			Text:         text,
			OriginalText: text,
			Matches:      []PIIMatch{},
			HasPII:       false,
			ProcessedAt:  start,
			Duration:     time.Since(start),
		}, nil
	}

	// Check text size limit
	if p.config.MaxTextSize > 0 && len(text) > p.config.MaxTextSize {
		return nil, fmt.Errorf("text size %d exceeds maximum allowed size %d", len(text), p.config.MaxTextSize)
	}

	// Initialize result
	result := &PIIDetectionResult{
		Text:         text,
		OriginalText: text,
		Matches:      []PIIMatch{},
		ProcessedAt:  start,
		Statistics: PIIStatistics{
			MatchesByType: make(map[PIIType]int),
			TextLength:   len(text),
		},
	}

	// Detect PII for each pattern
	allMatches := []PIIMatch{}
	for piiType, pattern := range p.patterns {
		matches := pattern.FindAllStringIndex(text, -1)
		for _, match := range matches {
			if p.shouldExcludeMatch(text[match[0]:match[1]]) {
				continue
			}

			piiMatch := PIIMatch{
				Type:       piiType,
				Value:      text[match[0]:match[1]],
				Position:   match[0],
				Length:     match[1] - match[0],
				Confidence: p.calculateConfidence(piiType, text[match[0]:match[1]]),
				Context:    p.extractContext(text, match[0], match[1]),
			}

			// Apply redaction if configured
			if p.config.RedactionMode != "" {
				piiMatch.Redacted = p.redactPII(piiMatch.Value, piiMatch.Type)
			}

			allMatches = append(allMatches, piiMatch)
		}
	}

	// Sort matches by position and remove overlaps
	result.Matches = p.removeDuplicateMatches(allMatches)
	result.HasPII = len(result.Matches) > 0

	// Apply redaction to text if configured
	if p.config.RedactionMode != "" {
		result.Text = p.redactText(text, result.Matches)
	}

	// Calculate statistics
	result.Statistics = p.calculateStatistics(result.Matches, len(text), len(result.Text))
	result.Duration = time.Since(start)

	// Log detection results
	p.logger.WithFields(logrus.Fields{
		"text_length":    len(text),
		"matches_found":  len(result.Matches),
		"has_pii":        result.HasPII,
		"duration_ms":    result.Duration.Milliseconds(),
		"matches_by_type": result.Statistics.MatchesByType,
	}).Info("PII detection completed")

	return result, nil
}

// shouldExcludeMatch checks if a match should be excluded based on exclude patterns
func (p *PIIDetector) shouldExcludeMatch(value string) bool {
	for _, excludePattern := range p.config.ExcludePatterns {
		if matched, _ := regexp.MatchString(excludePattern, value); matched {
			return true
		}
	}
	return false
}

// calculateConfidence calculates confidence score for a PII match
func (p *PIIDetector) calculateConfidence(piiType PIIType, value string) float64 {
	baseConfidence := confidenceScores[piiType]
	
	// Apply sensitivity level adjustments
	switch p.config.SensitivityLevel {
	case "high":
		return baseConfidence * 1.1 // Increase confidence
	case "low":
		return baseConfidence * 0.9 // Decrease confidence
	default: // medium
		return baseConfidence
	}
}

// extractContext extracts surrounding context for a PII match
func (p *PIIDetector) extractContext(text string, start, end int) string {
	contextSize := 20
	contextStart := start - contextSize
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end + contextSize
	if contextEnd > len(text) {
		contextEnd = len(text)
	}
	
	context := text[contextStart:contextEnd]
	// Replace the actual PII with placeholder in context
	piiValue := text[start:end]
	redacted := strings.Repeat("*", len(piiValue))
	context = strings.Replace(context, piiValue, redacted, 1)
	
	return context
}

// redactPII redacts a PII value based on the configured redaction mode
func (p *PIIDetector) redactPII(value string, piiType PIIType) string {
	switch p.config.RedactionMode {
	case "mask":
		return p.maskValue(value, piiType)
	case "remove":
		return ""
	case "hash":
		return p.hashValue(value)
	default:
		return value
	}
}

// maskValue masks a PII value while preserving some structure
func (p *PIIDetector) maskValue(value string, piiType PIIType) string {
	switch piiType {
	case PIITypeSSN:
		// Show last 4 digits: XXX-XX-1234
		if len(value) >= 4 {
			return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
		}
	case PIITypeCreditCard:
		// Show last 4 digits: ****-****-****-1234
		digits := regexp.MustCompile(`\d`).FindAllString(value, -1)
		if len(digits) >= 4 {
			masked := strings.Repeat("*", len(digits)-4) + strings.Join(digits[len(digits)-4:], "")
			return masked
		}
	case PIITypeEmail:
		// Show first character and domain: j***@example.com
		parts := strings.Split(value, "@")
		if len(parts) == 2 && len(parts[0]) > 1 {
			return string(parts[0][0]) + strings.Repeat("*", len(parts[0])-1) + "@" + parts[1]
		}
	case PIITypePhone:
		// Show last 4 digits: ***-***-1234
		digits := regexp.MustCompile(`\d`).FindAllString(value, -1)
		if len(digits) >= 4 {
			return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
		}
	}
	
	// Default masking
	return strings.Repeat("*", len(value))
}

// hashValue creates a hash of the PII value (simplified)
func (p *PIIDetector) hashValue(value string) string {
	// This is a simplified hash - in production, use proper cryptographic hashing
	return fmt.Sprintf("[HASH:%x]", len(value)*31+strings.Count(value, "1"))
}

// redactText applies redaction to the entire text based on detected matches
func (p *PIIDetector) redactText(text string, matches []PIIMatch) string {
	if len(matches) == 0 {
		return text
	}

	// Sort matches by position (descending) to avoid index shifting
	sortedMatches := make([]PIIMatch, len(matches))
	copy(sortedMatches, matches)
	
	// Simple sort by position (descending)
	for i := 0; i < len(sortedMatches)-1; i++ {
		for j := i + 1; j < len(sortedMatches); j++ {
			if sortedMatches[i].Position < sortedMatches[j].Position {
				sortedMatches[i], sortedMatches[j] = sortedMatches[j], sortedMatches[i]
			}
		}
	}

	result := text
	for _, match := range sortedMatches {
		redacted := match.Redacted
		if redacted == "" {
			redacted = p.redactPII(match.Value, match.Type)
		}
		
		start := match.Position
		end := match.Position + match.Length
		result = result[:start] + redacted + result[end:]
	}

	return result
}

// removeDuplicateMatches removes overlapping and duplicate matches
func (p *PIIDetector) removeDuplicateMatches(matches []PIIMatch) []PIIMatch {
	if len(matches) <= 1 {
		return matches
	}

	// Sort by position
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i].Position > matches[j].Position {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	result := []PIIMatch{}
	for i, match := range matches {
		// Check for overlap with previous match
		if i > 0 {
			prev := result[len(result)-1]
			if match.Position < prev.Position+prev.Length {
				// Overlapping - keep the one with higher confidence
				if match.Confidence > prev.Confidence {
					result[len(result)-1] = match
				}
				continue
			}
		}
		result = append(result, match)
	}

	return result
}

// calculateStatistics calculates statistics for the detection result
func (p *PIIDetector) calculateStatistics(matches []PIIMatch, originalLength, redactedLength int) PIIStatistics {
	stats := PIIStatistics{
		TotalMatches:   len(matches),
		MatchesByType:  make(map[PIIType]int),
		TextLength:     originalLength,
		RedactedLength: redactedLength,
		ConfidenceMin:  1.0,
		ConfidenceMax:  0.0,
	}

	if len(matches) == 0 {
		return stats
	}

	var totalConfidence float64
	for _, match := range matches {
		stats.MatchesByType[match.Type]++
		totalConfidence += match.Confidence
		
		if match.Confidence < stats.ConfidenceMin {
			stats.ConfidenceMin = match.Confidence
		}
		if match.Confidence > stats.ConfidenceMax {
			stats.ConfidenceMax = match.Confidence
		}
	}

	stats.ConfidenceAvg = totalConfidence / float64(len(matches))
	return stats
}

// getDefaultPIIConfig returns default configuration for PII detector
func getDefaultPIIConfig() *PIIDetectorConfig {
	return &PIIDetectorConfig{
		Enabled:          true,
		Patterns:         make(map[string]string),
		SensitivityLevel: "medium",
		RedactionMode:    "mask",
		CustomPatterns:   make(map[string]string),
		ExcludePatterns:  []string{},
		MaxTextSize:      1048576, // 1MB
	}
}

// AddCustomPattern adds a custom PII detection pattern
func (p *PIIDetector) AddCustomPattern(name string, pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	p.patterns[PIIType(name)] = compiled
	p.config.CustomPatterns[name] = pattern

	p.logger.WithFields(logrus.Fields{
		"pattern_name": name,
		"pattern":      pattern,
	}).Info("Custom PII pattern added")

	return nil
}

// RemoveCustomPattern removes a custom PII detection pattern
func (p *PIIDetector) RemoveCustomPattern(name string) {
	delete(p.patterns, PIIType(name))
	delete(p.config.CustomPatterns, name)

	p.logger.WithField("pattern_name", name).Info("Custom PII pattern removed")
}

// GetSupportedTypes returns all supported PII types
func (p *PIIDetector) GetSupportedTypes() []PIIType {
	types := make([]PIIType, 0, len(p.patterns))
	for piiType := range p.patterns {
		types = append(types, piiType)
	}
	return types
}

// UpdateConfig updates the detector configuration
func (p *PIIDetector) UpdateConfig(config *PIIDetectorConfig) error {
	p.config = config
	return p.compilePatterns()
} 