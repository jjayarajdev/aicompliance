package analysis

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"ai-gateway-poc/internal/logging"
	"github.com/sirupsen/logrus"
)

// ContentClassifier represents the content classification engine
type ContentClassifier struct {
	piiDetector    *PIIDetector
	classifiers    map[SensitivityLevel]*LevelClassifier
	globalRules    []ClassificationRule
	logger         *logging.Logger
	config         *ContentClassifierConfig
}

// SensitivityLevel represents different content sensitivity levels
type SensitivityLevel string

const (
	SensitivityPublic       SensitivityLevel = "public"
	SensitivityInternal     SensitivityLevel = "internal"
	SensitivityConfidential SensitivityLevel = "confidential"
	SensitivityRestricted   SensitivityLevel = "restricted"
)

// ContentClassifierConfig holds configuration for the content classifier
type ContentClassifierConfig struct {
	Enabled            bool                              `mapstructure:"enabled"`
	DefaultLevel       SensitivityLevel                  `mapstructure:"default_level"`
	RequirePIIForLevel map[SensitivityLevel]bool         `mapstructure:"require_pii_for_level"`
	LevelConfigs       map[SensitivityLevel]LevelConfig  `mapstructure:"level_configs"`
	GlobalRules        []RuleConfig                      `mapstructure:"global_rules"`
	MinConfidence      float64                           `mapstructure:"min_confidence"`
	MaxTextSize        int                               `mapstructure:"max_text_size"`
}

// LevelConfig holds configuration for a specific sensitivity level
type LevelConfig struct {
	Keywords         []string    `mapstructure:"keywords"`
	Patterns         []string    `mapstructure:"patterns"`
	RequiredPIITypes []string    `mapstructure:"required_pii_types"`
	MinPIICount      int         `mapstructure:"min_pii_count"`
	Weight           float64     `mapstructure:"weight"`
	Enabled          bool        `mapstructure:"enabled"`
}

// RuleConfig holds configuration for classification rules
type RuleConfig struct {
	Name        string           `mapstructure:"name"`
	Level       SensitivityLevel `mapstructure:"level"`
	Conditions  []ConditionConfig `mapstructure:"conditions"`
	Weight      float64          `mapstructure:"weight"`
	Enabled     bool             `mapstructure:"enabled"`
}

// ConditionConfig holds configuration for rule conditions
type ConditionConfig struct {
	Type      string      `mapstructure:"type"`       // keyword, pattern, pii_count, pii_type
	Operator  string      `mapstructure:"operator"`   // contains, matches, >=, ==
	Value     interface{} `mapstructure:"value"`
	CaseSensitive bool    `mapstructure:"case_sensitive"`
}

// LevelClassifier handles classification for a specific sensitivity level
type LevelClassifier struct {
	level     SensitivityLevel
	keywords  []*regexp.Regexp
	patterns  []*regexp.Regexp
	config    LevelConfig
	logger    *logging.Logger
}

// ClassificationRule represents a classification rule
type ClassificationRule struct {
	Name       string
	Level      SensitivityLevel
	Conditions []Condition
	Weight     float64
	Enabled    bool
}

// Condition represents a classification condition
type Condition struct {
	Type          string
	Operator      string
	Value         interface{}
	CaseSensitive bool
}

// ClassificationResult represents the result of content classification
type ClassificationResult struct {
	Text               string                            `json:"text"`
	Level              SensitivityLevel                  `json:"level"`
	Confidence         float64                           `json:"confidence"`
	Scores             map[SensitivityLevel]float64      `json:"scores"`
	PIIResult          *PIIDetectionResult               `json:"pii_result,omitempty"`
	MatchedRules       []RuleMatch                       `json:"matched_rules"`
	MatchedKeywords    map[SensitivityLevel][]string     `json:"matched_keywords"`
	MatchedPatterns    map[SensitivityLevel][]string     `json:"matched_patterns"`
	ProcessedAt        time.Time                         `json:"processed_at"`
	Duration           time.Duration                     `json:"duration"`
	RecommendedActions []string                          `json:"recommended_actions"`
	Metadata           map[string]interface{}            `json:"metadata"`
}

// RuleMatch represents a matched classification rule
type RuleMatch struct {
	RuleName   string           `json:"rule_name"`
	Level      SensitivityLevel `json:"level"`
	Weight     float64          `json:"weight"`
	Conditions []ConditionMatch `json:"conditions"`
}

// ConditionMatch represents a matched condition
type ConditionMatch struct {
	Type      string      `json:"type"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Matched   bool        `json:"matched"`
	Details   string      `json:"details,omitempty"`
}

// Default classification keywords for different levels
var defaultKeywords = map[SensitivityLevel][]string{
	SensitivityPublic: {
		"public", "announcement", "press release", "marketing", "blog", "social media",
		"website", "published", "open source", "general information",
	},
	SensitivityInternal: {
		"internal", "employee", "staff", "team", "department", "meeting notes",
		"project", "internal communication", "company policy", "training",
	},
	SensitivityConfidential: {
		"confidential", "proprietary", "trade secret", "financial", "strategic",
		"business plan", "merger", "acquisition", "salary", "performance review",
		"customer data", "contract", "nda", "non-disclosure",
	},
	SensitivityRestricted: {
		"restricted", "classified", "top secret", "security", "password",
		"authentication", "encryption key", "api key", "token", "credential",
		"regulatory", "compliance", "audit", "investigation",
	},
}

// Default classification patterns
var classificationPatterns = map[SensitivityLevel][]string{
	SensitivityPublic: {
		`(?i)\b(public|open)\s+(information|data|document)\b`,
		`(?i)\bpress\s+release\b`,
		`(?i)\bmarketing\s+material\b`,
	},
	SensitivityInternal: {
		`(?i)\binternal\s+(use|only|document)\b`,
		`(?i)\bemployee\s+(handbook|manual|guide)\b`,
		`(?i)\bcompany\s+(policy|procedure)\b`,
	},
	SensitivityConfidential: {
		`(?i)\b(confidential|proprietary)\s+(information|data)\b`,
		`(?i)\btrade\s+secret\b`,
		`(?i)\bfinancial\s+(statement|report|data)\b`,
		`(?i)\bcustomer\s+(database|information|records)\b`,
	},
	SensitivityRestricted: {
		`(?i)\b(restricted|classified|top\s+secret)\b`,
		`(?i)\bsecurity\s+(audit|assessment|review)\b`,
		`(?i)\b(password|credential|token|key)\s+(list|database|store)\b`,
		`(?i)\bregulatory\s+(filing|compliance|investigation)\b`,
	},
}

// Confidence thresholds for different levels
var confidenceThresholds = map[SensitivityLevel]float64{
	SensitivityPublic:       0.3,
	SensitivityInternal:     0.5,
	SensitivityConfidential: 0.7,
	SensitivityRestricted:   0.9,
}

// NewContentClassifier creates a new content classifier instance
func NewContentClassifier(config *ContentClassifierConfig, piiDetector *PIIDetector, logger *logging.Logger) (*ContentClassifier, error) {
	if config == nil {
		config = getDefaultClassifierConfig()
	}

	if logger == nil {
		logger = logging.GetGlobalLogger()
	}

	classifier := &ContentClassifier{
		piiDetector: piiDetector,
		classifiers: make(map[SensitivityLevel]*LevelClassifier),
		globalRules: []ClassificationRule{},
		logger:      logger.WithComponent("content_classifier"),
		config:      config,
	}

	// Initialize level classifiers
	if err := classifier.initializeLevelClassifiers(); err != nil {
		return nil, fmt.Errorf("failed to initialize level classifiers: %w", err)
	}

	// Initialize global rules
	if err := classifier.initializeGlobalRules(); err != nil {
		return nil, fmt.Errorf("failed to initialize global rules: %w", err)
	}

	classifier.logger.Info("Content classifier initialized successfully")
	return classifier, nil
}

// initializeLevelClassifiers initializes classifiers for each sensitivity level
func (c *ContentClassifier) initializeLevelClassifiers() error {
	levels := []SensitivityLevel{
		SensitivityPublic, SensitivityInternal, 
		SensitivityConfidential, SensitivityRestricted,
	}

	for _, level := range levels {
		levelConfig := c.config.LevelConfigs[level]
		if levelConfig.Enabled {
			classifier, err := c.createLevelClassifier(level, levelConfig)
			if err != nil {
				return fmt.Errorf("failed to create classifier for level %s: %w", level, err)
			}
			c.classifiers[level] = classifier
		}
	}

	c.logger.WithFields(logrus.Fields{
		"classifiers_count": len(c.classifiers),
		"levels": func() []string {
			var levels []string
			for level := range c.classifiers {
				levels = append(levels, string(level))
			}
			return levels
		}(),
	}).Info("Level classifiers initialized")

	return nil
}

// createLevelClassifier creates a classifier for a specific level
func (c *ContentClassifier) createLevelClassifier(level SensitivityLevel, config LevelConfig) (*LevelClassifier, error) {
	classifier := &LevelClassifier{
		level:  level,
		config: config,
		logger: c.logger.WithComponent(fmt.Sprintf("classifier_%s", level)),
	}

	// Compile keyword patterns
	keywords := config.Keywords
	if len(keywords) == 0 {
		keywords = defaultKeywords[level]
	}

	for _, keyword := range keywords {
		pattern := fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(keyword))
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			classifier.logger.WithError(err).Warnf("Failed to compile keyword pattern: %s", keyword)
			continue
		}
		classifier.keywords = append(classifier.keywords, compiled)
	}

	// Compile regex patterns
	patterns := config.Patterns
	if len(patterns) == 0 {
		patterns = classificationPatterns[level]
	}

	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			classifier.logger.WithError(err).Warnf("Failed to compile pattern: %s", pattern)
			continue
		}
		classifier.patterns = append(classifier.patterns, compiled)
	}

	classifier.logger.WithFields(logrus.Fields{
		"level":           level,
		"keywords_count":  len(classifier.keywords),
		"patterns_count":  len(classifier.patterns),
	}).Info("Level classifier created")

	return classifier, nil
}

// initializeGlobalRules initializes global classification rules
func (c *ContentClassifier) initializeGlobalRules() error {
	for _, ruleConfig := range c.config.GlobalRules {
		if !ruleConfig.Enabled {
			continue
		}

		rule := ClassificationRule{
			Name:    ruleConfig.Name,
			Level:   ruleConfig.Level,
			Weight:  ruleConfig.Weight,
			Enabled: ruleConfig.Enabled,
		}

		// Convert condition configs to conditions
		for _, condConfig := range ruleConfig.Conditions {
			condition := Condition{
				Type:          condConfig.Type,
				Operator:      condConfig.Operator,
				Value:         condConfig.Value,
				CaseSensitive: condConfig.CaseSensitive,
			}
			rule.Conditions = append(rule.Conditions, condition)
		}

		c.globalRules = append(c.globalRules, rule)
	}

	c.logger.WithField("rules_count", len(c.globalRules)).Info("Global rules initialized")
	return nil
}

// ClassifyContent analyzes content and determines its sensitivity level
func (c *ContentClassifier) ClassifyContent(ctx context.Context, text string) (*ClassificationResult, error) {
	start := time.Now()

	// Check if classification is enabled
	if !c.config.Enabled {
		return &ClassificationResult{
			Text:        text,
			Level:       c.config.DefaultLevel,
			Confidence:  0.0,
			Scores:      make(map[SensitivityLevel]float64),
			ProcessedAt: start,
			Duration:    time.Since(start),
		}, nil
	}

	// Check text size limit
	if c.config.MaxTextSize > 0 && len(text) > c.config.MaxTextSize {
		return nil, fmt.Errorf("text size %d exceeds maximum allowed size %d", len(text), c.config.MaxTextSize)
	}

	// Initialize result
	result := &ClassificationResult{
		Text:            text,
		Level:           c.config.DefaultLevel,
		Scores:          make(map[SensitivityLevel]float64),
		MatchedKeywords: make(map[SensitivityLevel][]string),
		MatchedPatterns: make(map[SensitivityLevel][]string),
		ProcessedAt:     start,
		Metadata:        make(map[string]interface{}),
	}

	// Perform PII detection if detector is available
	if c.piiDetector != nil {
		piiResult, err := c.piiDetector.DetectPII(ctx, text)
		if err != nil {
			c.logger.WithError(err).Warn("Failed to perform PII detection during classification")
		} else {
			result.PIIResult = piiResult
		}
	}

	// Calculate scores for each level
	for level, classifier := range c.classifiers {
		score := c.calculateLevelScore(text, level, classifier, result)
		result.Scores[level] = score
	}

	// Apply global rules
	c.applyGlobalRules(text, result)

	// Determine final classification
	result.Level, result.Confidence = c.determineFinalClassification(result.Scores)

	// Generate recommendations
	result.RecommendedActions = c.generateRecommendations(result)

	// Add metadata
	result.Metadata["text_length"] = len(text)
	result.Metadata["pii_detected"] = result.PIIResult != nil && result.PIIResult.HasPII
	if result.PIIResult != nil {
		result.Metadata["pii_count"] = len(result.PIIResult.Matches)
		result.Metadata["pii_types"] = len(result.PIIResult.Statistics.MatchesByType)
	}

	result.Duration = time.Since(start)

	// Log classification results
	c.logger.WithFields(logrus.Fields{
		"text_length":     len(text),
		"classified_as":   result.Level,
		"confidence":      result.Confidence,
		"duration_ms":     result.Duration.Milliseconds(),
		"pii_detected":    result.PIIResult != nil && result.PIIResult.HasPII,
		"rules_matched":   len(result.MatchedRules),
	}).Info("Content classification completed")

	return result, nil
}

// calculateLevelScore calculates the score for a specific sensitivity level
func (c *ContentClassifier) calculateLevelScore(text string, level SensitivityLevel, classifier *LevelClassifier, result *ClassificationResult) float64 {
	var score float64
	var matches []string

	// Keyword matching
	for _, keywordPattern := range classifier.keywords {
		if keywordPattern.MatchString(text) {
			score += 1.0
			match := keywordPattern.FindString(text)
			matches = append(matches, match)
		}
	}

	// Pattern matching
	for _, pattern := range classifier.patterns {
		if pattern.MatchString(text) {
			score += 2.0 // Patterns are weighted higher than keywords
			match := pattern.FindString(text)
			result.MatchedPatterns[level] = append(result.MatchedPatterns[level], match)
		}
	}

	result.MatchedKeywords[level] = matches

	// PII-based scoring
	if result.PIIResult != nil && result.PIIResult.HasPII {
		piiScore := c.calculatePIIScore(level, result.PIIResult)
		score += piiScore
	}

	// Apply level weight
	score *= classifier.config.Weight

	// Normalize score (simple approach)
	if score > 0 {
		normalizedScore := score / (float64(len(classifier.keywords)) + float64(len(classifier.patterns)) + 10.0) // 10.0 for PII
		if normalizedScore > 1.0 {
			normalizedScore = 1.0
		}
		return normalizedScore
	}

	return 0.0
}

// calculatePIIScore calculates score contribution from PII detection
func (c *ContentClassifier) calculatePIIScore(level SensitivityLevel, piiResult *PIIDetectionResult) float64 {
	var score float64

	// Base score for having any PII
	if piiResult.HasPII {
		switch level {
		case SensitivityPublic:
			score -= 2.0 // PII reduces public score
		case SensitivityInternal:
			score += 1.0
		case SensitivityConfidential:
			score += 3.0
		case SensitivityRestricted:
			score += 5.0
		}
	}

	// Additional score based on PII types and count
	piiMultiplier := map[PIIType]float64{
		PIITypeSSN:        2.0,
		PIITypeCreditCard: 2.0,
		PIITypeEmail:      0.5,
		PIITypePhone:      0.5,
		PIITypeBankAccount: 1.5,
	}

	for piiType, count := range piiResult.Statistics.MatchesByType {
		multiplier := piiMultiplier[piiType]
		if multiplier == 0 {
			multiplier = 1.0
		}
		score += float64(count) * multiplier * 0.5
	}

	return score
}

// applyGlobalRules applies global classification rules
func (c *ContentClassifier) applyGlobalRules(text string, result *ClassificationResult) {
	for _, rule := range c.globalRules {
		if !rule.Enabled {
			continue
		}

		ruleMatch := RuleMatch{
			RuleName: rule.Name,
			Level:    rule.Level,
			Weight:   rule.Weight,
		}

		allConditionsMet := true
		for _, condition := range rule.Conditions {
			conditionMatch := c.evaluateCondition(condition, text, result)
			ruleMatch.Conditions = append(ruleMatch.Conditions, conditionMatch)
			if !conditionMatch.Matched {
				allConditionsMet = false
			}
		}

		if allConditionsMet {
			result.MatchedRules = append(result.MatchedRules, ruleMatch)
			// Boost score for the rule's level
			currentScore := result.Scores[rule.Level]
			result.Scores[rule.Level] = currentScore + rule.Weight
		}
	}
}

// evaluateCondition evaluates a single classification condition
func (c *ContentClassifier) evaluateCondition(condition Condition, text string, result *ClassificationResult) ConditionMatch {
	condMatch := ConditionMatch{
		Type:     condition.Type,
		Operator: condition.Operator,
		Value:    condition.Value,
		Matched:  false,
	}

	switch condition.Type {
	case "keyword":
		keyword := fmt.Sprintf("%v", condition.Value)
		if !condition.CaseSensitive {
			text = strings.ToLower(text)
			keyword = strings.ToLower(keyword)
		}
		
		switch condition.Operator {
		case "contains":
			condMatch.Matched = strings.Contains(text, keyword)
		case "matches":
			matched, _ := regexp.MatchString(keyword, text)
			condMatch.Matched = matched
		}

	case "pattern":
		pattern := fmt.Sprintf("%v", condition.Value)
		matched, _ := regexp.MatchString(pattern, text)
		condMatch.Matched = matched

	case "pii_count":
		if result.PIIResult != nil {
			count := len(result.PIIResult.Matches)
			expectedCount := int(condition.Value.(float64))
			
			switch condition.Operator {
			case ">=":
				condMatch.Matched = count >= expectedCount
			case "==":
				condMatch.Matched = count == expectedCount
			case ">":
				condMatch.Matched = count > expectedCount
			}
			condMatch.Details = fmt.Sprintf("PII count: %d", count)
		}

	case "pii_type":
		if result.PIIResult != nil {
			piiType := PIIType(fmt.Sprintf("%v", condition.Value))
			count := result.PIIResult.Statistics.MatchesByType[piiType]
			condMatch.Matched = count > 0
			condMatch.Details = fmt.Sprintf("PII type %s count: %d", piiType, count)
		}
	}

	return condMatch
}

// determineFinalClassification determines the final classification based on scores
func (c *ContentClassifier) determineFinalClassification(scores map[SensitivityLevel]float64) (SensitivityLevel, float64) {
	// Sort levels by score
	type levelScore struct {
		level SensitivityLevel
		score float64
	}

	var sortedScores []levelScore
	for level, score := range scores {
		sortedScores = append(sortedScores, levelScore{level, score})
	}

	sort.Slice(sortedScores, func(i, j int) bool {
		return sortedScores[i].score > sortedScores[j].score
	})

	if len(sortedScores) == 0 {
		return c.config.DefaultLevel, 0.0
	}

	topLevel := sortedScores[0].level
	topScore := sortedScores[0].score

	// Check if score meets minimum confidence threshold
	if topScore < c.config.MinConfidence {
		return c.config.DefaultLevel, topScore
	}

	return topLevel, topScore
}

// generateRecommendations generates actionable recommendations based on classification
func (c *ContentClassifier) generateRecommendations(result *ClassificationResult) []string {
	var recommendations []string

	switch result.Level {
	case SensitivityPublic:
		recommendations = append(recommendations, "Content can be shared publicly")
		if result.PIIResult != nil && result.PIIResult.HasPII {
			recommendations = append(recommendations, "WARNING: PII detected in public content - review before publishing")
		}

	case SensitivityInternal:
		recommendations = append(recommendations, "Restrict sharing to internal team members only")
		recommendations = append(recommendations, "Add appropriate access controls")

	case SensitivityConfidential:
		recommendations = append(recommendations, "Implement strict access controls")
		recommendations = append(recommendations, "Require NDA for external sharing")
		recommendations = append(recommendations, "Enable audit logging for access")

	case SensitivityRestricted:
		recommendations = append(recommendations, "CRITICAL: Implement maximum security measures")
		recommendations = append(recommendations, "Limit access to authorized personnel only")
		recommendations = append(recommendations, "Enable comprehensive audit logging")
		recommendations = append(recommendations, "Consider encryption for storage and transmission")
	}

	// PII-specific recommendations
	if result.PIIResult != nil && result.PIIResult.HasPII {
		recommendations = append(recommendations, "PII detected - ensure compliance with data protection regulations")
		if len(result.PIIResult.Matches) > 5 {
			recommendations = append(recommendations, "High PII density - consider additional protection measures")
		}
	}

	return recommendations
}

// getDefaultClassifierConfig returns default configuration for content classifier
func getDefaultClassifierConfig() *ContentClassifierConfig {
	return &ContentClassifierConfig{
		Enabled:       true,
		DefaultLevel:  SensitivityInternal,
		MinConfidence: 0.3,
		MaxTextSize:   1048576, // 1MB
		RequirePIIForLevel: map[SensitivityLevel]bool{
			SensitivityPublic:       false,
			SensitivityInternal:     false,
			SensitivityConfidential: false,
			SensitivityRestricted:   true,
		},
		LevelConfigs: map[SensitivityLevel]LevelConfig{
			SensitivityPublic: {
				Weight:  1.0,
				Enabled: true,
			},
			SensitivityInternal: {
				Weight:  1.0,
				Enabled: true,
			},
			SensitivityConfidential: {
				Weight:  1.2,
				Enabled: true,
			},
			SensitivityRestricted: {
				Weight:  1.5,
				Enabled: true,
			},
		},
		GlobalRules: []RuleConfig{},
	}
}

// AddCustomRule adds a custom classification rule
func (c *ContentClassifier) AddCustomRule(rule ClassificationRule) {
	c.globalRules = append(c.globalRules, rule)
	c.logger.WithFields(logrus.Fields{
		"rule_name": rule.Name,
		"level":     rule.Level,
		"weight":    rule.Weight,
	}).Info("Custom classification rule added")
}

// RemoveCustomRule removes a custom classification rule
func (c *ContentClassifier) RemoveCustomRule(ruleName string) {
	for i, rule := range c.globalRules {
		if rule.Name == ruleName {
			c.globalRules = append(c.globalRules[:i], c.globalRules[i+1:]...)
			c.logger.WithField("rule_name", ruleName).Info("Custom classification rule removed")
			return
		}
	}
}

// GetSupportedLevels returns all supported sensitivity levels
func (c *ContentClassifier) GetSupportedLevels() []SensitivityLevel {
	levels := make([]SensitivityLevel, 0, len(c.classifiers))
	for level := range c.classifiers {
		levels = append(levels, level)
	}
	return levels
}

// UpdateConfig updates the classifier configuration
func (c *ContentClassifier) UpdateConfig(config *ContentClassifierConfig) error {
	c.config = config
	
	// Reinitialize classifiers
	if err := c.initializeLevelClassifiers(); err != nil {
		return fmt.Errorf("failed to reinitialize level classifiers: %w", err)
	}
	
	// Reinitialize rules
	if err := c.initializeGlobalRules(); err != nil {
		return fmt.Errorf("failed to reinitialize global rules: %w", err)
	}
	
	c.logger.Info("Content classifier configuration updated")
	return nil
} 