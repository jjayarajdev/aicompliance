package analysis

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"ai-gateway-poc/internal/logging"
	"github.com/sirupsen/logrus"
)

// MLAnalyzer represents the machine learning content analysis engine
type MLAnalyzer struct {
	config    *MLAnalyzerConfig
	logger    *logging.Logger
	providers map[string]MLProvider
	mutex     sync.RWMutex
}

// MLAnalyzerConfig holds configuration for ML-powered analysis
type MLAnalyzerConfig struct {
	Enabled            bool                    `mapstructure:"enabled"`
	DefaultProvider    string                  `mapstructure:"default_provider"`
	Timeout           time.Duration           `mapstructure:"timeout"`
	MinConfidenceScore float64                 `mapstructure:"min_confidence_score"`
	EnableSentiment    bool                    `mapstructure:"enable_sentiment"`
	EnableTopics       bool                    `mapstructure:"enable_topics"`
	EnableEntities     bool                    `mapstructure:"enable_entities"`
}

// MLProvider interface for ML service providers
type MLProvider interface {
	GetName() string
	AnalyzeContent(ctx context.Context, content string) (*MLAnalysisResult, error)
	ExtractEntities(ctx context.Context, content string) (*EntityResult, error)
	AnalyzeSentiment(ctx context.Context, content string) (*SentimentResult, error)
	ExtractTopics(ctx context.Context, content string) (*TopicResult, error)
	IsHealthy() bool
	Close() error
}

// MLAnalysisResult represents the result of ML analysis
type MLAnalysisResult struct {
	Content              string                 `json:"content"`
	BusinessCategories   []BusinessCategoryInfo `json:"business_categories"`
	Entities             *EntityResult          `json:"entities,omitempty"`
	Sentiment            *SentimentResult       `json:"sentiment,omitempty"`
	Topics               *TopicResult           `json:"topics,omitempty"`
	ConfidenceScore      float64                `json:"confidence_score"`
	ProcessingTime       time.Duration          `json:"processing_time"`
	ProviderUsed         string                 `json:"provider_used"`
	Recommendations      []string               `json:"recommendations"`
}

// BusinessCategoryInfo represents detected business information
type BusinessCategoryInfo struct {
	Category    string   `json:"category"`
	Confidence  float64  `json:"confidence"`
	Keywords    []string `json:"keywords"`
	Sensitivity string   `json:"sensitivity"`
}

// EntityResult represents extracted entities
type EntityResult struct {
	Entities []Entity `json:"entities"`
	Count    int      `json:"count"`
}

// Entity represents a named entity
type Entity struct {
	Text       string  `json:"text"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
}

// SentimentResult represents sentiment analysis
type SentimentResult struct {
	Overall    string  `json:"overall"`
	Confidence float64 `json:"confidence"`
	Positive   float64 `json:"positive"`
	Negative   float64 `json:"negative"`
	Neutral    float64 `json:"neutral"`
}

// TopicResult represents topic extraction
type TopicResult struct {
	Topics []Topic `json:"topics"`
	Count  int     `json:"count"`
}

// Topic represents an extracted topic
type Topic struct {
	Name       string   `json:"name"`
	Confidence float64  `json:"confidence"`
	Keywords   []string `json:"keywords"`
}

// NewMLAnalyzer creates a new ML analyzer instance
func NewMLAnalyzer(config *MLAnalyzerConfig, logger *logging.Logger) (*MLAnalyzer, error) {
	if config == nil {
		config = getDefaultMLConfig()
	}

	if logger == nil {
		logger = logging.GetGlobalLogger()
	}

	analyzer := &MLAnalyzer{
		config:    config,
		logger:    logger.WithComponent("ml_analyzer"),
		providers: make(map[string]MLProvider),
	}

	// Initialize mock provider
	mockProvider := NewMockMLProvider(logger)
	analyzer.providers["mock"] = mockProvider

	analyzer.logger.Info("ML analyzer initialized successfully")
	return analyzer, nil
}

// AnalyzeContent performs comprehensive ML analysis on content
func (m *MLAnalyzer) AnalyzeContent(ctx context.Context, content string) (*MLAnalysisResult, error) {
	start := time.Now()

	if !m.config.Enabled {
		return &MLAnalysisResult{
			Content:         content,
			ConfidenceScore: 0.0,
			ProcessingTime:  time.Since(start),
			ProviderUsed:    "disabled",
		}, nil
	}

	// Get provider
	provider := m.getProvider()
	if provider == nil {
		return nil, fmt.Errorf("no ML provider available")
	}

	// Create analysis context with timeout
	ctx, cancel := context.WithTimeout(ctx, m.config.Timeout)
	defer cancel()

	// Perform analysis
	result, err := provider.AnalyzeContent(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("ML analysis failed: %w", err)
	}

	// Enhance with business category analysis
	businessCategories := m.analyzeBusinessCategories(content)
	result.BusinessCategories = businessCategories

	// Calculate overall confidence score
	result.ConfidenceScore = m.calculateConfidenceScore(result)

	// Generate recommendations
	result.Recommendations = m.generateRecommendations(result)

	result.ProcessingTime = time.Since(start)

	m.logger.WithFields(logrus.Fields{
		"content_length":      len(content),
		"confidence_score":    result.ConfidenceScore,
		"business_categories": len(result.BusinessCategories),
		"processing_time_ms":  result.ProcessingTime.Milliseconds(),
		"provider":            result.ProviderUsed,
	}).Info("ML analysis completed")

	return result, nil
}

// analyzeBusinessCategories analyzes content for business information
func (m *MLAnalyzer) analyzeBusinessCategories(content string) []BusinessCategoryInfo {
	var categories []BusinessCategoryInfo
	contentLower := strings.ToLower(content)

	// Financial data detection
	if m.containsAny(contentLower, []string{"revenue", "profit", "financial", "quarterly", "budget", "earnings"}) {
		categories = append(categories, BusinessCategoryInfo{
			Category:    "financial_data",
			Confidence:  0.85,
			Keywords:    m.findKeywords(contentLower, []string{"revenue", "profit", "financial", "quarterly"}),
			Sensitivity: "confidential",
		})
	}

	// Customer data detection
	if m.containsAny(contentLower, []string{"customer", "client", "user data", "personal information"}) {
		categories = append(categories, BusinessCategoryInfo{
			Category:    "customer_data",
			Confidence:  0.90,
			Keywords:    m.findKeywords(contentLower, []string{"customer", "client", "user data"}),
			Sensitivity: "restricted",
		})
	}

	// Strategic planning detection
	if m.containsAny(contentLower, []string{"strategy", "roadmap", "planning", "objectives", "goals"}) {
		categories = append(categories, BusinessCategoryInfo{
			Category:    "strategic_planning",
			Confidence:  0.80,
			Keywords:    m.findKeywords(contentLower, []string{"strategy", "roadmap", "planning"}),
			Sensitivity: "confidential",
		})
	}

	// Legal documents detection
	if m.containsAny(contentLower, []string{"contract", "agreement", "legal", "compliance", "regulation"}) {
		categories = append(categories, BusinessCategoryInfo{
			Category:    "legal_documents",
			Confidence:  0.88,
			Keywords:    m.findKeywords(contentLower, []string{"contract", "agreement", "legal"}),
			Sensitivity: "restricted",
		})
	}

	// Intellectual property detection
	if m.containsAny(contentLower, []string{"patent", "trademark", "proprietary", "trade secret", "ip"}) {
		categories = append(categories, BusinessCategoryInfo{
			Category:    "intellectual_property",
			Confidence:  0.92,
			Keywords:    m.findKeywords(contentLower, []string{"patent", "trademark", "proprietary"}),
			Sensitivity: "restricted",
		})
	}

	return categories
}

// containsAny checks if content contains any of the keywords
func (m *MLAnalyzer) containsAny(content string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

// findKeywords returns keywords found in content
func (m *MLAnalyzer) findKeywords(content string, keywords []string) []string {
	var found []string
	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			found = append(found, keyword)
		}
	}
	return found
}

// calculateConfidenceScore calculates overall confidence score
func (m *MLAnalyzer) calculateConfidenceScore(result *MLAnalysisResult) float64 {
	var totalScore float64
	var components int

	// Business categories score
	if len(result.BusinessCategories) > 0 {
		var categoryScore float64
		for _, category := range result.BusinessCategories {
			categoryScore += category.Confidence
		}
		totalScore += categoryScore / float64(len(result.BusinessCategories))
		components++
	}

	// Entity score
	if result.Entities != nil && result.Entities.Count > 0 {
		var entityScore float64
		for _, entity := range result.Entities.Entities {
			entityScore += entity.Confidence
		}
		totalScore += entityScore / float64(result.Entities.Count)
		components++
	}

	// Sentiment score
	if result.Sentiment != nil {
		totalScore += result.Sentiment.Confidence
		components++
	}

	// Topic score
	if result.Topics != nil && result.Topics.Count > 0 {
		var topicScore float64
		for _, topic := range result.Topics.Topics {
			topicScore += topic.Confidence
		}
		totalScore += topicScore / float64(result.Topics.Count)
		components++
	}

	if components == 0 {
		return 0.0
	}

	return totalScore / float64(components)
}

// generateRecommendations generates actionable recommendations
func (m *MLAnalyzer) generateRecommendations(result *MLAnalysisResult) []string {
	var recommendations []string

	// Business category recommendations
	for _, category := range result.BusinessCategories {
		if category.Confidence > 0.7 {
			switch category.Category {
			case "financial_data":
				recommendations = append(recommendations, "Financial data detected - ensure proper access controls and audit logging")
			case "customer_data":
				recommendations = append(recommendations, "Customer data identified - verify GDPR/CCPA compliance measures")
			case "intellectual_property":
				recommendations = append(recommendations, "IP content detected - implement maximum security protocols")
			case "legal_documents":
				recommendations = append(recommendations, "Legal content identified - ensure attorney-client privilege protection")
			case "strategic_planning":
				recommendations = append(recommendations, "Strategic content detected - limit access to authorized personnel")
			}
		}
	}

	// Entity-based recommendations
	if result.Entities != nil && result.Entities.Count > 5 {
		recommendations = append(recommendations, "High entity density detected - consider enhanced data protection measures")
	}

	// Sentiment-based recommendations
	if result.Sentiment != nil && result.Sentiment.Overall == "negative" && result.Sentiment.Confidence > 0.8 {
		recommendations = append(recommendations, "Negative sentiment detected - review for potential risk or crisis management")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "ML analysis complete - no specific security recommendations")
	}

	return recommendations
}

// getProvider returns the appropriate ML provider
func (m *MLAnalyzer) getProvider() MLProvider {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Try default provider first
	if provider, exists := m.providers[m.config.DefaultProvider]; exists && provider.IsHealthy() {
		return provider
	}

	// Fallback to any healthy provider
	for _, provider := range m.providers {
		if provider.IsHealthy() {
			return provider
		}
	}

	return nil
}

// getDefaultMLConfig returns default ML analyzer configuration
func getDefaultMLConfig() *MLAnalyzerConfig {
	return &MLAnalyzerConfig{
		Enabled:            true,
		DefaultProvider:    "mock",
		Timeout:           30 * time.Second,
		MinConfidenceScore: 0.3,
		EnableSentiment:    true,
		EnableTopics:       true,
		EnableEntities:     true,
	}
}

// Close gracefully shuts down the ML analyzer
func (m *MLAnalyzer) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for name, provider := range m.providers {
		if err := provider.Close(); err != nil {
			m.logger.WithError(err).Warnf("Failed to close provider %s", name)
		}
	}

	m.logger.Info("ML analyzer closed")
	return nil
} 