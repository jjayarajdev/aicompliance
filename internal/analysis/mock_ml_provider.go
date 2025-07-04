package analysis

import (
	"context"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"ai-gateway-poc/internal/logging"
)

// MockMLProvider implements MLProvider for testing and demonstration
type MockMLProvider struct {
	logger    *logging.Logger
	isHealthy bool
}

// GetName returns the provider name
func (p *MockMLProvider) GetName() string {
	return "mock"
}

// AnalyzeContent performs mock content analysis
func (p *MockMLProvider) AnalyzeContent(ctx context.Context, content string) (*MLAnalysisResult, error) {
	// Simulate processing time
	time.Sleep(time.Millisecond * time.Duration(50+rand.Intn(100)))

	result := &MLAnalysisResult{
		Content:      content,
		ProviderUsed: "mock",
	}

	// Mock entity extraction
	entities := p.mockEntityExtraction(content)
	result.Entities = entities

	// Mock sentiment analysis
	sentiment := p.mockSentimentAnalysis(content)
	result.Sentiment = sentiment

	// Mock topic extraction
	topics := p.mockTopicExtraction(content)
	result.Topics = topics

	return result, nil
}

// ExtractEntities performs mock entity extraction
func (p *MockMLProvider) ExtractEntities(ctx context.Context, content string) (*EntityResult, error) {
	return p.mockEntityExtraction(content), nil
}

// AnalyzeSentiment performs mock sentiment analysis
func (p *MockMLProvider) AnalyzeSentiment(ctx context.Context, content string) (*SentimentResult, error) {
	return p.mockSentimentAnalysis(content), nil
}

// ExtractTopics performs mock topic extraction
func (p *MockMLProvider) ExtractTopics(ctx context.Context, content string) (*TopicResult, error) {
	return p.mockTopicExtraction(content), nil
}

// IsHealthy returns provider health status
func (p *MockMLProvider) IsHealthy() bool {
	return p.isHealthy
}

// Close closes the provider
func (p *MockMLProvider) Close() error {
	p.isHealthy = false
	return nil
}

// mockBusinessCategories simulates business category detection
func (p *MockMLProvider) mockBusinessCategories(content string) []BusinessCategoryInfo {
	contentLower := strings.ToLower(content)
	var matches []BusinessCategoryInfo

	// Financial keywords
	if strings.Contains(contentLower, "revenue") || strings.Contains(contentLower, "financial") || 
	   strings.Contains(contentLower, "quarterly") || strings.Contains(contentLower, "profit") {
		matches = append(matches, BusinessCategoryInfo{
			Category:    "financial_data",
			Confidence:  0.85 + rand.Float64()*0.1,
			Keywords:    []string{"revenue", "financial", "quarterly"},
			Sensitivity: "confidential",
		})
	}

	// Customer data keywords
	if strings.Contains(contentLower, "customer") || strings.Contains(contentLower, "client") ||
	   strings.Contains(contentLower, "user data") {
		matches = append(matches, BusinessCategoryInfo{
			Category:    "customer_data",
			Confidence:  0.80 + rand.Float64()*0.15,
			Keywords:    []string{"customer", "client"},
			Sensitivity: "restricted",
		})
	}

	// Strategic planning keywords
	if strings.Contains(contentLower, "strategy") || strings.Contains(contentLower, "roadmap") ||
	   strings.Contains(contentLower, "planning") {
		matches = append(matches, BusinessCategoryInfo{
			Category:    "strategic_planning",
			Confidence:  0.75 + rand.Float64()*0.15,
			Keywords:    []string{"strategy", "roadmap", "planning"},
			Sensitivity: "confidential",
		})
	}

	// Legal documents
	if strings.Contains(contentLower, "contract") || strings.Contains(contentLower, "agreement") ||
	   strings.Contains(contentLower, "legal") || strings.Contains(contentLower, "compliance") {
		matches = append(matches, BusinessCategoryInfo{
			Category:    "legal_documents",
			Confidence:  0.88 + rand.Float64()*0.1,
			Keywords:    []string{"contract", "agreement", "legal"},
			Sensitivity: "restricted",
		})
	}

	// Intellectual property
	if strings.Contains(contentLower, "patent") || strings.Contains(contentLower, "trademark") ||
	   strings.Contains(contentLower, "proprietary") || strings.Contains(contentLower, "trade secret") {
		matches = append(matches, BusinessCategoryInfo{
			Category:    "intellectual_property",
			Confidence:  0.90 + rand.Float64()*0.05,
			Keywords:    []string{"patent", "trademark", "proprietary"},
			Sensitivity: "restricted",
		})
	}

	// Technical specifications
	if strings.Contains(contentLower, "technical") || strings.Contains(contentLower, "specification") ||
	   strings.Contains(contentLower, "architecture") || strings.Contains(contentLower, "design") {
		matches = append(matches, BusinessCategoryInfo{
			Category:    "technical_specifications",
			Confidence:  0.70 + rand.Float64()*0.2,
			Keywords:    []string{"technical", "specification", "architecture"},
			Sensitivity: "internal",
		})
	}

	return matches
}

// mockEntityExtraction simulates entity extraction
func (p *MockMLProvider) mockEntityExtraction(content string) *EntityResult {
	entities := []Entity{}

	// Extract email-like patterns
	emailRegex := regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
	emailMatches := emailRegex.FindAllStringIndex(content, -1)
	for _, match := range emailMatches {
		entities = append(entities, Entity{
			Text:       content[match[0]:match[1]],
			Type:       "EMAIL",
			Confidence: 0.95 + rand.Float64()*0.05,
			Start:      match[0],
			End:        match[1],
		})
	}

	// Extract organization names (simple pattern)
	orgPatterns := []string{"Inc", "Corp", "LLC", "Ltd", "Company", "Organization"}
	for _, pattern := range orgPatterns {
		regex := regexp.MustCompile(`\b\w+\s+` + pattern + `\b`)
		matches := regex.FindAllStringIndex(content, -1)
		for _, match := range matches {
			entities = append(entities, Entity{
				Text:       content[match[0]:match[1]],
				Type:       "ORGANIZATION",
				Confidence: 0.80 + rand.Float64()*0.15,
				Start:      match[0],
				End:        match[1],
			})
		}
	}

	// Extract person names (simple pattern)
	nameRegex := regexp.MustCompile(`\b[A-Z][a-z]+ [A-Z][a-z]+\b`)
	nameMatches := nameRegex.FindAllStringIndex(content, -1)
	for _, match := range nameMatches[:min(len(nameMatches), 5)] { // Limit to 5 names
		entities = append(entities, Entity{
			Text:       content[match[0]:match[1]],
			Type:       "PERSON",
			Confidence: 0.75 + rand.Float64()*0.2,
			Start:      match[0],
			End:        match[1],
		})
	}

	// Extract monetary amounts
	moneyRegex := regexp.MustCompile(`\$[\d,]+(?:\.\d{2})?`)
	moneyMatches := moneyRegex.FindAllStringIndex(content, -1)
	for _, match := range moneyMatches {
		entities = append(entities, Entity{
			Text:       content[match[0]:match[1]],
			Type:       "MONEY",
			Confidence: 0.90 + rand.Float64()*0.1,
			Start:      match[0],
			End:        match[1],
		})
	}

	// Extract dates
	dateRegex := regexp.MustCompile(`\b\d{1,2}/\d{1,2}/\d{4}\b|\b\d{4}-\d{2}-\d{2}\b`)
	dateMatches := dateRegex.FindAllStringIndex(content, -1)
	for _, match := range dateMatches {
		entities = append(entities, Entity{
			Text:       content[match[0]:match[1]],
			Type:       "DATE",
			Confidence: 0.85 + rand.Float64()*0.1,
			Start:      match[0],
			End:        match[1],
		})
	}

	return &EntityResult{
		Entities: entities,
		Count:    len(entities),
	}
}

// mockSentimentAnalysis simulates sentiment analysis
func (p *MockMLProvider) mockSentimentAnalysis(content string) *SentimentResult {
	contentLower := strings.ToLower(content)
	
	// Simple keyword-based sentiment analysis
	positiveWords := []string{"good", "great", "excellent", "positive", "success", "growth", "improve", "benefit", "advantage", "opportunity"}
	negativeWords := []string{"bad", "terrible", "negative", "failure", "decline", "problem", "issue", "risk", "threat", "concern"}
	
	var positiveScore, negativeScore float64
	
	for _, word := range positiveWords {
		if strings.Contains(contentLower, word) {
			positiveScore += 0.1
		}
	}
	
	for _, word := range negativeWords {
		if strings.Contains(contentLower, word) {
			negativeScore += 0.1
		}
	}
	
	// Normalize and add some randomness
	total := positiveScore + negativeScore
	if total == 0 {
		// Neutral content
		return &SentimentResult{
			Overall:    "neutral",
			Confidence: 0.6 + rand.Float64()*0.2,
			Positive:   0.3 + rand.Float64()*0.2,
			Negative:   0.2 + rand.Float64()*0.2,
			Neutral:    0.5 + rand.Float64()*0.2,
		}
	}
	
	positiveScore = positiveScore / total
	negativeScore = negativeScore / total
	neutralScore := 1.0 - positiveScore - negativeScore
	
	overall := "neutral"
	confidence := 0.5
	
	if positiveScore > negativeScore && positiveScore > 0.4 {
		overall = "positive"
		confidence = positiveScore + rand.Float64()*0.1
	} else if negativeScore > positiveScore && negativeScore > 0.4 {
		overall = "negative"
		confidence = negativeScore + rand.Float64()*0.1
	}
	
	return &SentimentResult{
		Overall:    overall,
		Confidence: confidence,
		Positive:   positiveScore + rand.Float64()*0.1,
		Negative:   negativeScore + rand.Float64()*0.1,
		Neutral:    neutralScore + rand.Float64()*0.1,
	}
}

// mockTopicExtraction simulates topic extraction
func (p *MockMLProvider) mockTopicExtraction(content string) *TopicResult {
	contentLower := strings.ToLower(content)
	topics := []Topic{}
	
	// Business topics
	businessTopics := map[string][]string{
		"finance": {"revenue", "profit", "financial", "budget", "cost", "expense", "investment"},
		"technology": {"software", "system", "platform", "technology", "technical", "development", "api"},
		"strategy": {"strategy", "planning", "roadmap", "objective", "goal", "initiative", "vision"},
		"operations": {"operations", "process", "workflow", "efficiency", "optimization", "performance"},
		"marketing": {"marketing", "campaign", "brand", "customer", "market", "promotion", "advertising"},
		"legal": {"legal", "compliance", "regulation", "contract", "agreement", "policy", "governance"},
		"hr": {"employee", "staff", "personnel", "hr", "human resources", "training", "recruitment"},
		"security": {"security", "risk", "threat", "protection", "access", "authentication", "encryption"},
	}
	
	for topic, keywords := range businessTopics {
		score := 0.0
		matchedKeywords := []string{}
		
		for _, keyword := range keywords {
			if strings.Contains(contentLower, keyword) {
				score += 1.0
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}
		
		if score > 0 {
			confidence := score / float64(len(keywords))
			if confidence > 0.2 { // Only include topics with reasonable confidence
				topics = append(topics, Topic{
					Name:       topic,
					Confidence: confidence + rand.Float64()*0.1,
					Keywords:   matchedKeywords,
				})
			}
		}
	}
	
	// Sort by confidence
	for i := 0; i < len(topics)-1; i++ {
		for j := i+1; j < len(topics); j++ {
			if topics[j].Confidence > topics[i].Confidence {
				topics[i], topics[j] = topics[j], topics[i]
			}
		}
	}
	
	// Limit to top 5 topics
	if len(topics) > 5 {
		topics = topics[:5]
	}
	
	return &TopicResult{
		Topics: topics,
		Count:  len(topics),
	}
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// NewMockMLProvider creates a new mock ML provider
func NewMockMLProvider(logger *logging.Logger) *MockMLProvider {
	return &MockMLProvider{
		logger:    logger,
		isHealthy: true,
	}
} 