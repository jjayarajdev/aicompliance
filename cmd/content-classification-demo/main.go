package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ai-gateway-poc/internal/analysis"
	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/logging"
)

func main() {
	fmt.Println("🚀 AI Gateway - Content Classification System Demo")
	fmt.Println("==================================================")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	// Setup logging
	logger, err := logging.New(&logging.Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	})
	if err != nil {
		fmt.Printf("❌ Failed to create logger: %v\n", err)
		return
	}

	// Create PII detector for integration
	piiConfig := &analysis.PIIDetectorConfig{
		Enabled:          cfg.PIIDetection.Enabled,
		SensitivityLevel: cfg.PIIDetection.SensitivityLevel,
		RedactionMode:    "mask",
		CustomPatterns:   cfg.PIIDetection.CustomPatterns,
		ExcludePatterns:  cfg.PIIDetection.ExcludePatterns,
		MaxTextSize:      cfg.PIIDetection.MaxTextSize,
	}

	piiDetector, err := analysis.NewPIIDetector(piiConfig, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create PII detector: %v\n", err)
		return
	}

	// Create content classifier configuration
	classifierConfig := &analysis.ContentClassifierConfig{
		Enabled:       cfg.ContentClassification.Enabled,
		DefaultLevel:  analysis.SensitivityLevel(cfg.ContentClassification.DefaultLevel),
		MinConfidence: cfg.ContentClassification.MinConfidence,
		MaxTextSize:   cfg.ContentClassification.MaxTextSize,
		LevelConfigs: map[analysis.SensitivityLevel]analysis.LevelConfig{
			analysis.SensitivityPublic: {
				Weight:  1.0,
				Enabled: true,
			},
			analysis.SensitivityInternal: {
				Weight:  1.0,
				Enabled: true,
			},
			analysis.SensitivityConfidential: {
				Weight:  1.2,
				Enabled: true,
			},
			analysis.SensitivityRestricted: {
				Weight:  1.5,
				Enabled: true,
			},
		},
		GlobalRules: []analysis.RuleConfig{
			{
				Name:    "high_pii_count",
				Level:   analysis.SensitivityConfidential,
				Weight:  2.0,
				Enabled: true,
				Conditions: []analysis.ConditionConfig{
					{
						Type:     "pii_count",
						Operator: ">=",
						Value:    3.0,
					},
				},
			},
		},
	}

	// Create content classifier
	classifier, err := analysis.NewContentClassifier(classifierConfig, piiDetector, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create content classifier: %v\n", err)
		return
	}

	fmt.Println("✅ Content classification system initialized successfully")
	fmt.Println()

	// Demo 1: Basic Sensitivity Level Classification
	fmt.Println("📝 Demo 1: Basic Sensitivity Level Classification")
	fmt.Println("------------------------------------------------")

	testCases := []struct {
		name string
		text string
	}{
		{
			"Public Announcement",
			"This is a public announcement about our new product launch. Press release materials are available for marketing purposes.",
		},
		{
			"Internal Communication",
			"Internal team meeting notes: Project updates for Q4. Employee handbook revision needed for company policy changes.",
		},
		{
			"Confidential Business Information",
			"Confidential strategic business plan containing proprietary trade secrets. Financial merger data and acquisition targets included.",
		},
		{
			"Restricted Security Information",
			"Restricted classified security audit findings. Password database review completed. Top secret investigation results.",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("🔍 %s:\n", tc.name)
		fmt.Printf("Text: %s\n", tc.text)

		result, err := classifier.ClassifyContent(context.Background(), tc.text)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("🏷️  Classification: %s (confidence: %.2f)\n", result.Level, result.Confidence)
		fmt.Printf("📊 Scores: ")
		for level, score := range result.Scores {
			fmt.Printf("%s=%.2f ", level, score)
		}
		fmt.Println()

		if len(result.MatchedKeywords) > 0 {
			fmt.Printf("🔤 Matched Keywords: ")
			for level, keywords := range result.MatchedKeywords {
				if len(keywords) > 0 {
					fmt.Printf("%s=[%s] ", level, strings.Join(keywords, ","))
				}
			}
			fmt.Println()
		}

		fmt.Printf("💡 Recommendations:\n")
		for _, rec := range result.RecommendedActions {
			fmt.Printf("   - %s\n", rec)
		}
		fmt.Println()
	}

	// Demo 2: PII Integration
	fmt.Println("📝 Demo 2: PII Integration and Impact")
	fmt.Println("------------------------------------")

	piiTestCases := []struct {
		name string
		text string
	}{
		{
			"Document with Customer PII",
			"Customer information: John Doe, email john.doe@company.com, phone (555) 123-4567, SSN 123-45-6789.",
		},
		{
			"Public Content with PII Warning",
			"Public blog post about our services. Contact information: support@company.com, phone 555-HELP.",
		},
		{
			"High PII Density Document",
			"Employee records: Jane Smith (jane@corp.com, 555-111-2222, SSN: 987-65-4321), Bob Wilson (bob@corp.com, 555-333-4444, SSN: 456-78-9012), Credit cards: 4111-1111-1111-1111, 5555-5555-5555-4444.",
		},
	}

	for _, tc := range piiTestCases {
		fmt.Printf("🔍 %s:\n", tc.name)
		fmt.Printf("Text: %s\n", tc.text)

		result, err := classifier.ClassifyContent(context.Background(), tc.text)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("🏷️  Classification: %s (confidence: %.2f)\n", result.Level, result.Confidence)
		
		if result.PIIResult != nil {
			fmt.Printf("🔒 PII Detected: %t (%d items)\n", result.PIIResult.HasPII, len(result.PIIResult.Matches))
			if result.PIIResult.HasPII {
				fmt.Printf("🔍 PII Types: ")
				for piiType, count := range result.PIIResult.Statistics.MatchesByType {
					fmt.Printf("%s=%d ", piiType, count)
				}
				fmt.Println()
			}
		}

		if len(result.MatchedRules) > 0 {
			fmt.Printf("📋 Matched Rules:\n")
			for _, rule := range result.MatchedRules {
				fmt.Printf("   - %s (level: %s, weight: %.1f)\n", rule.RuleName, rule.Level, rule.Weight)
			}
		}

		fmt.Printf("💡 Recommendations:\n")
		for _, rec := range result.RecommendedActions {
			fmt.Printf("   - %s\n", rec)
		}
		fmt.Println()
	}

	// Demo 3: Custom Classification Rules
	fmt.Println("📝 Demo 3: Custom Classification Rules")
	fmt.Println("--------------------------------------")

	// Add custom rules
	apiKeyRule := analysis.ClassificationRule{
		Name:   "API Credentials Detection",
		Level:  analysis.SensitivityRestricted,
		Weight: 3.0,
		Conditions: []analysis.Condition{
			{
				Type:     "pattern",
				Operator: "matches",
				Value:    `(?i)(api[_-]?key|token|secret)[:=]\s*[a-zA-Z0-9]+`,
			},
		},
		Enabled: true,
	}
	classifier.AddCustomRule(apiKeyRule)

	financialRule := analysis.ClassificationRule{
		Name:   "Financial Data Detection",
		Level:  analysis.SensitivityConfidential,
		Weight: 2.0,
		Conditions: []analysis.Condition{
			{
				Type:     "keyword",
				Operator: "contains",
				Value:    "revenue",
			},
			{
				Type:     "keyword",
				Operator: "contains",
				Value:    "quarterly",
			},
		},
		Enabled: true,
	}
	classifier.AddCustomRule(financialRule)

	customRuleTests := []struct {
		name string
		text string
	}{
		{
			"API Configuration File",
			"Production configuration: API_KEY=abc123xyz789 for external service integration.",
		},
		{
			"Financial Report",
			"Q3 quarterly revenue report shows significant growth. Financial projections for next quarter included.",
		},
		{
			"Mixed Sensitive Content",
			"Database credentials: TOKEN=secret123abc and quarterly revenue data for merger analysis.",
		},
	}

	for _, tc := range customRuleTests {
		fmt.Printf("🔍 %s:\n", tc.name)
		fmt.Printf("Text: %s\n", tc.text)

		result, err := classifier.ClassifyContent(context.Background(), tc.text)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("🏷️  Classification: %s (confidence: %.2f)\n", result.Level, result.Confidence)

		if len(result.MatchedRules) > 0 {
			fmt.Printf("📋 Matched Custom Rules:\n")
			for _, rule := range result.MatchedRules {
				fmt.Printf("   - %s → %s (weight: %.1f)\n", rule.RuleName, rule.Level, rule.Weight)
				for _, condition := range rule.Conditions {
					fmt.Printf("     ✓ %s %s %v: %t\n", condition.Type, condition.Operator, condition.Value, condition.Matched)
				}
			}
		}

		fmt.Printf("💡 Recommendations:\n")
		for _, rec := range result.RecommendedActions {
			fmt.Printf("   - %s\n", rec)
		}
		fmt.Println()
	}

	// Demo 4: Complex Document Analysis
	fmt.Println("📝 Demo 4: Complex Document Analysis")
	fmt.Println("------------------------------------")

	complexDocument := `
CONFIDENTIAL MERGER ANALYSIS REPORT

Executive Summary:
This proprietary document contains confidential trade secrets regarding the potential acquisition of TechCorp Inc. 

Financial Data:
- Quarterly revenue: $15.2M
- Customer database: 50,000+ records
- Employee count: 1,200 staff members

Contact Information:
- CFO: sarah.johnson@company.com
- Legal: legal-team@company.com  
- Phone: (555) 987-6543

Security Details:
- Database credentials: API_KEY=prod_abc123xyz789
- Authentication token: SECRET_TOKEN=xyz789abc123
- Access controls: Restricted to C-level executives only

Regulatory Compliance:
Due diligence required for regulatory filing with SEC. Investigation ongoing.

PII Examples:
- John Doe, SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111
- Jane Smith, Phone: 555-111-2222, Bank Account: 9876543210123456
`

	fmt.Printf("📄 Analyzing complex document (%d characters)...\n", len(complexDocument))

	start := time.Now()
	result, err := classifier.ClassifyContent(context.Background(), complexDocument)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	fmt.Printf("⚡ Analysis completed in %v\n", duration)
	fmt.Printf("\n📊 Classification Results:\n")
	fmt.Printf("🏷️  Final Classification: %s\n", result.Level)
	fmt.Printf("🎯 Confidence Score: %.2f\n", result.Confidence)

	fmt.Printf("\n📈 Sensitivity Scores:\n")
	for level, score := range result.Scores {
		bar := strings.Repeat("█", int(score*20))
		fmt.Printf("  %s: %.3f %s\n", level, score, bar)
	}

	if result.PIIResult != nil && result.PIIResult.HasPII {
		fmt.Printf("\n🔒 PII Analysis:\n")
		fmt.Printf("  - Total PII Items: %d\n", len(result.PIIResult.Matches))
		fmt.Printf("  - PII Types Found: %d\n", len(result.PIIResult.Statistics.MatchesByType))
		fmt.Printf("  - Average Confidence: %.2f\n", result.PIIResult.Statistics.ConfidenceAvg)
	}

	if len(result.MatchedRules) > 0 {
		fmt.Printf("\n📋 Applied Rules:\n")
		for _, rule := range result.MatchedRules {
			fmt.Printf("  ✓ %s → %s (weight: %.1f)\n", rule.RuleName, rule.Level, rule.Weight)
		}
	}

	fmt.Printf("\n🔤 Keyword Matches:\n")
	for level, keywords := range result.MatchedKeywords {
		if len(keywords) > 0 {
			fmt.Printf("  %s: %v\n", level, keywords)
		}
	}

	fmt.Printf("\n💡 Security Recommendations:\n")
	for i, rec := range result.RecommendedActions {
		fmt.Printf("  %d. %s\n", i+1, rec)
	}

	fmt.Printf("\n📋 Metadata:\n")
	for key, value := range result.Metadata {
		fmt.Printf("  - %s: %v\n", key, value)
	}

	// Demo 5: Performance Testing
	fmt.Println("\n📝 Demo 5: Performance Testing")
	fmt.Println("------------------------------")

	// Generate performance test document
	perfDoc := ""
	for i := 0; i < 50; i++ {
		perfDoc += fmt.Sprintf("Document %d contains confidential information about project %d. ", i, i)
		perfDoc += fmt.Sprintf("Contact: user%d@company.com, Internal reference: INT-%08d. ", i, i)
		if i%10 == 0 {
			perfDoc += "This section contains proprietary trade secrets and financial data. "
		}
	}

	fmt.Printf("📏 Testing with document (%d characters, mixed content)...\n", len(perfDoc))

	start = time.Now()
	result, err = classifier.ClassifyContent(context.Background(), perfDoc)
	duration = time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
	} else {
		fmt.Printf("⚡ Performance Results:\n")
		fmt.Printf("  - Processing Time: %v\n", duration)
		fmt.Printf("  - Throughput: %.2f chars/ms\n", float64(len(perfDoc))/float64(duration.Milliseconds()))
		fmt.Printf("  - Classification: %s (confidence: %.2f)\n", result.Level, result.Confidence)
		if result.PIIResult != nil {
			fmt.Printf("  - PII Items: %d\n", len(result.PIIResult.Matches))
		}
		fmt.Printf("  - Rules Applied: %d\n", len(result.MatchedRules))
	}

	// Final summary
	fmt.Println("\n🎉 Content Classification Demo Completed Successfully!")
	fmt.Println("=====================================================")

	supportedLevels := classifier.GetSupportedLevels()
	fmt.Printf("📊 System Summary:\n")
	fmt.Printf("  - Supported Sensitivity Levels: %d\n", len(supportedLevels))
	fmt.Printf("  - PII Integration: ✅ Enabled\n")
	fmt.Printf("  - Custom Rules: ✅ Supported\n")
	fmt.Printf("  - Real-time Classification: ✅ Ready\n")
	fmt.Printf("  - Performance: ✅ Optimized\n")

	fmt.Printf("\n🏷️  Sensitivity Levels:\n")
	for i, level := range supportedLevels {
		fmt.Printf("  %d. %s\n", i+1, level)
	}

	fmt.Printf("\n🔧 Key Features:\n")
	fmt.Printf("  • Keyword and pattern-based classification\n")
	fmt.Printf("  • PII-aware sensitivity scoring\n")
	fmt.Printf("  • Custom rule engine for business logic\n")
	fmt.Printf("  • Confidence scoring and recommendations\n")
	fmt.Printf("  • Real-time processing with detailed analytics\n")
	fmt.Printf("  • Configurable sensitivity thresholds\n")
	fmt.Printf("  • Integration-ready with structured logging\n")

	fmt.Println("\n✅ Ready for production deployment!")
} 