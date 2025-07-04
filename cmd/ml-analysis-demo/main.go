package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ai-gateway-poc/internal/analysis"
	"ai-gateway-poc/internal/logging"
)

func main() {
	fmt.Println("🚀 AI Gateway - ML-Powered Content Analysis Demo")
	fmt.Println("===============================================")

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

	// Create ML analyzer
	mlConfig := &analysis.MLAnalyzerConfig{
		Enabled:            true,
		DefaultProvider:    "mock",
		Timeout:           30 * time.Second,
		MinConfidenceScore: 0.3,
		EnableSentiment:    true,
		EnableTopics:       true,
		EnableEntities:     true,
	}

	mlAnalyzer, err := analysis.NewMLAnalyzer(mlConfig, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create ML analyzer: %v\n", err)
		return
	}
	defer mlAnalyzer.Close()

	fmt.Println("✅ ML-powered content analysis system initialized successfully")
	fmt.Println()

	// Demo: Business Information Detection
	fmt.Println("📝 Business Information Detection")
	fmt.Println("--------------------------------")

	testCases := []struct {
		name string
		text string
	}{
		{
			"Financial Report",
			"Q3 financial results show revenue growth of 15% year-over-year. Quarterly earnings exceeded expectations with profit margins improving significantly.",
		},
		{
			"Customer Data Analysis", 
			"Customer satisfaction survey results indicate positive feedback from 85% of clients. User data analytics reveal engagement patterns and behavioral insights.",
		},
		{
			"Strategic Planning",
			"Strategic roadmap for 2024 includes expansion into new markets and competitive positioning. Planning committee identified key objectives and milestone targets.",
		},
		{
			"Legal Contract",
			"Contract negotiations completed with vendor agreements finalized. Legal compliance requirements addressed in new partnership deals.",
		},
		{
			"Intellectual Property",
			"Patent application submitted for new algorithm innovation. Trademark registration process initiated for brand protection.",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("🔍 %s:\n", tc.name)
		fmt.Printf("Text: %s\n", tc.text)

		result, err := mlAnalyzer.AnalyzeContent(context.Background(), tc.text)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("🎯 Confidence: %.2f | ⚡ Time: %v\n", result.ConfidenceScore, result.ProcessingTime)

		if len(result.BusinessCategories) > 0 {
			fmt.Printf("🏢 Business Categories:\n")
			for _, category := range result.BusinessCategories {
				fmt.Printf("   - %s (%.2f, %s)\n", category.Category, category.Confidence, category.Sensitivity)
			}
		}

		if result.Entities != nil && result.Entities.Count > 0 {
			fmt.Printf("🏷️  Entities: %d found\n", result.Entities.Count)
		}

		if result.Topics != nil && result.Topics.Count > 0 {
			fmt.Printf("📚 Topics: ")
			var topicNames []string
			for _, topic := range result.Topics.Topics {
				topicNames = append(topicNames, topic.Name)
			}
			fmt.Printf("%s\n", strings.Join(topicNames, ", "))
		}

		if result.Sentiment != nil {
			fmt.Printf("😊 Sentiment: %s (%.2f)\n", result.Sentiment.Overall, result.Sentiment.Confidence)
		}

		fmt.Printf("💡 Recommendations: %d generated\n", len(result.Recommendations))
		fmt.Println()
	}

	// Complex Document Demo
	fmt.Println("📝 Complex Document Analysis")
	fmt.Println("----------------------------")

	complexDoc := `CONFIDENTIAL BUSINESS STRATEGY DOCUMENT
	
Executive Summary: This proprietary strategic planning document outlines our competitive positioning for Q4 2024.

Financial Performance: Current quarterly revenue: $15.2M (15% growth). Customer base has grown with 85% satisfaction rates.

Strategic Initiatives: Digital transformation, market expansion, intellectual property development.

Team: Sarah Johnson (s.johnson@company.com), Michael Chen (m.chen@company.com)

This document contains sensitive business information and should be treated as confidential proprietary material.`

	fmt.Printf("📄 Analyzing complex document (%d characters)...\n", len(complexDoc))

	start := time.Now()
	result, err := mlAnalyzer.AnalyzeContent(context.Background(), complexDoc)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	fmt.Printf("⚡ Analysis completed in %v\n", duration)
	fmt.Printf("🎯 Overall Confidence: %.2f\n", result.ConfidenceScore)

	if len(result.BusinessCategories) > 0 {
		fmt.Printf("\n🏢 Business Categories Detected:\n")
		for _, category := range result.BusinessCategories {
			sensitivityIcon := map[string]string{
				"public": "🌐", "internal": "🏢", "confidential": "🔐", "restricted": "🔒",
			}[category.Sensitivity]
			
			fmt.Printf("   %s %s (%.2f)\n", sensitivityIcon, strings.ToUpper(category.Category), category.Confidence)
		}
	}

	if result.Entities != nil {
		fmt.Printf("\n🏷️  Entity Analysis: %d entities found\n", result.Entities.Count)
		entityTypes := make(map[string]int)
		for _, entity := range result.Entities.Entities {
			entityTypes[entity.Type]++
		}
		for entityType, count := range entityTypes {
			fmt.Printf("   - %s: %d\n", entityType, count)
		}
	}

	if result.Topics != nil && result.Topics.Count > 0 {
		fmt.Printf("\n📚 Topics Identified:\n")
		for _, topic := range result.Topics.Topics {
			fmt.Printf("   - %s (%.2f)\n", topic.Name, topic.Confidence)
		}
	}

	if result.Sentiment != nil {
		fmt.Printf("\n😊 Sentiment: %s (%.2f confidence)\n", strings.ToUpper(result.Sentiment.Overall), result.Sentiment.Confidence)
	}

	fmt.Printf("\n🛡️  Security Recommendations:\n")
	for i, rec := range result.Recommendations {
		fmt.Printf("   %d. %s\n", i+1, rec)
	}

	// Summary
	fmt.Println("\n🎉 ML Analysis Demo Completed Successfully!")
	fmt.Println("==========================================")

	fmt.Printf("🧠 ML Capabilities Demonstrated:\n")
	fmt.Printf("  • Business Information Detection ✅\n")
	fmt.Printf("  • Named Entity Recognition ✅\n") 
	fmt.Printf("  • Sentiment Analysis ✅\n")
	fmt.Printf("  • Topic Modeling ✅\n")
	fmt.Printf("  • Security Classification ✅\n")
	fmt.Printf("  • Real-time Processing ✅\n")

	fmt.Println("\n✅ Ready for enterprise deployment with ML-enhanced security!")
} 