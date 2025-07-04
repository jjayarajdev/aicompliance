package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"ai-gateway-poc/internal/analysis"
)

func main() {
	fmt.Println("🚀 AI Gateway PoC - Parallel Analysis Pipeline Demo")
	fmt.Println("=====================================================")
	fmt.Println()

	// Test cases with different complexity levels
	testCases := []struct {
		name        string
		description string
		content     string
		profile     string
	}{
		{
			name:        "Simple Business Email",
			description: "Basic email content with minimal PII",
			content:     "Hi team, please review the quarterly report. Contact Sarah at sarah.johnson@company.com if you have questions.",
			profile:     "default",
		},
		{
			name:        "Confidential Financial Report",
			description: "Complex document with multiple PII types and sensitive information",
			content: `CONFIDENTIAL - Q4 Financial Analysis

Executive Summary:
Our revenue growth has exceeded expectations this quarter, reaching $2.5M in total sales.

Key Personnel:
- CFO: Michael Thompson (mthompson@company.com, 555-234-5678)
- Lead Analyst: Jennifer Lee (jlee@company.com, SSN: 123-45-6789)
- Account Manager: David Wilson (Credit Card: 4532-1234-5678-9012)

Strategic Planning:
We are planning aggressive expansion into the European market next year.
Customer acquisition costs have decreased by 15% while retention improved.

Financial Projections:
The board expects 40% growth in Q1 2024 based on current pipeline data.
Investment in AI infrastructure will require $500K initial capital.

This document contains proprietary business information and should be 
treated as RESTRICTED ACCESS ONLY.`,
			profile: "comprehensive",
		},
		{
			name:        "Customer Support Ticket",
			description: "Mixed content with customer information",
			content: `Support Ticket #12345

Customer: John Smith
Email: john.smith@gmail.com
Phone: (555) 123-4567
Issue: Unable to access premium features

Description:
The customer reports being unable to access premium features despite having
an active subscription. Account verification required.

Internal Notes:
- Customer ID: CUST-789123
- Last payment: 2023-12-01
- Subscription tier: Premium Plus
- Revenue impact: $99/month

This ticket requires immediate attention due to premium customer status.`,
			profile: "default",
		},
		{
			name:        "HR Employment Record",
			description: "HR document with extensive PII",
			content: `EMPLOYEE RECORD - CONFIDENTIAL

Personal Information:
Name: Maria Rodriguez
SSN: 987-65-4321
Email: maria.rodriguez@company.com
Phone: 555-987-6543
Address: 123 Main Street, City, State 12345

Employment Details:
Employee ID: EMP-2023-456
Department: Engineering
Salary: $95,000
Start Date: 2023-06-15
Manager: David Kim (dkim@company.com)

Banking Information:
Bank Account: 1234567890 (Chase Bank)
Routing Number: 021000021

Emergency Contact:
Carlos Rodriguez (spouse): 555-876-5432

This record contains sensitive personal information and must be handled
according to company privacy policies and GDPR regulations.`,
			profile: "comprehensive",
		},
		{
			name:        "Public Marketing Content",
			description: "Safe public content for comparison",
			content: `Join Our Team - Open Positions

We are a fast-growing technology company looking for talented individuals
to join our innovative team. We offer competitive salaries, comprehensive
benefits, and opportunities for professional growth.

Current Openings:
- Software Engineer (Remote Available)
- Product Manager (San Francisco, CA)  
- Marketing Specialist (New York, NY)

Company Culture:
Our mission is to create technology that makes a positive impact on the world.
We value diversity, inclusion, and work-life balance.

Apply Today:
Visit our careers page or send your resume to careers@company.com

Equal Opportunity Employer`,
			profile: "default",
		},
		{
			name:        "Legal Contract Draft",
			description: "Complex legal document with business terms",
			content: `SOFTWARE LICENSE AGREEMENT - DRAFT

This Agreement is entered into between TechCorp Inc. and Client Corporation
for the licensing of proprietary software solutions.

Financial Terms:
- License Fee: $250,000 annually
- Implementation Cost: $50,000
- Support Fee: $25,000 per year

Key Personnel:
- Technical Lead: Alice Chen (alice.chen@techcorp.com)
- Legal Counsel: Robert Brown (rbrown@legal.com, 555-345-6789)
- Project Manager: Susan Davis (Tax ID: 12-3456789)

Confidentiality:
This agreement contains confidential and proprietary information.
Unauthorized disclosure may result in legal action and damages
up to $1,000,000.

Intellectual Property:
All software, documentation, and related materials remain the
exclusive property of TechCorp Inc.

CONFIDENTIAL - ATTORNEY-CLIENT PRIVILEGED`,
			profile: "comprehensive",
		},
	}

	// Demo 1: Pipeline Performance Comparison
	fmt.Println("📊 Demo 1: Pipeline Performance Comparison")
	fmt.Println("===========================================")
	runPerformanceComparison()

	// Demo 2: Component Analysis Results
	fmt.Println()
	fmt.Println("🔍 Demo 2: Comprehensive Analysis Results")
	fmt.Println("==========================================")
	
	for i, testCase := range testCases {
		fmt.Printf("\n📋 Test Case %d: %s\n", i+1, testCase.name)
		fmt.Printf("   Description: %s\n", testCase.description)
		fmt.Printf("   Profile: %s\n", testCase.profile)
		fmt.Println()

		runComprehensiveAnalysis(testCase.content, testCase.profile, testCase.name)
		
		if i < len(testCases)-1 {
			fmt.Println()
			fmt.Println(strings.Repeat("-", 80))
		}
	}

	// Demo 3: Pipeline Configuration Options
	fmt.Println()
	fmt.Println("⚙️ Demo 3: Pipeline Configuration Options")
	fmt.Println("==========================================")
	demonstratePipelineConfigurations()

	// Demo 4: Error Handling and Resilience
	fmt.Println()
	fmt.Println("🛡️ Demo 4: Error Handling and Resilience")
	fmt.Println("=========================================")
	demonstrateErrorHandling()

	// Demo 5: Performance Monitoring
	fmt.Println()
	fmt.Println("📈 Demo 5: Performance Monitoring and Statistics")
	fmt.Println("=================================================")
	demonstratePerformanceMonitoring()

	fmt.Println()
	fmt.Println("✅ Parallel Analysis Pipeline Demo Complete!")
	fmt.Println("🎯 Key achievements:")
	fmt.Println("   • Parallel execution of analysis components")
	fmt.Println("   • Intelligent result aggregation and risk assessment")
	fmt.Println("   • Comprehensive performance optimization")
	fmt.Println("   • Robust error handling and timeout management")
	fmt.Println("   • Real-time performance monitoring and bottleneck detection")
	fmt.Println("   • Flexible configuration profiles for different use cases")
	fmt.Println("   • Actionable security and compliance recommendations")
}

func runPerformanceComparison() {
	// Compare different pipeline configurations
	configurations := []struct {
		name    string
		options analysis.PipelineOptions
	}{
		{
			name:    "High Performance",
			options: analysis.GetHighPerformanceOptions(),
		},
		{
			name:    "Default Configuration",
			options: analysis.GetDefaultPipelineOptions(),
		},
		{
			name:    "Comprehensive Analysis",
			options: analysis.GetComprehensiveOptions(),
		},
	}

	testContent := `CONFIDENTIAL BUSINESS REPORT

Financial Performance:
Q4 revenue reached $1.2M, exceeding targets by 15%.

Key Contacts:
- CEO: John Smith (jsmith@company.com, 555-123-4567)
- CFO: Sarah Johnson (SSN: 123-45-6789)
- Legal: Mike Wilson (Credit Card: 4532-1234-5678-9012)

Strategic Initiatives:
Our AI development program requires $300K investment.
Customer data analysis shows 85% satisfaction rates.

This document contains proprietary information and should be 
treated as CONFIDENTIAL per company policy.`

	for _, config := range configurations {
		fmt.Printf("   🔧 Testing %s Configuration:\n", config.name)
		
		pipeline, err := analysis.NewAnalysisPipeline(config.options)
		if err != nil {
			fmt.Printf("      ❌ Error creating pipeline: %v\n", err)
			continue
		}

		ctx := context.Background()
		request := analysis.AnalysisRequest{
			ID:          fmt.Sprintf("perf-test-%s", strings.ToLower(strings.ReplaceAll(config.name, " ", "-"))),
			Content:     testContent,
			ContentType: "text",
			Options:     config.options,
		}

		start := time.Now()
		result, err := pipeline.Analyze(ctx, request)
		totalTime := time.Since(start)

		if err != nil {
			fmt.Printf("      ❌ Analysis failed: %v\n", err)
			continue
		}

		fmt.Printf("      ⏱️ Total time: %v\n", totalTime)
		fmt.Printf("      🚀 Parallel speedup: %.2fx\n", result.ParallelSpeedup)
		fmt.Printf("      🎯 Overall confidence: %.1f%%\n", result.Confidence*100)
		fmt.Printf("      ⚠️ Risk level: %s\n", result.OverallRiskLevel)
		fmt.Printf("      🔍 PII items found: %d\n", len(result.PIIDetection.Matches))
		fmt.Printf("      📊 Classification: %s\n", result.Classification.Level)
		fmt.Printf("      🐌 Bottleneck: %s (%dms)\n", result.BottleneckComponent, result.ComponentTimes[result.BottleneckComponent])
		
		if len(result.Errors) > 0 {
			fmt.Printf("      ⚠️ Partial results due to %d errors\n", len(result.Errors))
		}
		
		fmt.Println()
	}
}

func runComprehensiveAnalysis(content, profileName, testName string) {
	// Get pipeline options based on profile
	var options analysis.PipelineOptions
	switch profileName {
	case "comprehensive":
		options = analysis.GetComprehensiveOptions()
	case "high_performance":
		options = analysis.GetHighPerformanceOptions()
	default:
		options = analysis.GetDefaultPipelineOptions()
	}

	pipeline, err := analysis.NewAnalysisPipeline(options)
	if err != nil {
		fmt.Printf("   ❌ Error creating pipeline: %v\n", err)
		return
	}

	ctx := context.Background()
	request := analysis.AnalysisRequest{
		ID:          fmt.Sprintf("test-%s", strings.ToLower(strings.ReplaceAll(testName, " ", "-"))),
		Content:     content,
		ContentType: "text",
		Options:     options,
	}

	result, err := pipeline.Analyze(ctx, request)
	if err != nil {
		fmt.Printf("   ❌ Analysis failed: %v\n", err)
		return
	}

	// Display comprehensive results
	fmt.Printf("   ⏱️ Processing time: %dms (Speedup: %.2fx)\n", result.ProcessingTimeMs, result.ParallelSpeedup)
	fmt.Printf("   🎯 Overall confidence: %.1f%%\n", result.Confidence*100)
	fmt.Printf("   ⚠️ Risk level: %s\n", result.OverallRiskLevel)
	
	if result.PartialResults {
		fmt.Printf("   ⚠️ Partial results due to %d errors\n", len(result.Errors))
	}

	// Component-specific results
	if result.Preprocessing != nil {
		fmt.Printf("   📝 Preprocessing: %d→%d chars (%.0f%% compression), %s detected\n",
			result.Preprocessing.Statistics.OriginalLength,
			result.Preprocessing.Statistics.ProcessedLength,
			(1-result.Preprocessing.Statistics.CompressionRatio)*100,
			result.Preprocessing.Statistics.PrimaryLanguage)
	}

	if result.PIIDetection != nil {
		fmt.Printf("   🔍 PII Detection: %d items found (%.1f%% confidence)\n",
			len(result.PIIDetection.Matches),
			result.PIIDetection.Statistics.ConfidenceAvg*100)
		
		// Show PII types found
		piiTypes := make(map[string]int)
		for _, detection := range result.PIIDetection.Matches {
			piiTypes[string(detection.Type)]++
		}
		if len(piiTypes) > 0 {
			fmt.Printf("      Types: ")
			var types []string
			for piiType, count := range piiTypes {
				types = append(types, fmt.Sprintf("%s(%d)", piiType, count))
			}
			fmt.Printf("%s\n", strings.Join(types, ", "))
		}
	}

	if result.Classification != nil {
		fmt.Printf("   📊 Classification: %s (%.1f%% confidence)\n",
			result.Classification.Level,
			result.Classification.Confidence*100)
	}

	if result.MLAnalysis != nil {
		fmt.Printf("   🤖 ML Analysis: %.1f%% confidence\n",
			result.MLAnalysis.ConfidenceScore*100)
		
		if result.MLAnalysis.Entities != nil && result.MLAnalysis.Entities.Count > 0 {
			fmt.Printf("      Entities: %d found\n", result.MLAnalysis.Entities.Count)
		}
	}

	// Performance breakdown
	fmt.Printf("   ⚡ Component times:\n")
	for component, duration := range result.ComponentTimes {
		status := ""
		if component == result.BottleneckComponent {
			status = " (bottleneck)"
		}
		fmt.Printf("      • %s: %dms%s\n", component, duration, status)
	}

	// Show top recommendations
	fmt.Printf("   💡 Recommendations:\n")
	for i, rec := range result.Recommendations {
		if i >= 3 { // Show top 3 recommendations
			fmt.Printf("      • ... and %d more\n", len(result.Recommendations)-3)
			break
		}
		fmt.Printf("      • %s\n", rec)
	}
}

func demonstratePipelineConfigurations() {
	profiles := []struct {
		name        string
		description string
		options     analysis.PipelineOptions
	}{
		{
			name:        "Minimal Pipeline",
			description: "Basic analysis with minimal overhead",
			options: func() analysis.PipelineOptions {
				opts := analysis.GetDefaultPipelineOptions()
				opts.EnableClassification = false
				opts.EnableMLAnalysis = false
				opts.EnableFileScanning = false
				opts.MaxConcurrency = 2
				opts.ComponentTimeout = 15 * time.Second
				return opts
			}(),
		},
		{
			name:        "Security-Focused",
			description: "Emphasis on PII detection and classification",
			options: func() analysis.PipelineOptions {
				opts := analysis.GetDefaultPipelineOptions()
				opts.EnableMLAnalysis = false
				opts.RequireAllComponents = true
				opts.ContinueOnError = false
				return opts
			}(),
		},
		{
			name:        "AI-Enhanced",
			description: "Full ML analysis with comprehensive insights",
			options: analysis.GetComprehensiveOptions(),
		},
	}

	testContent := "Employee John Doe (john.doe@company.com, SSN: 123-45-6789) submitted confidential budget proposal for Q1 2024."

	for _, profile := range profiles {
		fmt.Printf("   🔧 %s:\n", profile.name)
		fmt.Printf("      %s\n", profile.description)

		pipeline, err := analysis.NewAnalysisPipeline(profile.options)
		if err != nil {
			fmt.Printf("      ❌ Error: %v\n", err)
			continue
		}

		ctx := context.Background()
		request := analysis.AnalysisRequest{
			ID:          fmt.Sprintf("config-test-%s", strings.ToLower(strings.ReplaceAll(profile.name, " ", "-"))),
			Content:     testContent,
			ContentType: "text",
			Options:     profile.options,
		}

		result, err := pipeline.Analyze(ctx, request)
		if err != nil {
			fmt.Printf("      ❌ Analysis failed: %v\n", err)
			continue
		}

		fmt.Printf("      ⏱️ Time: %dms, Risk: %s, Confidence: %.1f%%\n",
			result.ProcessingTimeMs, result.OverallRiskLevel, result.Confidence*100)
		
		// Show which components ran
		components := []string{}
		if result.Preprocessing != nil {
			components = append(components, "preprocessing")
		}
		if result.PIIDetection != nil {
			components = append(components, "pii")
		}
		if result.Classification != nil {
			components = append(components, "classification")
		}
		if result.MLAnalysis != nil {
			components = append(components, "ml")
		}
		if result.FileScanning != nil {
			components = append(components, "file")
		}
		
		fmt.Printf("      🔧 Components: %s\n", strings.Join(components, ", "))
		fmt.Println()
	}
}

func demonstrateErrorHandling() {
	// Test error handling with aggressive timeouts
	options := analysis.GetDefaultPipelineOptions()
	options.ComponentTimeout = 1 * time.Millisecond  // Force timeouts
	options.ContinueOnError = true

	pipeline, err := analysis.NewAnalysisPipeline(options)
	if err != nil {
		fmt.Printf("   ❌ Error creating pipeline: %v\n", err)
		return
	}

	ctx := context.Background()
	request := analysis.AnalysisRequest{
		ID:          "error-handling-test",
		Content:     "Test content for error handling demonstration",
		ContentType: "text",
		Options:     options,
	}

	fmt.Printf("   🧪 Testing with aggressive 1ms timeouts:\n")
	
	result, err := pipeline.Analyze(ctx, request)
	if err != nil {
		fmt.Printf("      ❌ Pipeline failed completely: %v\n", err)
	} else {
		fmt.Printf("      ✅ Pipeline completed with graceful error handling\n")
		fmt.Printf("      ⚠️ Partial results: %v\n", result.PartialResults)
		fmt.Printf("      📊 Errors encountered: %d\n", len(result.Errors))
		
		for _, pipelineError := range result.Errors {
			fmt.Printf("         • %s: %s\n", pipelineError.Component, pipelineError.Error)
		}
		
		fmt.Printf("      ⏱️ Still got results in: %dms\n", result.ProcessingTimeMs)
	}

	// Test with better timeouts but require all components
	fmt.Printf("\n   🧪 Testing with RequireAllComponents=false:\n")
	options.ComponentTimeout = 30 * time.Second
	options.RequireAllComponents = false
	
	pipeline2, _ := analysis.NewAnalysisPipeline(options)
	request.ID = "error-handling-test-2"
	
	result2, err := pipeline2.Analyze(ctx, request)
	if err != nil {
		fmt.Printf("      ❌ Pipeline failed: %v\n", err)
	} else {
		fmt.Printf("      ✅ Pipeline succeeded with flexible requirements\n")
		fmt.Printf("      📊 Components completed successfully: %d\n", len(result2.ComponentTimes))
	}
}

func demonstratePerformanceMonitoring() {
	options := analysis.GetDefaultPipelineOptions()
	options.EnableMetrics = true
	
	pipeline, err := analysis.NewAnalysisPipeline(options)
	if err != nil {
		fmt.Printf("   ❌ Error creating pipeline: %v\n", err)
		return
	}

	// Run multiple requests to generate statistics
	testRequests := []string{
		"Simple test with email test@example.com",
		"Complex document with PII: John Smith (john.smith@company.com, SSN: 123-45-6789, Phone: 555-123-4567)",
		"Financial report with revenue $250K and confidential strategic planning information",
		"HR record with employee Sarah Johnson (sara.j@company.com, Credit Card: 4532-1234-5678-9012)",
		"Public marketing content about our innovative technology solutions",
	}

	ctx := context.Background()
	
	fmt.Printf("   📊 Running %d analysis requests to generate statistics:\n", len(testRequests))
	
	for i, content := range testRequests {
		request := analysis.AnalysisRequest{
			ID:          fmt.Sprintf("monitoring-test-%d", i+1),
			Content:     content,
			ContentType: "text",
			Options:     options,
		}

		result, err := pipeline.Analyze(ctx, request)
		if err != nil {
			fmt.Printf("      ❌ Request %d failed: %v\n", i+1, err)
			continue
		}

		fmt.Printf("      ✅ Request %d: %dms, Risk: %s, PII: %d\n",
			i+1, result.ProcessingTimeMs, result.OverallRiskLevel, len(result.PIIDetection.Matches))
	}

	// Get and display pipeline statistics
	fmt.Printf("\n   📈 Pipeline Performance Statistics:\n")
	stats := pipeline.GetPipelineStats()
	
	fmt.Printf("      Total requests processed: %v\n", stats["total_requests"])
	fmt.Printf("      Average processing time: %v\n", stats["average_process_time"])
	
	if componentStats, ok := stats["component_statistics"].(map[string]analysis.ComponentStats); ok {
		fmt.Printf("      Component performance:\n")
		for component, compStats := range componentStats {
			fmt.Printf("         • %s: %d runs, avg %v, success rate %.1f%%\n",
				component, compStats.ExecutionCount, compStats.AverageTime, compStats.SuccessRate*100)
		}
	}
}

func init() {
	// Set up basic error handling
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		fmt.Println("AI Gateway PoC - Parallel Analysis Pipeline Demo")
		fmt.Println()
		fmt.Println("This demo showcases the parallel analysis pipeline including:")
		fmt.Println("• Coordinated execution of multiple analysis components")
		fmt.Println("• Performance optimization through parallel processing")
		fmt.Println("• Intelligent result aggregation and risk assessment")
		fmt.Println("• Robust error handling and timeout management")
		fmt.Println("• Real-time performance monitoring and statistics")
		fmt.Println("• Flexible configuration profiles")
		fmt.Println()
		fmt.Println("Usage: go run cmd/pipeline-demo/main.go")
		os.Exit(0)
	}
} 