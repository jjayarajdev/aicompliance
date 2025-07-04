package analysis

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNewAnalysisPipeline(t *testing.T) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	if pipeline == nil {
		t.Fatal("Pipeline is nil")
	}
	
	// Check that components are initialized based on options
	if options.EnablePreprocessing && pipeline.preprocessor == nil {
		t.Error("Preprocessor should be initialized")
	}
	
	if options.EnablePIIDetection && pipeline.piiDetector == nil {
		t.Error("PII detector should be initialized")
	}
	
	if options.EnableClassification && pipeline.classifier == nil {
		t.Error("Classifier should be initialized")
	}
	
	if options.EnableMLAnalysis && pipeline.mlAnalyzer == nil {
		t.Error("ML analyzer should be initialized")
	}
}

func TestPipelineAnalyze_BasicFunctionality(t *testing.T) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "test-001",
		Content:     "Hello world! This is a test document with an email john.doe@company.com and phone number 555-123-4567.",
		ContentType: "text",
		Options:     options,
	}
	
	result, err := pipeline.Analyze(ctx, request)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}
	
	// Verify basic result structure
	if result.RequestID != request.ID {
		t.Errorf("Expected request ID %s, got %s", request.ID, result.RequestID)
	}
	
	if result.ProcessingTimeMs <= 0 {
		t.Error("Processing time should be positive")
	}
	
	// Check that enabled components produced results
	if options.EnablePreprocessing && result.Preprocessing == nil {
		t.Error("Preprocessing result should not be nil")
	}
	
	if options.EnablePIIDetection && result.PIIDetection == nil {
		t.Error("PII detection result should not be nil")
	}
	
	if options.EnableClassification && result.Classification == nil {
		t.Error("Classification result should not be nil")
	}
	
	if options.EnableMLAnalysis && result.MLAnalysis == nil {
		t.Error("ML analysis result should not be nil")
	}
	
	// Verify aggregated metrics are calculated
	if result.OverallRiskLevel == "" {
		t.Error("Overall risk level should be set")
	}
	
	if result.Confidence < 0 || result.Confidence > 1 {
		t.Errorf("Confidence should be between 0 and 1, got %f", result.Confidence)
	}
	
	if len(result.Recommendations) == 0 {
		t.Error("Should have at least one recommendation")
	}
}

func TestPipelineAnalyze_PIIDetection(t *testing.T) {
	options := GetDefaultPipelineOptions()
	// Enable only PII detection for focused testing
	options.EnableClassification = false
	options.EnableMLAnalysis = false
	
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	testCases := []struct {
		name            string
		content         string
		expectedPIICount int
		expectedRiskLevel string
	}{
		{
			name:            "No PII",
			content:         "This is a simple text without any sensitive information.",
			expectedPIICount: 0,
			expectedRiskLevel: "low",
		},
		{
			name:            "Email PII",
			content:         "Contact us at support@company.com for assistance.",
			expectedPIICount: 1,
			expectedRiskLevel: "medium",
		},
		{
			name:            "Multiple PII Types",
			content:         "John Doe (john.doe@company.com) can be reached at 555-123-4567 or SSN 123-45-6789.",
			expectedPIICount: 3,
			expectedRiskLevel: "high",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			request := AnalysisRequest{
				ID:          fmt.Sprintf("pii-test-%s", tc.name),
				Content:     tc.content,
				ContentType: "text",
				Options:     options,
			}
			
			result, err := pipeline.Analyze(ctx, request)
			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}
			
			if result.PIIDetection == nil {
				t.Fatal("PII detection result should not be nil")
			}
			
			actualPIICount := len(result.PIIDetection.Matches)
			if actualPIICount != tc.expectedPIICount {
				t.Errorf("Expected %d PII detections, got %d", tc.expectedPIICount, actualPIICount)
			}
			
			if result.OverallRiskLevel != tc.expectedRiskLevel {
				t.Errorf("Expected risk level %s, got %s", tc.expectedRiskLevel, result.OverallRiskLevel)
			}
		})
	}
}

func TestPipelineAnalyze_ParallelPerformance(t *testing.T) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "perf-test",
		Content:     "This is a comprehensive test document with multiple analysis requirements. It includes email addresses like test@example.com, phone numbers like 555-123-4567, and confidential business information about our quarterly revenue projections and strategic planning initiatives.",
		ContentType: "text",
		Options:     options,
	}
	
	result, err := pipeline.Analyze(ctx, request)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}
	
	// Verify parallel speedup calculation
	if result.ParallelSpeedup <= 1.0 {
		t.Errorf("Expected parallel speedup > 1.0, got %f", result.ParallelSpeedup)
	}
	
	// Verify component times are recorded
	expectedComponents := []string{"preprocessing", "pii_detection", "classification", "ml_analysis"}
	for _, component := range expectedComponents {
		if _, exists := result.ComponentTimes[component]; !exists {
			t.Errorf("Component time not recorded for %s", component)
		}
	}
	
	// Verify bottleneck component is identified
	if result.BottleneckComponent == "" {
		t.Error("Bottleneck component should be identified")
	}
	
	// Verify the bottleneck component has the longest time
	bottleneckTime := result.ComponentTimes[result.BottleneckComponent]
	for component, duration := range result.ComponentTimes {
		if component != result.BottleneckComponent && duration > bottleneckTime {
			t.Errorf("Component %s (%dms) has longer time than bottleneck %s (%dms)", 
				component, duration, result.BottleneckComponent, bottleneckTime)
		}
	}
}

func TestPipelineAnalyze_ErrorHandling(t *testing.T) {
	options := GetDefaultPipelineOptions()
	options.ContinueOnError = true
	
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	
	// Test with very short timeout to force timeout errors
	options.ComponentTimeout = 1 * time.Millisecond
	request := AnalysisRequest{
		ID:          "error-test",
		Content:     "Test content for error handling",
		ContentType: "text",
		Options:     options,
	}
	
	result, err := pipeline.Analyze(ctx, request)
	
	// Should not fail completely due to ContinueOnError = true
	if err != nil {
		t.Fatalf("Analysis should not fail with ContinueOnError=true: %v", err)
	}
	
	// Should have partial results flag set
	if !result.PartialResults {
		t.Error("PartialResults should be true when errors occur")
	}
	
	// Should have error records
	if len(result.Errors) == 0 {
		t.Error("Should have error records when timeouts occur")
	}
}

func TestPipelineAnalyze_ContextTimeout(t *testing.T) {
	options := GetDefaultPipelineOptions()
	options.OverallTimeout = 1 * time.Millisecond
	
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "timeout-test",
		Content:     "Test content for timeout handling",
		ContentType: "text",
		Options:     options,
	}
	
	_, err = pipeline.Analyze(ctx, request)
	
	// Should fail due to overall timeout
	if err == nil {
		t.Error("Analysis should fail with very short overall timeout")
	}
	
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("Error should be timeout-related, got: %v", err)
	}
}

func TestPipelineOptions_Variants(t *testing.T) {
	testCases := []struct {
		name    string
		options PipelineOptions
	}{
		{
			name:    "Default Options",
			options: GetDefaultPipelineOptions(),
		},
		{
			name:    "High Performance Options",
			options: GetHighPerformanceOptions(),
		},
		{
			name:    "Comprehensive Options",
			options: GetComprehensiveOptions(),
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pipeline, err := NewAnalysisPipeline(tc.options)
			if err != nil {
				t.Fatalf("Failed to create pipeline with %s: %v", tc.name, err)
			}
			
			ctx := context.Background()
			request := AnalysisRequest{
				ID:          fmt.Sprintf("options-test-%s", tc.name),
				Content:     "Test content with email test@example.com",
				ContentType: "text",
				Options:     tc.options,
			}
			
			result, err := pipeline.Analyze(ctx, request)
			if err != nil {
				t.Fatalf("Analysis failed with %s: %v", tc.name, err)
			}
			
			// Basic validation
			if result.RequestID != request.ID {
				t.Errorf("Request ID mismatch in %s", tc.name)
			}
			
			if result.ProcessingTimeMs <= 0 {
				t.Errorf("Processing time should be positive in %s", tc.name)
			}
		})
	}
}

func TestPipelineAnalyze_ComponentSelective(t *testing.T) {
	// Test with only specific components enabled
	options := GetDefaultPipelineOptions()
	options.EnablePreprocessing = true
	options.EnablePIIDetection = true
	options.EnableClassification = false
	options.EnableMLAnalysis = false
	options.EnableFileScanning = false
	
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "selective-test",
		Content:     "Email: test@example.com, Phone: 555-123-4567",
		ContentType: "text",
		Options:     options,
	}
	
	result, err := pipeline.Analyze(ctx, request)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}
	
	// Should have results for enabled components
	if result.Preprocessing == nil {
		t.Error("Preprocessing result should not be nil")
	}
	
	if result.PIIDetection == nil {
		t.Error("PII detection result should not be nil")
	}
	
	// Should not have results for disabled components
	if result.Classification != nil {
		t.Error("Classification result should be nil when disabled")
	}
	
	if result.MLAnalysis != nil {
		t.Error("ML analysis result should be nil when disabled")
	}
	
	if result.FileScanning != nil {
		t.Error("File scanning result should be nil when disabled")
	}
}

func TestPipelineStats(t *testing.T) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	// Run multiple analyses to generate stats
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		request := AnalysisRequest{
			ID:          fmt.Sprintf("stats-test-%d", i),
			Content:     fmt.Sprintf("Test content %d with email test%d@example.com", i, i),
			ContentType: "text",
			Options:     options,
		}
		
		_, err := pipeline.Analyze(ctx, request)
		if err != nil {
			t.Fatalf("Analysis %d failed: %v", i, err)
		}
	}
	
	// Get and validate stats
	stats := pipeline.GetPipelineStats()
	
	totalRequests, ok := stats["total_requests"].(int64)
	if !ok || totalRequests != 3 {
		t.Errorf("Expected 3 total requests, got %v", stats["total_requests"])
	}
	
	avgProcessTime, ok := stats["average_process_time"].(string)
	if !ok || avgProcessTime == "" {
		t.Errorf("Expected non-empty average process time, got %v", stats["average_process_time"])
	}
	
	componentStats, ok := stats["component_statistics"].(map[string]ComponentStats)
	if !ok {
		t.Errorf("Expected component statistics map, got %T", stats["component_statistics"])
	} else {
		// Check that we have stats for expected components
		expectedComponents := []string{"preprocessing", "pii_detection", "classification", "ml_analysis"}
		for _, component := range expectedComponents {
			if compStats, exists := componentStats[component]; !exists {
				t.Errorf("Missing stats for component %s", component)
			} else {
				if compStats.ExecutionCount != 3 {
					t.Errorf("Expected 3 executions for %s, got %d", component, compStats.ExecutionCount)
				}
				
				if compStats.AverageTime <= 0 {
					t.Errorf("Expected positive average time for %s", component)
				}
			}
		}
	}
}

func TestPipelineRecommendations(t *testing.T) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	
	testCases := []struct {
		name                  string
		content               string
		expectedRecommendations []string
	}{
		{
			name:    "Safe Content",
			content: "This is a simple, safe document with no sensitive information.",
			expectedRecommendations: []string{"Content appears safe for general use"},
		},
		{
			name:    "SSN Content",
			content: "Employee SSN: 123-45-6789",
			expectedRecommendations: []string{"PII items", "SSN detected"},
		},
		{
			name:    "Credit Card Content",
			content: "Credit card number: 4532-1234-5678-9012",
			expectedRecommendations: []string{"PII items", "Credit card detected"},
		},
		{
			name:    "Email Content",
			content: "Contact: support@company.com",
			expectedRecommendations: []string{"Email addresses detected"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			request := AnalysisRequest{
				ID:          fmt.Sprintf("rec-test-%s", tc.name),
				Content:     tc.content,
				ContentType: "text",
				Options:     options,
			}
			
			result, err := pipeline.Analyze(ctx, request)
			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}
			
			if len(result.Recommendations) == 0 {
				t.Error("Should have at least one recommendation")
			}
			
			// Check that expected recommendations are present
			for _, expectedRec := range tc.expectedRecommendations {
				found := false
				for _, actualRec := range result.Recommendations {
					if strings.Contains(actualRec, expectedRec) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected recommendation containing '%s' not found in %v", expectedRec, result.Recommendations)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkPipelineAnalyze_SmallText(b *testing.B) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		b.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "benchmark-small",
		Content:     "Test email: test@example.com",
		ContentType: "text",
		Options:     options,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.ID = fmt.Sprintf("benchmark-small-%d", i)
		_, err := pipeline.Analyze(ctx, request)
		if err != nil {
			b.Fatalf("Analysis failed: %v", err)
		}
	}
}

func BenchmarkPipelineAnalyze_LargeText(b *testing.B) {
	options := GetDefaultPipelineOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		b.Fatalf("Failed to create pipeline: %v", err)
	}
	
	// Create large text content
	largeContent := strings.Repeat("This is a comprehensive business document with sensitive information including emails like test@company.com and phone numbers like 555-123-4567. ", 100)
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "benchmark-large",
		Content:     largeContent,
		ContentType: "text",
		Options:     options,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.ID = fmt.Sprintf("benchmark-large-%d", i)
		_, err := pipeline.Analyze(ctx, request)
		if err != nil {
			b.Fatalf("Analysis failed: %v", err)
		}
	}
}

func BenchmarkPipelineAnalyze_HighPerformance(b *testing.B) {
	options := GetHighPerformanceOptions()
	pipeline, err := NewAnalysisPipeline(options)
	if err != nil {
		b.Fatalf("Failed to create pipeline: %v", err)
	}
	
	ctx := context.Background()
	request := AnalysisRequest{
		ID:          "benchmark-hp",
		Content:     "Quick test with email test@example.com and phone 555-123-4567",
		ContentType: "text",
		Options:     options,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request.ID = fmt.Sprintf("benchmark-hp-%d", i)
		_, err := pipeline.Analyze(ctx, request)
		if err != nil {
			b.Fatalf("Analysis failed: %v", err)
		}
	}
} 