package analysis

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AnalysisRequest represents a request for comprehensive content analysis
type AnalysisRequest struct {
	ID          string                 `json:"id"`
	Content     string                 `json:"content"`
	ContentType string                 `json:"content_type"` // "text", "file", "image", etc.
	Metadata    map[string]interface{} `json:"metadata"`
	Options     PipelineOptions        `json:"options"`
}

// AnalysisResult contains the aggregated results from all analysis components
type AnalysisResult struct {
	RequestID        string                   `json:"request_id"`
	ProcessingTimeMs int64                    `json:"processing_time_ms"`
	
	// Component results
	Preprocessing    *PreprocessingResult     `json:"preprocessing,omitempty"`
	PIIDetection     *PIIDetectionResult      `json:"pii_detection,omitempty"`
	Classification   *ClassificationResult    `json:"classification,omitempty"`
	MLAnalysis       *MLAnalysisResult        `json:"ml_analysis,omitempty"`
	FileScanning     *FileScanResult          `json:"file_scanning,omitempty"`
	
	// Aggregated insights
	OverallRiskLevel string                   `json:"overall_risk_level"`
	Confidence       float64                  `json:"confidence"`
	Recommendations  []string                 `json:"recommendations"`
	
	// Performance metrics
	ComponentTimes   map[string]int64         `json:"component_times"`
	ParallelSpeedup  float64                  `json:"parallel_speedup"`
	BottleneckComponent string                `json:"bottleneck_component"`
	
	// Error handling
	Errors           []ComponentError         `json:"errors,omitempty"`
	PartialResults   bool                     `json:"partial_results"`
}

// ComponentError represents an error from a specific analysis component
type ComponentError struct {
	Component string `json:"component"`
	Error     string `json:"error"`
	Fatal     bool   `json:"fatal"`
}

// PipelineOptions configures the analysis pipeline behavior
type PipelineOptions struct {
	// Component enablement
	EnablePreprocessing   bool `json:"enable_preprocessing"`
	EnablePIIDetection    bool `json:"enable_pii_detection"`
	EnableClassification  bool `json:"enable_classification"`
	EnableMLAnalysis      bool `json:"enable_ml_analysis"`
	EnableFileScanning    bool `json:"enable_file_scanning"`
	
	// Parallelism settings
	MaxConcurrency       int           `json:"max_concurrency"`
	ComponentTimeout     time.Duration `json:"component_timeout"`
	OverallTimeout       time.Duration `json:"overall_timeout"`
	
	// Error handling
	ContinueOnError      bool `json:"continue_on_error"`
	RequireAllComponents bool `json:"require_all_components"`
	
	// Performance tuning
	EnableMetrics        bool `json:"enable_metrics"`
	WarmupComponents     bool `json:"warmup_components"`
}

// AnalysisPipeline coordinates parallel execution of analysis components
type AnalysisPipeline struct {
	// Component instances
	preprocessor      *ContentPreprocessor
	piiDetector       *PIIDetector
	classifier        *ContentClassifier
	mlAnalyzer        *MLAnalyzer
	fileScanner       *FileScanner
	
	// Ensemble voting system
	ensembleVoter     *EnsembleVoter
	
	// Configuration
	options          PipelineOptions
	
	// Performance tracking
	mu               sync.RWMutex
	totalRequests    int64
	totalProcessTime time.Duration
	componentStats   map[string]ComponentStats
}

// ComponentStats tracks performance metrics for each component
type ComponentStats struct {
	ExecutionCount   int64         `json:"execution_count"`
	TotalTime        time.Duration `json:"total_time"`
	AverageTime      time.Duration `json:"average_time"`
	MinTime          time.Duration `json:"min_time"`
	MaxTime          time.Duration `json:"max_time"`
	ErrorCount       int64         `json:"error_count"`
	SuccessRate      float64       `json:"success_rate"`
}

// WorkerResult represents the result from a component worker
type WorkerResult struct {
	Component string
	Result    interface{}
	Error     error
	Duration  time.Duration
}

// NewAnalysisPipeline creates a new parallel analysis pipeline
func NewAnalysisPipeline(options PipelineOptions) (*AnalysisPipeline, error) {
	pipeline := &AnalysisPipeline{
		options:        options,
		componentStats: make(map[string]ComponentStats),
	}
	
	// Initialize components based on options
	if options.EnablePreprocessing {
		preprocessingOpts := GetDefaultOptions()
		pipeline.preprocessor = NewContentPreprocessor(preprocessingOpts)
	}
	
	if options.EnablePIIDetection {
		piiConfig := &PIIDetectorConfig{
			Enabled:          true,
			SensitivityLevel: "medium",
			RedactionMode:    "mask",
			Patterns:         make(map[string]string),
			CustomPatterns:   make(map[string]string),
			ExcludePatterns:  []string{},
			MaxTextSize:      1048576, // 1MB
		}
		var err error
		pipeline.piiDetector, err = NewPIIDetector(piiConfig, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize PII detector: %w", err)
		}
	}
	
	if options.EnableClassification {
		classConfig := &ContentClassifierConfig{
			Enabled:       true,
			DefaultLevel:  SensitivityPublic,
			MinConfidence: 0.3,
			LevelConfigs:  make(map[SensitivityLevel]LevelConfig),
			GlobalRules:   []RuleConfig{},
			MaxTextSize:   1048576, // 1MB
		}
		
		// Initialize default level configs
		levels := []SensitivityLevel{SensitivityPublic, SensitivityInternal, SensitivityConfidential, SensitivityRestricted}
		for _, level := range levels {
			classConfig.LevelConfigs[level] = LevelConfig{
				Keywords:         []string{},
				Patterns:         []string{},
				RequiredPIITypes: []string{},
				MinPIICount:      0,
				Weight:           1.0,
				Enabled:          true,
			}
		}
		
		var err error
		pipeline.classifier, err = NewContentClassifier(classConfig, pipeline.piiDetector, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize content classifier: %w", err)
		}
	}
	
	if options.EnableMLAnalysis {
		mlConfig := &MLAnalyzerConfig{
			Enabled:            true,
			DefaultProvider:    "mock",
			EnableSentiment:    true,
			EnableTopics:       true,
			EnableEntities:     true,
			Timeout:            30 * time.Second,
			MinConfidenceScore: 0.3,
		}
		var err error
		pipeline.mlAnalyzer, err = NewMLAnalyzer(mlConfig, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ML analyzer: %w", err)
		}
	}
	
	if options.EnableFileScanning {
		fileScanConfig := &FileScannerConfig{
			Enabled:              true,
			MaxFileSize:          50 * 1024 * 1024, // 50MB
			AllowedTypes:         []string{"text/plain", "application/pdf", "image/jpeg", "image/png"},
			EnableOCR:            true,
			EnableTextExtraction: true,
			EnableContentAnalysis: true,
			ScanTimeout:          60 * time.Second,
			ExtractorConfigs:     make(map[string]ExtractorConfig),
		}
		var err error
		pipeline.fileScanner, err = NewFileScanner(fileScanConfig, pipeline.piiDetector, pipeline.classifier, pipeline.mlAnalyzer, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize file scanner: %w", err)
		}
	}
	
	// Warmup components if enabled
	if options.WarmupComponents {
		pipeline.warmupComponents()
	}
	
	return pipeline, nil
}

// Analyze performs comprehensive parallel analysis of the provided content
func (p *AnalysisPipeline) Analyze(ctx context.Context, request AnalysisRequest) (*AnalysisResult, error) {
	startTime := time.Now()
	
	// Create overall timeout context
	analyzeCtx, cancel := context.WithTimeout(ctx, p.options.OverallTimeout)
	defer cancel()
	
	result := &AnalysisResult{
		RequestID:      request.ID,
		ComponentTimes: make(map[string]int64),
		Errors:         []ComponentError{},
	}
	
	// Step 1: Preprocessing (must run first as other components depend on it)
	var preprocessedText string = request.Content
	if p.options.EnablePreprocessing && p.preprocessor != nil {
		preprocessingResult, err := p.runPreprocessing(analyzeCtx, request.Content)
		if err != nil {
			if !p.options.ContinueOnError {
				return nil, fmt.Errorf("preprocessing failed: %w", err)
			}
			result.Errors = append(result.Errors, ComponentError{
				Component: "preprocessing",
				Error:     err.Error(),
				Fatal:     false,
			})
		} else {
			result.Preprocessing = preprocessingResult
			preprocessedText = preprocessingResult.ProcessedText
			result.ComponentTimes["preprocessing"] = preprocessingResult.ProcessingTimeMs
		}
	}
	
	// Step 2: Run remaining components in parallel
	workerResults := p.runParallelAnalysis(analyzeCtx, preprocessedText, request)
	
	// Step 3: Aggregate results
	p.aggregateResults(result, workerResults)
	
	// Step 4: Calculate overall metrics
	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
	p.calculateOverallMetrics(result)
	
	// Step 5: Update pipeline statistics
	p.updateStatistics(result)
	
	return result, nil
}

// runPreprocessing executes the preprocessing component
func (p *AnalysisPipeline) runPreprocessing(ctx context.Context, content string) (*PreprocessingResult, error) {
	componentCtx, cancel := context.WithTimeout(ctx, p.options.ComponentTimeout)
	defer cancel()
	
	// Run preprocessing with timeout
	resultChan := make(chan *PreprocessingResult, 1)
	errorChan := make(chan error, 1)
	
	go func() {
		result, err := p.preprocessor.Process(content)
		if err != nil {
			errorChan <- err
		} else {
			resultChan <- result
		}
	}()
	
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return nil, err
	case <-componentCtx.Done():
		return nil, fmt.Errorf("preprocessing timeout: %w", componentCtx.Err())
	}
}

// runParallelAnalysis executes the remaining analysis components in parallel
func (p *AnalysisPipeline) runParallelAnalysis(ctx context.Context, content string, request AnalysisRequest) []WorkerResult {
	var wg sync.WaitGroup
	resultsChan := make(chan WorkerResult, 4) // Buffer for up to 4 components
	
	// Launch parallel workers
	if p.options.EnablePIIDetection && p.piiDetector != nil {
		wg.Add(1)
		go p.runPIIDetectionWorker(ctx, content, &wg, resultsChan)
	}
	
	if p.options.EnableClassification && p.classifier != nil {
		wg.Add(1)
		go p.runClassificationWorker(ctx, content, &wg, resultsChan)
	}
	
	if p.options.EnableMLAnalysis && p.mlAnalyzer != nil {
		wg.Add(1)
		go p.runMLAnalysisWorker(ctx, content, &wg, resultsChan)
	}
	
	if p.options.EnableFileScanning && p.fileScanner != nil && request.ContentType != "text" {
		wg.Add(1)
		go p.runFileScanningWorker(ctx, request, &wg, resultsChan)
	}
	
	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Collect results
	var results []WorkerResult
	for result := range resultsChan {
		results = append(results, result)
	}
	
	return results
}

// runPIIDetectionWorker executes PII detection in a separate goroutine
func (p *AnalysisPipeline) runPIIDetectionWorker(ctx context.Context, content string, wg *sync.WaitGroup, resultsChan chan<- WorkerResult) {
	defer wg.Done()
	
	componentCtx, cancel := context.WithTimeout(ctx, p.options.ComponentTimeout)
	defer cancel()
	
	startTime := time.Now()
	
	// Create channel for result
	piiChan := make(chan *PIIDetectionResult, 1)
	errChan := make(chan error, 1)
	
	go func() {
		result, err := p.piiDetector.DetectPII(componentCtx, content)
		if err != nil {
			errChan <- err
		} else {
			piiChan <- result
		}
	}()
	
	select {
	case result := <-piiChan:
		resultsChan <- WorkerResult{
			Component: "pii_detection",
			Result:    result,
			Error:     nil,
			Duration:  time.Since(startTime),
		}
	case err := <-errChan:
		resultsChan <- WorkerResult{
			Component: "pii_detection",
			Result:    nil,
			Error:     err,
			Duration:  time.Since(startTime),
		}
	case <-componentCtx.Done():
		resultsChan <- WorkerResult{
			Component: "pii_detection",
			Result:    nil,
			Error:     fmt.Errorf("PII detection timeout: %w", componentCtx.Err()),
			Duration:  time.Since(startTime),
		}
	}
}

// runClassificationWorker executes content classification in a separate goroutine
func (p *AnalysisPipeline) runClassificationWorker(ctx context.Context, content string, wg *sync.WaitGroup, resultsChan chan<- WorkerResult) {
	defer wg.Done()
	
	componentCtx, cancel := context.WithTimeout(ctx, p.options.ComponentTimeout)
	defer cancel()
	
	startTime := time.Now()
	
	// Create channel for result
	classChan := make(chan *ClassificationResult, 1)
	errChan := make(chan error, 1)
	
	go func() {
		result, err := p.classifier.ClassifyContent(componentCtx, content)
		if err != nil {
			errChan <- err
		} else {
			classChan <- result
		}
	}()
	
	select {
	case result := <-classChan:
		resultsChan <- WorkerResult{
			Component: "classification",
			Result:    result,
			Error:     nil,
			Duration:  time.Since(startTime),
		}
	case err := <-errChan:
		resultsChan <- WorkerResult{
			Component: "classification",
			Result:    nil,
			Error:     err,
			Duration:  time.Since(startTime),
		}
	case <-componentCtx.Done():
		resultsChan <- WorkerResult{
			Component: "classification",
			Result:    nil,
			Error:     fmt.Errorf("classification timeout: %w", componentCtx.Err()),
			Duration:  time.Since(startTime),
		}
	}
}

// runMLAnalysisWorker executes ML analysis in a separate goroutine
func (p *AnalysisPipeline) runMLAnalysisWorker(ctx context.Context, content string, wg *sync.WaitGroup, resultsChan chan<- WorkerResult) {
	defer wg.Done()
	
	componentCtx, cancel := context.WithTimeout(ctx, p.options.ComponentTimeout)
	defer cancel()
	
	startTime := time.Now()
	
	// Create channel for result
	mlChan := make(chan *MLAnalysisResult, 1)
	errChan := make(chan error, 1)
	
	go func() {
		result, err := p.mlAnalyzer.AnalyzeContent(componentCtx, content)
		if err != nil {
			errChan <- err
		} else {
			mlChan <- result
		}
	}()
	
	select {
	case result := <-mlChan:
		resultsChan <- WorkerResult{
			Component: "ml_analysis",
			Result:    result,
			Error:     nil,
			Duration:  time.Since(startTime),
		}
	case err := <-errChan:
		resultsChan <- WorkerResult{
			Component: "ml_analysis",
			Result:    nil,
			Error:     err,
			Duration:  time.Since(startTime),
		}
	case <-componentCtx.Done():
		resultsChan <- WorkerResult{
			Component: "ml_analysis",
			Result:    nil,
			Error:     fmt.Errorf("ML analysis timeout: %w", componentCtx.Err()),
			Duration:  time.Since(startTime),
		}
	}
}

// runFileScanningWorker executes file scanning in a separate goroutine
func (p *AnalysisPipeline) runFileScanningWorker(ctx context.Context, request AnalysisRequest, wg *sync.WaitGroup, resultsChan chan<- WorkerResult) {
	defer wg.Done()
	
	componentCtx, cancel := context.WithTimeout(ctx, p.options.ComponentTimeout)
	defer cancel()
	
	startTime := time.Now()
	
	// Create channel for result
	scanChan := make(chan *FileScanResult, 1)
	errChan := make(chan error, 1)
	
	go func() {
		// For this demo, we'll analyze the content as if it were a file
		fileUpload := &FileUpload{
			Filename:    "content.txt",
			ContentType: request.ContentType,
			Size:        int64(len(request.Content)),
			Data:        []byte(request.Content),
			Metadata:    make(map[string]string),
			UploadedAt:  time.Now(),
		}
		result, err := p.fileScanner.ScanFile(componentCtx, fileUpload)
		if err != nil {
			errChan <- err
		} else {
			scanChan <- result
		}
	}()
	
	select {
	case result := <-scanChan:
		resultsChan <- WorkerResult{
			Component: "file_scanning",
			Result:    result,
			Error:     nil,
			Duration:  time.Since(startTime),
		}
	case err := <-errChan:
		resultsChan <- WorkerResult{
			Component: "file_scanning",
			Result:    nil,
			Error:     err,
			Duration:  time.Since(startTime),
		}
	case <-componentCtx.Done():
		resultsChan <- WorkerResult{
			Component: "file_scanning",
			Result:    nil,
			Error:     fmt.Errorf("file scanning timeout: %w", componentCtx.Err()),
			Duration:  time.Since(startTime),
		}
	}
}

// aggregateResults combines results from all worker components
func (p *AnalysisPipeline) aggregateResults(result *AnalysisResult, workerResults []WorkerResult) {
	for _, workerResult := range workerResults {
		result.ComponentTimes[workerResult.Component] = workerResult.Duration.Milliseconds()
		
		if workerResult.Error != nil {
			result.Errors = append(result.Errors, ComponentError{
				Component: workerResult.Component,
				Error:     workerResult.Error.Error(),
				Fatal:     false,
			})
			continue
		}
		
		// Type assertion and assignment based on component
		switch workerResult.Component {
		case "pii_detection":
			if piiResult, ok := workerResult.Result.(*PIIDetectionResult); ok {
				result.PIIDetection = piiResult
			}
		case "classification":
			if classResult, ok := workerResult.Result.(*ClassificationResult); ok {
				result.Classification = classResult
			}
		case "ml_analysis":
			if mlResult, ok := workerResult.Result.(*MLAnalysisResult); ok {
				result.MLAnalysis = mlResult
			}
		case "file_scanning":
			if scanResult, ok := workerResult.Result.(*FileScanResult); ok {
				result.FileScanning = scanResult
			}
		}
	}
	
	result.PartialResults = len(result.Errors) > 0
}

// calculateOverallMetrics computes aggregated metrics and insights
func (p *AnalysisPipeline) calculateOverallMetrics(result *AnalysisResult) {
	// Calculate overall risk level
	result.OverallRiskLevel = p.calculateOverallRiskLevel(result)
	
	// Calculate overall confidence
	result.Confidence = p.calculateOverallConfidence(result)
	
	// Generate recommendations
	result.Recommendations = p.generateRecommendations(result)
	
	// Calculate parallel speedup (theoretical)
	maxComponentTime := int64(0)
	totalSequentialTime := int64(0)
	
	for _, duration := range result.ComponentTimes {
		totalSequentialTime += duration
		if duration > maxComponentTime {
			maxComponentTime = duration
			// Find bottleneck component
			for component, time := range result.ComponentTimes {
				if time == maxComponentTime {
					result.BottleneckComponent = component
				}
			}
		}
	}
	
	if maxComponentTime > 0 {
		result.ParallelSpeedup = float64(totalSequentialTime) / float64(maxComponentTime)
	}
}

// calculateOverallRiskLevel determines the highest risk level from all components
func (p *AnalysisPipeline) calculateOverallRiskLevel(result *AnalysisResult) string {
	riskLevels := map[string]int{
		"low":          1,
		"medium":       2,
		"high":         3,
		"critical":     4,
		"public":       1,
		"internal":     2,
		"confidential": 3,
		"restricted":   4,
	}
	
	maxRisk := 0
	maxRiskLevel := "low"
	
	// Check PII detection risk
	if result.PIIDetection != nil && len(result.PIIDetection.Matches) > 0 {
		piiRisk := 2 // Medium risk for PII presence
		if len(result.PIIDetection.Matches) >= 3 {
			piiRisk = 3 // High risk for multiple PII
		}
		if piiRisk > maxRisk {
			maxRisk = piiRisk
			maxRiskLevel = []string{"", "low", "medium", "high", "critical"}[piiRisk]
		}
	}
	
	// Check classification level
	if result.Classification != nil {
		if classRisk, exists := riskLevels[string(result.Classification.Level)]; exists && classRisk > maxRisk {
			maxRisk = classRisk
			maxRiskLevel = string(result.Classification.Level)
		}
	}
	
	// Check ML analysis insights
	if result.MLAnalysis != nil {
		// Use business categories to determine risk
		for _, category := range result.MLAnalysis.BusinessCategories {
			if category.Sensitivity == "restricted" || category.Sensitivity == "confidential" {
				if riskValue, exists := riskLevels[category.Sensitivity]; exists && riskValue > maxRisk {
					maxRisk = riskValue
					maxRiskLevel = category.Sensitivity
				}
			}
		}
	}
	
	return maxRiskLevel
}

// calculateOverallConfidence computes weighted average confidence across components
func (p *AnalysisPipeline) calculateOverallConfidence(result *AnalysisResult) float64 {
	var totalConfidence float64
	var totalWeight float64
	
	// Weight each component based on importance and reliability
	if result.PIIDetection != nil {
		avgConfidence := result.PIIDetection.Statistics.ConfidenceAvg
		totalConfidence += avgConfidence * 0.3
		totalWeight += 0.3
	}
	
	if result.Classification != nil {
		totalConfidence += result.Classification.Confidence * 0.3
		totalWeight += 0.3
	}
	
	if result.MLAnalysis != nil {
		totalConfidence += result.MLAnalysis.ConfidenceScore * 0.25
		totalWeight += 0.25
	}
	
	if result.FileScanning != nil {
		totalConfidence += result.FileScanning.ConfidenceScore * 0.15
		totalWeight += 0.15
	}
	
	if totalWeight > 0 {
		return totalConfidence / totalWeight
	}
	
	return 0.0
}

// generateRecommendations creates actionable recommendations based on analysis results
func (p *AnalysisPipeline) generateRecommendations(result *AnalysisResult) []string {
	var recommendations []string
	
	// PII-based recommendations
	if result.PIIDetection != nil && len(result.PIIDetection.Matches) > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Found %d PII items - consider data masking or encryption", len(result.PIIDetection.Matches)))
		
		// Check for specific PII types
		for _, detection := range result.PIIDetection.Matches {
			switch detection.Type {
			case "ssn":
				recommendations = append(recommendations, "SSN detected - ensure GDPR/CCPA compliance")
			case "credit_card":
				recommendations = append(recommendations, "Credit card detected - verify PCI DSS compliance")
			case "email":
				recommendations = append(recommendations, "Email addresses detected - consider anonymization")
			}
		}
	}
	
	// Classification-based recommendations
	if result.Classification != nil {
		switch result.Classification.Level {
		case "confidential", "restricted":
			recommendations = append(recommendations, "High sensitivity content - restrict access and add audit logging")
		case "internal":
			recommendations = append(recommendations, "Internal content - verify appropriate access controls")
		}
	}
	
	// ML analysis recommendations
	if result.MLAnalysis != nil {
		for _, category := range result.MLAnalysis.BusinessCategories {
			if category.Sensitivity == "restricted" || category.Sensitivity == "confidential" {
				recommendations = append(recommendations, fmt.Sprintf("Business category '%s' detected - ensure appropriate access controls", category.Category))
			}
		}
	}
	
	// Performance recommendations
	if result.BottleneckComponent != "" {
		recommendations = append(recommendations, fmt.Sprintf("Consider optimizing %s component for better performance", result.BottleneckComponent))
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Content appears safe for general use")
	}
	
	return recommendations
}

// warmupComponents initializes components to improve first-request performance
func (p *AnalysisPipeline) warmupComponents() {
	warmupText := "This is a warmup test to initialize all analysis components for optimal performance."
	ctx := context.Background()
	
	if p.preprocessor != nil {
		p.preprocessor.Process(warmupText)
	}
	
	if p.piiDetector != nil {
		p.piiDetector.DetectPII(ctx, warmupText)
	}
	
	if p.classifier != nil {
		p.classifier.ClassifyContent(ctx, warmupText)
	}
	
	if p.mlAnalyzer != nil {
		p.mlAnalyzer.AnalyzeContent(ctx, warmupText)
	}
}

// updateStatistics updates pipeline performance statistics
func (p *AnalysisPipeline) updateStatistics(result *AnalysisResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	p.totalRequests++
	p.totalProcessTime += time.Duration(result.ProcessingTimeMs) * time.Millisecond
	
	// Update component statistics
	for component, duration := range result.ComponentTimes {
		stats := p.componentStats[component]
		stats.ExecutionCount++
		componentDuration := time.Duration(duration) * time.Millisecond
		stats.TotalTime += componentDuration
		stats.AverageTime = stats.TotalTime / time.Duration(stats.ExecutionCount)
		
		if stats.MinTime == 0 || componentDuration < stats.MinTime {
			stats.MinTime = componentDuration
		}
		
		if componentDuration > stats.MaxTime {
			stats.MaxTime = componentDuration
		}
		
		// Check for errors
		hasError := false
		for _, err := range result.Errors {
			if err.Component == component {
				stats.ErrorCount++
				hasError = true
				break
			}
		}
		
		if !hasError {
			stats.SuccessRate = float64(stats.ExecutionCount-stats.ErrorCount) / float64(stats.ExecutionCount)
		}
		
		p.componentStats[component] = stats
	}
}

// GetPipelineStats returns current pipeline performance statistics
func (p *AnalysisPipeline) GetPipelineStats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	avgProcessTime := time.Duration(0)
	if p.totalRequests > 0 {
		avgProcessTime = p.totalProcessTime / time.Duration(p.totalRequests)
	}
	
	return map[string]interface{}{
		"total_requests":        p.totalRequests,
		"average_process_time":  avgProcessTime.String(),
		"component_statistics":  p.componentStats,
	}
}

// GetDefaultPipelineOptions returns default pipeline configuration
func GetDefaultPipelineOptions() PipelineOptions {
	return PipelineOptions{
		EnablePreprocessing:   true,
		EnablePIIDetection:    true,
		EnableClassification:  true,
		EnableMLAnalysis:      true,
		EnableFileScanning:    false, // Disabled by default for text content
		MaxConcurrency:        4,
		ComponentTimeout:      30 * time.Second,
		OverallTimeout:        60 * time.Second,
		ContinueOnError:       true,
		RequireAllComponents:  false,
		EnableMetrics:         true,
		WarmupComponents:      true,
	}
}

// GetHighPerformanceOptions returns options optimized for speed
func GetHighPerformanceOptions() PipelineOptions {
	options := GetDefaultPipelineOptions()
	options.ComponentTimeout = 10 * time.Second
	options.OverallTimeout = 30 * time.Second
	options.MaxConcurrency = 8
	options.WarmupComponents = true
	return options
}

// GetComprehensiveOptions returns options for thorough analysis
func GetComprehensiveOptions() PipelineOptions {
	options := GetDefaultPipelineOptions()
	options.EnableFileScanning = true
	options.ComponentTimeout = 60 * time.Second
	options.OverallTimeout = 120 * time.Second
	options.RequireAllComponents = true
	return options
} 