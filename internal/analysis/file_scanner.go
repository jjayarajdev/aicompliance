package analysis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ai-gateway-poc/internal/logging"
	"github.com/sirupsen/logrus"
)

// FileScanner represents the file scanning and analysis engine
type FileScanner struct {
	config         *FileScannerConfig
	logger         *logging.Logger
	piiDetector    *PIIDetector
	classifier     *ContentClassifier
	mlAnalyzer     *MLAnalyzer
	extractors     map[string]TextExtractor
	ocrEngine      OCREngine
}

// FileScannerConfig holds configuration for file scanning
type FileScannerConfig struct {
	Enabled              bool                  `mapstructure:"enabled"`
	MaxFileSize         int64                 `mapstructure:"max_file_size"`
	AllowedTypes        []string              `mapstructure:"allowed_types"`
	EnableOCR           bool                  `mapstructure:"enable_ocr"`
	EnableTextExtraction bool                  `mapstructure:"enable_text_extraction"`
	EnableContentAnalysis bool                 `mapstructure:"enable_content_analysis"`
	TempDirectory       string                `mapstructure:"temp_directory"`
	KeepOriginalFiles   bool                  `mapstructure:"keep_original_files"`
	ScanTimeout         time.Duration         `mapstructure:"scan_timeout"`
	ExtractorConfigs    map[string]ExtractorConfig `mapstructure:"extractors"`
	OCRConfig           OCRConfig             `mapstructure:"ocr"`
}

// ExtractorConfig holds configuration for text extractors
type ExtractorConfig struct {
	Enabled bool                   `mapstructure:"enabled"`
	Options map[string]interface{} `mapstructure:"options"`
}

// OCRConfig holds OCR engine configuration
type OCRConfig struct {
	Enabled    bool                   `mapstructure:"enabled"`
	Engine     string                 `mapstructure:"engine"`
	Languages  []string               `mapstructure:"languages"`
	Confidence float64                `mapstructure:"min_confidence"`
	Options    map[string]interface{} `mapstructure:"options"`
}

// TextExtractor interface for extracting text from different file types
type TextExtractor interface {
	GetSupportedTypes() []string
	ExtractText(ctx context.Context, data []byte, filename string) (*TextExtractionResult, error)
	IsHealthy() bool
}

// OCREngine interface for optical character recognition
type OCREngine interface {
	ExtractTextFromImage(ctx context.Context, imageData []byte, filename string) (*OCRResult, error)
	GetSupportedFormats() []string
	IsHealthy() bool
}

// FileUpload represents an uploaded file for scanning
type FileUpload struct {
	Filename    string            `json:"filename"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	Data        []byte            `json:"-"`
	Metadata    map[string]string `json:"metadata"`
	UploadedAt  time.Time         `json:"uploaded_at"`
}

// FileScanResult represents the complete scan result
type FileScanResult struct {
	File                *FileUpload              `json:"file"`
	TextExtraction      *TextExtractionResult    `json:"text_extraction,omitempty"`
	OCRResult           *OCRResult               `json:"ocr_result,omitempty"`
	PIIDetection        *PIIDetectionResult      `json:"pii_detection,omitempty"`
	Classification      *ClassificationResult    `json:"classification,omitempty"`
	MLAnalysis          *MLAnalysisResult        `json:"ml_analysis,omitempty"`
	SecurityAssessment  *SecurityAssessment      `json:"security_assessment"`
	OverallRisk         string                   `json:"overall_risk"`
	ConfidenceScore     float64                  `json:"confidence_score"`
	ProcessingTime      time.Duration            `json:"processing_time"`
	Recommendations     []string                 `json:"recommendations"`
	Warnings            []string                 `json:"warnings"`
	Errors              []string                 `json:"errors"`
}

// TextExtractionResult represents extracted text from a file
type TextExtractionResult struct {
	ExtractedText   string                 `json:"extracted_text"`
	Extractor       string                 `json:"extractor"`
	Confidence      float64                `json:"confidence"`
	Metadata        map[string]interface{} `json:"metadata"`
	ProcessingTime  time.Duration          `json:"processing_time"`
	WordCount       int                    `json:"word_count"`
	CharacterCount  int                    `json:"character_count"`
	Language        string                 `json:"language,omitempty"`
}

// OCRResult represents OCR extraction results
type OCRResult struct {
	ExtractedText  string        `json:"extracted_text"`
	Confidence     float64       `json:"confidence"`
	BoundingBoxes  []BoundingBox `json:"bounding_boxes,omitempty"`
	ProcessingTime time.Duration `json:"processing_time"`
	Engine         string        `json:"engine"`
	Language       string        `json:"language"`
	WordCount      int           `json:"word_count"`
}

// BoundingBox represents text location in an image
type BoundingBox struct {
	Text       string  `json:"text"`
	Confidence float64 `json:"confidence"`
	X          int     `json:"x"`
	Y          int     `json:"y"`
	Width      int     `json:"width"`
	Height     int     `json:"height"`
}

// SecurityAssessment represents security analysis of the file
type SecurityAssessment struct {
	RiskLevel        string            `json:"risk_level"`
	ThreatIndicators []ThreatIndicator `json:"threat_indicators"`
	DataSensitivity  string            `json:"data_sensitivity"`
	ComplianceFlags  []string          `json:"compliance_flags"`
	AccessControls   []string          `json:"recommended_access_controls"`
}

// ThreatIndicator represents a potential security threat
type ThreatIndicator struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Location    string  `json:"location,omitempty"`
}

// Default supported file types
var defaultSupportedTypes = []string{
	// Text files
	"text/plain", "text/csv", "text/html", "text/xml",
	// Documents
	"application/pdf", "application/msword", 
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"application/vnd.ms-excel",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	"application/vnd.ms-powerpoint",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation",
	// Images
	"image/jpeg", "image/png", "image/gif", "image/bmp", "image/tiff",
	// Archives (for scanning contents)
	"application/zip", "application/x-rar-compressed",
}

// NewFileScanner creates a new file scanner instance
func NewFileScanner(config *FileScannerConfig, piiDetector *PIIDetector, classifier *ContentClassifier, mlAnalyzer *MLAnalyzer, logger *logging.Logger) (*FileScanner, error) {
	if config == nil {
		config = getDefaultFileScannerConfig()
	}

	if logger == nil {
		logger = logging.GetGlobalLogger()
	}

	scanner := &FileScanner{
		config:      config,
		logger:      logger.WithComponent("file_scanner"),
		piiDetector: piiDetector,
		classifier:  classifier,
		mlAnalyzer:  mlAnalyzer,
		extractors:  make(map[string]TextExtractor),
	}

	// Initialize text extractors
	if err := scanner.initializeExtractors(); err != nil {
		return nil, fmt.Errorf("failed to initialize text extractors: %w", err)
	}

	// Initialize OCR engine if enabled
	if config.EnableOCR {
		if err := scanner.initializeOCR(); err != nil {
			scanner.logger.WithError(err).Warn("Failed to initialize OCR engine")
		}
	}

	scanner.logger.Info("File scanner initialized successfully")
	return scanner, nil
}

// initializeExtractors initializes text extractors for different file types
func (fs *FileScanner) initializeExtractors() error {
	// Initialize mock text extractor for demonstration
	mockExtractor := &MockTextExtractor{
		logger: fs.logger.WithComponent("mock_extractor"),
	}
	fs.extractors["mock"] = mockExtractor

	// TODO: Initialize real extractors (PDFBox, Apache Tika, etc.)
	
	fs.logger.WithField("extractors_count", len(fs.extractors)).Info("Text extractors initialized")
	return nil
}

// initializeOCR initializes the OCR engine
func (fs *FileScanner) initializeOCR() error {
	// Initialize mock OCR engine for demonstration
	fs.ocrEngine = &MockOCREngine{
		logger: fs.logger.WithComponent("mock_ocr"),
	}

	fs.logger.Info("OCR engine initialized")
	return nil
}

// ScanFile performs comprehensive scanning and analysis of an uploaded file
func (fs *FileScanner) ScanFile(ctx context.Context, upload *FileUpload) (*FileScanResult, error) {
	start := time.Now()

	if !fs.config.Enabled {
		return &FileScanResult{
			File:           upload,
			OverallRisk:    "unknown",
			ProcessingTime: time.Since(start),
			Warnings:       []string{"File scanning is disabled"},
		}, nil
	}

	// Validate file
	if err := fs.validateFile(upload); err != nil {
		return nil, fmt.Errorf("file validation failed: %w", err)
	}

	// Initialize result
	result := &FileScanResult{
		File:            upload,
		SecurityAssessment: &SecurityAssessment{},
		Recommendations: []string{},
		Warnings:        []string{},
		Errors:          []string{},
	}

	// Create scan context with timeout
	ctx, cancel := context.WithTimeout(ctx, fs.config.ScanTimeout)
	defer cancel()

	// Determine file type and extract text
	extractedText := ""
	
	if fs.isImageFile(upload.ContentType) && fs.config.EnableOCR && fs.ocrEngine != nil {
		// Extract text using OCR for images
		ocrResult, err := fs.ocrEngine.ExtractTextFromImage(ctx, upload.Data, upload.Filename)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("OCR failed: %v", err))
		} else {
			result.OCRResult = ocrResult
			extractedText = ocrResult.ExtractedText
		}
	} else if fs.config.EnableTextExtraction {
		// Extract text using appropriate extractor
		textResult, err := fs.extractTextFromFile(ctx, upload)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Text extraction failed: %v", err))
		} else {
			result.TextExtraction = textResult
			extractedText = textResult.ExtractedText
		}
	}

	// Perform content analysis if text was extracted
	if extractedText != "" && fs.config.EnableContentAnalysis {
		// PII Detection
		if fs.piiDetector != nil {
			piiResult, err := fs.piiDetector.DetectPII(ctx, extractedText)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("PII detection failed: %v", err))
			} else {
				result.PIIDetection = piiResult
			}
		}

		// Content Classification
		if fs.classifier != nil {
			classResult, err := fs.classifier.ClassifyContent(ctx, extractedText)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Content classification failed: %v", err))
			} else {
				result.Classification = classResult
			}
		}

		// ML Analysis
		if fs.mlAnalyzer != nil {
			mlResult, err := fs.mlAnalyzer.AnalyzeContent(ctx, extractedText)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("ML analysis failed: %v", err))
			} else {
				result.MLAnalysis = mlResult
			}
		}
	}

	// Perform security assessment
	fs.performSecurityAssessment(result)

	// Calculate overall confidence and risk
	result.ConfidenceScore = fs.calculateOverallConfidence(result)
	result.OverallRisk = fs.determineOverallRisk(result)

	// Generate recommendations
	result.Recommendations = fs.generateFileRecommendations(result)

	result.ProcessingTime = time.Since(start)

	fs.logger.WithFields(logrus.Fields{
		"filename":        upload.Filename,
		"file_size":       upload.Size,
		"content_type":    upload.ContentType,
		"overall_risk":    result.OverallRisk,
		"confidence":      result.ConfidenceScore,
		"processing_ms":   result.ProcessingTime.Milliseconds(),
		"text_extracted":  extractedText != "",
		"pii_detected":    result.PIIDetection != nil && result.PIIDetection.HasPII,
		"errors_count":    len(result.Errors),
	}).Info("File scan completed")

	return result, nil
}

// validateFile validates the uploaded file
func (fs *FileScanner) validateFile(upload *FileUpload) error {
	// Check file size
	if fs.config.MaxFileSize > 0 && upload.Size > fs.config.MaxFileSize {
		return fmt.Errorf("file size %d exceeds maximum allowed size %d", upload.Size, fs.config.MaxFileSize)
	}

	// Check file type
	if len(fs.config.AllowedTypes) > 0 {
		allowed := false
		for _, allowedType := range fs.config.AllowedTypes {
			if upload.ContentType == allowedType {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("file type %s is not allowed", upload.ContentType)
		}
	}

	// Basic file content validation
	if len(upload.Data) == 0 {
		return fmt.Errorf("file is empty")
	}

	return nil
}

// isImageFile checks if the file is an image
func (fs *FileScanner) isImageFile(contentType string) bool {
	return strings.HasPrefix(contentType, "image/")
}

// extractTextFromFile extracts text from a file using the appropriate extractor
func (fs *FileScanner) extractTextFromFile(ctx context.Context, upload *FileUpload) (*TextExtractionResult, error) {
	// Find appropriate extractor
	var extractor TextExtractor
	for _, ext := range fs.extractors {
		supportedTypes := ext.GetSupportedTypes()
		for _, supportedType := range supportedTypes {
			if upload.ContentType == supportedType || supportedType == "*" {
				if ext.IsHealthy() {
					extractor = ext
					break
				}
			}
		}
		if extractor != nil {
			break
		}
	}

	if extractor == nil {
		return nil, fmt.Errorf("no text extractor available for content type: %s", upload.ContentType)
	}

	return extractor.ExtractText(ctx, upload.Data, upload.Filename)
}

// performSecurityAssessment performs security analysis of the scan results
func (fs *FileScanner) performSecurityAssessment(result *FileScanResult) {
	assessment := result.SecurityAssessment
	
	// Analyze PII exposure
	if result.PIIDetection != nil && result.PIIDetection.HasPII {
		assessment.ThreatIndicators = append(assessment.ThreatIndicators, ThreatIndicator{
			Type:        "pii_exposure",
			Severity:    fs.getPIISeverity(result.PIIDetection),
			Description: fmt.Sprintf("PII detected: %d items across %d types", len(result.PIIDetection.Matches), len(result.PIIDetection.Statistics.MatchesByType)),
			Confidence:  result.PIIDetection.Statistics.ConfidenceAvg,
		})
		
		assessment.ComplianceFlags = append(assessment.ComplianceFlags, "GDPR", "CCPA", "HIPAA")
	}

	// Analyze content sensitivity
	if result.Classification != nil {
		assessment.DataSensitivity = string(result.Classification.Level)
		
		if result.Classification.Level == SensitivityRestricted || result.Classification.Level == SensitivityConfidential {
			assessment.ThreatIndicators = append(assessment.ThreatIndicators, ThreatIndicator{
				Type:        "sensitive_content",
				Severity:    "high",
				Description: fmt.Sprintf("Content classified as %s", result.Classification.Level),
				Confidence:  result.Classification.Confidence,
			})
		}
	}

	// Analyze business information exposure
	if result.MLAnalysis != nil {
		for _, category := range result.MLAnalysis.BusinessCategories {
			if category.Confidence > 0.7 && (category.Sensitivity == "confidential" || category.Sensitivity == "restricted") {
				assessment.ThreatIndicators = append(assessment.ThreatIndicators, ThreatIndicator{
					Type:        "business_intel_exposure",
					Severity:    "medium",
					Description: fmt.Sprintf("Business category detected: %s", category.Category),
					Confidence:  category.Confidence,
				})
			}
		}
	}

	// Set risk level based on threat indicators
	assessment.RiskLevel = fs.calculateRiskLevel(assessment.ThreatIndicators)
	
	// Generate access control recommendations
	assessment.AccessControls = fs.generateAccessControls(assessment)
}

// getPIISeverity determines PII severity level
func (fs *FileScanner) getPIISeverity(piiResult *PIIDetectionResult) string {
	if len(piiResult.Matches) > 10 {
		return "critical"
	} else if len(piiResult.Matches) > 5 {
		return "high"
	} else if len(piiResult.Matches) > 1 {
		return "medium"
	}
	return "low"
}

// calculateRiskLevel calculates overall risk level
func (fs *FileScanner) calculateRiskLevel(indicators []ThreatIndicator) string {
	if len(indicators) == 0 {
		return "low"
	}

	criticalCount := 0
	highCount := 0
	
	for _, indicator := range indicators {
		switch indicator.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		}
	}

	if criticalCount > 0 {
		return "critical"
	} else if highCount > 0 {
		return "high"
	} else if len(indicators) > 2 {
		return "medium"
	}
	
	return "low"
}

// generateAccessControls generates access control recommendations
func (fs *FileScanner) generateAccessControls(assessment *SecurityAssessment) []string {
	controls := []string{}

	switch assessment.RiskLevel {
	case "critical":
		controls = append(controls, "Restrict to C-level executives only")
		controls = append(controls, "Enable maximum audit logging")
		controls = append(controls, "Require multi-factor authentication")
		controls = append(controls, "Implement data loss prevention")
	case "high":
		controls = append(controls, "Limit to authorized personnel")
		controls = append(controls, "Enable audit logging")
		controls = append(controls, "Require authentication")
	case "medium":
		controls = append(controls, "Internal access only")
		controls = append(controls, "Basic audit logging")
	default:
		controls = append(controls, "Standard access controls")
	}

	return controls
}

// calculateOverallConfidence calculates overall confidence score
func (fs *FileScanner) calculateOverallConfidence(result *FileScanResult) float64 {
	var totalScore float64
	var components int

	if result.TextExtraction != nil {
		totalScore += result.TextExtraction.Confidence
		components++
	}

	if result.OCRResult != nil {
		totalScore += result.OCRResult.Confidence
		components++
	}

	if result.PIIDetection != nil {
		totalScore += result.PIIDetection.Statistics.ConfidenceAvg
		components++
	}

	if result.Classification != nil {
		totalScore += result.Classification.Confidence
		components++
	}

	if result.MLAnalysis != nil {
		totalScore += result.MLAnalysis.ConfidenceScore
		components++
	}

	if components == 0 {
		return 0.0
	}

	return totalScore / float64(components)
}

// determineOverallRisk determines the overall risk level
func (fs *FileScanner) determineOverallRisk(result *FileScanResult) string {
	if result.SecurityAssessment != nil {
		return result.SecurityAssessment.RiskLevel
	}
	return "unknown"
}

// generateFileRecommendations generates recommendations for file handling
func (fs *FileScanner) generateFileRecommendations(result *FileScanResult) []string {
	recommendations := []string{}

	// Basic file recommendations
	recommendations = append(recommendations, "Store file in secure location with appropriate access controls")

	// PII-based recommendations
	if result.PIIDetection != nil && result.PIIDetection.HasPII {
		recommendations = append(recommendations, "PII detected - ensure compliance with data protection regulations")
		recommendations = append(recommendations, "Consider data anonymization or pseudonymization")
	}

	// Classification-based recommendations
	if result.Classification != nil {
		switch result.Classification.Level {
		case SensitivityRestricted:
			recommendations = append(recommendations, "CRITICAL: Implement maximum security measures for restricted content")
		case SensitivityConfidential:
			recommendations = append(recommendations, "Apply confidential data handling procedures")
		}
	}

	// ML analysis recommendations
	if result.MLAnalysis != nil {
		recommendations = append(recommendations, result.MLAnalysis.Recommendations...)
	}

	// Risk-based recommendations
	switch result.OverallRisk {
	case "critical":
		recommendations = append(recommendations, "URGENT: Escalate to security team for immediate review")
	case "high":
		recommendations = append(recommendations, "Schedule security review within 24 hours")
	}

	return recommendations
}

// getDefaultFileScannerConfig returns default file scanner configuration
func getDefaultFileScannerConfig() *FileScannerConfig {
	return &FileScannerConfig{
		Enabled:               true,
		MaxFileSize:          50 * 1024 * 1024, // 50MB
		AllowedTypes:         defaultSupportedTypes,
		EnableOCR:            true,
		EnableTextExtraction: true,
		EnableContentAnalysis: true,
		TempDirectory:        "/tmp",
		KeepOriginalFiles:    false,
		ScanTimeout:          5 * time.Minute,
		ExtractorConfigs: map[string]ExtractorConfig{
			"mock": {Enabled: true},
		},
		OCRConfig: OCRConfig{
			Enabled:    true,
			Engine:     "mock",
			Languages:  []string{"en"},
			Confidence: 0.7,
		},
	}
}

// Close gracefully shuts down the file scanner
func (fs *FileScanner) Close() error {
	fs.logger.Info("File scanner closed")
	return nil
} 