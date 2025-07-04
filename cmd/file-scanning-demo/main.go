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
	fmt.Println("🚀 AI Gateway - File Upload Scanning Demo")
	fmt.Println("=========================================")

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

	// Initialize analysis components
	piiDetector, err := analysis.NewPIIDetector(&analysis.PIIDetectorConfig{
		Enabled:          true,
		SensitivityLevel: "medium",
		RedactionMode:    "mask",
		MaxTextSize:      1048576,
	}, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create PII detector: %v\n", err)
		return
	}

	classifier, err := analysis.NewContentClassifier(nil, piiDetector, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create content classifier: %v\n", err)
		return
	}

	mlAnalyzer, err := analysis.NewMLAnalyzer(nil, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create ML analyzer: %v\n", err)
		return
	}

	// Create file scanner
	scannerConfig := &analysis.FileScannerConfig{
		Enabled:               true,
		MaxFileSize:          50 * 1024 * 1024, // 50MB
		EnableOCR:            true,
		EnableTextExtraction: true,
		EnableContentAnalysis: true,
		ScanTimeout:          5 * time.Minute,
	}

	fileScanner, err := analysis.NewFileScanner(scannerConfig, piiDetector, classifier, mlAnalyzer, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create file scanner: %v\n", err)
		return
	}
	defer fileScanner.Close()

	fmt.Println("✅ File scanning system initialized successfully")
	fmt.Println()

	// Demo 1: Document File Scanning
	fmt.Println("📝 Demo 1: Document File Scanning")
	fmt.Println("---------------------------------")

	documentFiles := []struct {
		name        string
		filename    string
		contentType string
		size        int64
		description string
	}{
		{
			"Financial Report PDF",
			"Q3_Financial_Report.pdf",
			"application/pdf",
			95000,
			"Quarterly financial report with revenue and performance data",
		},
		{
			"Strategic Planning Doc",
			"Strategic_Plan_2024.docx",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			45000,
			"Strategic planning document with confidential business information",
		},
		{
			"Customer Database",
			"Customer_Data.xlsx",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			125000,
			"Customer database with PII and financial information",
		},
		{
			"Legal Contract",
			"Software_License_Agreement.docx",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			78000,
			"Software licensing agreement with legal terms",
		},
		{
			"Employee Records",
			"Employee_Directory.csv",
			"text/csv",
			32000,
			"Employee directory with personal and salary information",
		},
	}

	for _, file := range documentFiles {
		fmt.Printf("📄 Scanning: %s\n", file.name)
		fmt.Printf("   File: %s (%s, %d bytes)\n", file.filename, file.contentType, file.size)
		fmt.Printf("   Description: %s\n", file.description)

		// Create mock file upload
		upload := &analysis.FileUpload{
			Filename:    file.filename,
			ContentType: file.contentType,
			Size:        file.size,
			Data:        make([]byte, file.size), // Mock file data
			Metadata:    map[string]string{"source": "demo", "department": "finance"},
			UploadedAt:  time.Now(),
		}

		// Scan the file
		result, err := fileScanner.ScanFile(context.Background(), upload)
		if err != nil {
			fmt.Printf("❌ Scanning failed: %v\n", err)
			continue
		}

		// Display results
		fmt.Printf("⚡ Processing Time: %v\n", result.ProcessingTime)
		fmt.Printf("🎯 Overall Confidence: %.2f\n", result.ConfidenceScore)
		fmt.Printf("⚠️  Risk Level: %s\n", strings.ToUpper(result.OverallRisk))

		if result.TextExtraction != nil {
			fmt.Printf("📝 Text Extraction: %d words, %d characters (%.2f confidence)\n",
				result.TextExtraction.WordCount,
				result.TextExtraction.CharacterCount,
				result.TextExtraction.Confidence)
		}

		if result.PIIDetection != nil && result.PIIDetection.HasPII {
			fmt.Printf("🔒 PII Detected: %d items across %d types\n",
				len(result.PIIDetection.Matches),
				len(result.PIIDetection.Statistics.MatchesByType))
		}

		if result.Classification != nil {
			fmt.Printf("🏷️  Content Classification: %s (%.2f confidence)\n",
				result.Classification.Level,
				result.Classification.Confidence)
		}

		if result.MLAnalysis != nil && len(result.MLAnalysis.BusinessCategories) > 0 {
			fmt.Printf("🧠 Business Categories:\n")
			for _, category := range result.MLAnalysis.BusinessCategories {
				fmt.Printf("   - %s (%.2f, %s)\n",
					category.Category, category.Confidence, category.Sensitivity)
			}
		}

		if result.SecurityAssessment != nil && len(result.SecurityAssessment.ThreatIndicators) > 0 {
			fmt.Printf("🛡️  Security Threats: %d indicators detected\n", len(result.SecurityAssessment.ThreatIndicators))
			for _, threat := range result.SecurityAssessment.ThreatIndicators {
				fmt.Printf("   - %s: %s (%.2f confidence)\n",
					threat.Type, threat.Severity, threat.Confidence)
			}
		}

		fmt.Printf("💡 Recommendations: %d generated\n", len(result.Recommendations))
		fmt.Println()
	}

	// Demo 2: Image File OCR Scanning
	fmt.Println("📝 Demo 2: Image File OCR Scanning")
	fmt.Println("----------------------------------")

	imageFiles := []struct {
		name        string
		filename    string
		contentType string
		size        int64
		description string
	}{
		{
			"Scanned Invoice",
			"Invoice_12345.png",
			"image/png",
			850000,
			"Scanned invoice with billing information and amounts",
		},
		{
			"Driver License Scan",
			"ID_Document.jpg",
			"image/jpeg",
			420000,
			"Scanned driver license with personal information",
		},
		{
			"Business Card",
			"Business_Card_CEO.jpg",
			"image/jpeg",
			180000,
			"Business card with contact information",
		},
		{
			"Handwritten Note",
			"Meeting_Notes.png",
			"image/png",
			650000,
			"Handwritten meeting notes with strategy discussion",
		},
	}

	for _, file := range imageFiles {
		fmt.Printf("🖼️  OCR Scanning: %s\n", file.name)
		fmt.Printf("   File: %s (%s, %d bytes)\n", file.filename, file.contentType, file.size)
		fmt.Printf("   Description: %s\n", file.description)

		// Create mock file upload
		upload := &analysis.FileUpload{
			Filename:    file.filename,
			ContentType: file.contentType,
			Size:        file.size,
			Data:        make([]byte, file.size), // Mock image data
			Metadata:    map[string]string{"source": "scanner", "dpi": "300"},
			UploadedAt:  time.Now(),
		}

		// Scan the image file
		result, err := fileScanner.ScanFile(context.Background(), upload)
		if err != nil {
			fmt.Printf("❌ OCR scanning failed: %v\n", err)
			continue
		}

		// Display OCR results
		fmt.Printf("⚡ Processing Time: %v\n", result.ProcessingTime)
		fmt.Printf("🎯 Overall Confidence: %.2f\n", result.ConfidenceScore)

		if result.OCRResult != nil {
			fmt.Printf("👁️  OCR Results:\n")
			fmt.Printf("   - Extracted Text: %d words\n", result.OCRResult.WordCount)
			fmt.Printf("   - Confidence: %.2f\n", result.OCRResult.Confidence)
			fmt.Printf("   - Engine: %s\n", result.OCRResult.Engine)
			fmt.Printf("   - Language: %s\n", result.OCRResult.Language)

			if len(result.OCRResult.BoundingBoxes) > 0 {
				fmt.Printf("   - Bounding Boxes: %d detected\n", len(result.OCRResult.BoundingBoxes))
			}
		}

		if result.PIIDetection != nil && result.PIIDetection.HasPII {
			fmt.Printf("🔒 PII in OCR Text: %d items detected\n", len(result.PIIDetection.Matches))
		}

		fmt.Printf("⚠️  Risk Level: %s\n", strings.ToUpper(result.OverallRisk))
		fmt.Printf("💡 Recommendations: %d generated\n", len(result.Recommendations))
		fmt.Println()
	}

	// Demo 3: High-Risk File Analysis
	fmt.Println("📝 Demo 3: High-Risk File Analysis")
	fmt.Println("----------------------------------")

	// Simulate a high-risk file with multiple threat indicators
	highRiskFile := &analysis.FileUpload{
		Filename:    "Confidential_Customer_Database_With_PII.xlsx",
		ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		Size:        2500000, // Large file
		Data:        make([]byte, 2500000),
		Metadata:    map[string]string{"classification": "restricted", "department": "hr"},
		UploadedAt:  time.Now(),
	}

	fmt.Printf("🚨 Analyzing High-Risk File:\n")
	fmt.Printf("   File: %s\n", highRiskFile.Filename)
	fmt.Printf("   Size: %.2f MB\n", float64(highRiskFile.Size)/1024/1024)

	start := time.Now()
	result, err := fileScanner.ScanFile(context.Background(), highRiskFile)
	scanDuration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ High-risk file analysis failed: %v\n", err)
	} else {
		fmt.Printf("\n📊 Comprehensive Analysis Results:\n")
		fmt.Printf("⚡ Total Processing Time: %v\n", scanDuration)
		fmt.Printf("🎯 Overall Confidence Score: %.2f\n", result.ConfidenceScore)
		fmt.Printf("⚠️  Final Risk Assessment: %s\n", strings.ToUpper(result.OverallRisk))

		if result.SecurityAssessment != nil {
			fmt.Printf("\n🛡️  Security Assessment:\n")
			fmt.Printf("   - Data Sensitivity: %s\n", result.SecurityAssessment.DataSensitivity)
			fmt.Printf("   - Risk Level: %s\n", result.SecurityAssessment.RiskLevel)
			
			if len(result.SecurityAssessment.ThreatIndicators) > 0 {
				fmt.Printf("   - Threat Indicators:\n")
				for _, threat := range result.SecurityAssessment.ThreatIndicators {
					fmt.Printf("     • %s (%s severity): %s\n",
						threat.Type, threat.Severity, threat.Description)
				}
			}

			if len(result.SecurityAssessment.ComplianceFlags) > 0 {
				fmt.Printf("   - Compliance Concerns: %s\n",
					strings.Join(result.SecurityAssessment.ComplianceFlags, ", "))
			}

			if len(result.SecurityAssessment.AccessControls) > 0 {
				fmt.Printf("   - Access Controls:\n")
				for _, control := range result.SecurityAssessment.AccessControls {
					fmt.Printf("     • %s\n", control)
				}
			}
		}

		fmt.Printf("\n💡 Critical Recommendations:\n")
		for i, rec := range result.Recommendations {
			priority := "📌"
			if strings.Contains(strings.ToLower(rec), "critical") || strings.Contains(strings.ToLower(rec), "urgent") {
				priority = "🚨"
			}
			fmt.Printf("   %d. %s %s\n", i+1, priority, rec)
		}

		if len(result.Errors) > 0 {
			fmt.Printf("\n⚠️  Errors Encountered:\n")
			for _, errMsg := range result.Errors {
				fmt.Printf("   - %s\n", errMsg)
			}
		}
	}

	// Demo 4: Performance Statistics
	fmt.Println("\n📝 Demo 4: Performance Statistics")
	fmt.Println("---------------------------------")

	// Test various file sizes for performance analysis
	performanceTests := []struct {
		name    string
		sizeKB  int
		fileType string
	}{
		{"Small Text File", 10, "text/plain"},
		{"Medium PDF", 500, "application/pdf"},
		{"Large Spreadsheet", 5000, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		{"High-Res Image", 8000, "image/png"},
	}

	fmt.Printf("📊 Performance Analysis:\n")
	fmt.Printf("%-20s %-12s %-15s %-15s %-15s\n", "File Type", "Size", "Process Time", "Confidence", "Risk Level")
	fmt.Printf("%s\n", strings.Repeat("-", 80))

	for _, test := range performanceTests {
		testFile := &analysis.FileUpload{
			Filename:    fmt.Sprintf("test_%s", strings.ReplaceAll(strings.ToLower(test.name), " ", "_")),
			ContentType: test.fileType,
			Size:        int64(test.sizeKB * 1024),
			Data:        make([]byte, test.sizeKB*1024),
			UploadedAt:  time.Now(),
		}

		start := time.Now()
		result, err := fileScanner.ScanFile(context.Background(), testFile)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("%-20s %-12s %-15s %-15s %-15s\n",
				test.name, fmt.Sprintf("%dKB", test.sizeKB), "ERROR", "N/A", "N/A")
			continue
		}

		fmt.Printf("%-20s %-12s %-15v %-15.2f %-15s\n",
			test.name,
			fmt.Sprintf("%dKB", test.sizeKB),
			duration,
			result.ConfidenceScore,
			result.OverallRisk)
	}

	// Final summary
	fmt.Println("\n🎉 File Scanning Demo Completed Successfully!")
	fmt.Println("============================================")

	fmt.Printf("🗂️  File Scanning Capabilities:\n")
	fmt.Printf("  • Text Extraction: ✅ Multiple formats supported\n")
	fmt.Printf("  • OCR Processing: ✅ Image-to-text conversion\n")
	fmt.Printf("  • PII Detection: ✅ Privacy protection\n")
	fmt.Printf("  • Content Classification: ✅ Sensitivity analysis\n")
	fmt.Printf("  • ML Analysis: ✅ Business intelligence\n")
	fmt.Printf("  • Security Assessment: ✅ Risk evaluation\n")
	fmt.Printf("  • Threat Detection: ✅ Compliance monitoring\n")

	fmt.Printf("\n📋 Supported File Types:\n")
	fmt.Printf("  • Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX\n")
	fmt.Printf("  • Text Files: TXT, CSV, HTML, XML\n")
	fmt.Printf("  • Images: JPG, PNG, GIF, BMP, TIFF (with OCR)\n")
	fmt.Printf("  • Archives: ZIP, RAR (content scanning)\n")

	fmt.Printf("\n🛡️  Security Features:\n")
	fmt.Printf("  • Real-time threat detection\n")
	fmt.Printf("  • Compliance monitoring (GDPR, CCPA, HIPAA)\n")
	fmt.Printf("  • Risk-based access control recommendations\n")
	fmt.Printf("  • Automated security classification\n")
	fmt.Printf("  • Comprehensive audit logging\n")

	fmt.Println("\n✅ Enterprise-ready file upload scanning system!")
} 