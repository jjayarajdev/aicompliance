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
	fmt.Println("🚀 AI Gateway - PII Detection Engine Demo")
	fmt.Println("==========================================")

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

	// Create PII detector configuration
	piiConfig := &analysis.PIIDetectorConfig{
		Enabled:          cfg.PIIDetection.Enabled,
		SensitivityLevel: cfg.PIIDetection.SensitivityLevel,
		RedactionMode:    cfg.PIIDetection.RedactionMode,
		CustomPatterns:   cfg.PIIDetection.CustomPatterns,
		ExcludePatterns:  cfg.PIIDetection.ExcludePatterns,
		MaxTextSize:      cfg.PIIDetection.MaxTextSize,
	}

	// Create PII detector
	detector, err := analysis.NewPIIDetector(piiConfig, logger)
	if err != nil {
		fmt.Printf("❌ Failed to create PII detector: %v\n", err)
		return
	}

	fmt.Println("✅ PII detection engine initialized successfully")
	fmt.Println()

	// Demo 1: Basic PII Detection
	fmt.Println("📝 Demo 1: Basic PII Detection")
	fmt.Println("------------------------------")

	testCases := []struct {
		name string
		text string
	}{
		{"SSN Detection", "My Social Security Number is 123-45-6789"},
		{"Credit Card", "Pay with card 4111-1111-1111-1111"},
		{"Phone Number", "Call me at (555) 123-4567"},
		{"Email Address", "Contact john.doe@company.com"},
		{"Multiple PII", "John Doe, SSN: 987-65-4321, Email: john@example.com, Phone: 555-987-6543"},
	}

	for _, tc := range testCases {
		fmt.Printf("🔍 %s:\n", tc.name)
		fmt.Printf("Original: %s\n", tc.text)

		result, err := detector.DetectPII(context.Background(), tc.text)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("Has PII: %t\n", result.HasPII)
		fmt.Printf("Matches: %d\n", len(result.Matches))
		if result.HasPII {
			fmt.Printf("Redacted: %s\n", result.Text)
			for _, match := range result.Matches {
				fmt.Printf("  - %s: %s (confidence: %.2f)\n", 
					match.Type, match.Value, match.Confidence)
			}
		}
		fmt.Println()
	}

	// Demo 2: Different Redaction Modes
	fmt.Println("📝 Demo 2: Redaction Modes")
	fmt.Println("--------------------------")

	testText := "Contact info: john.doe@company.com, Phone: (555) 123-4567, SSN: 123-45-6789"
	modes := []string{"mask", "remove", "hash"}

	for _, mode := range modes {
		fmt.Printf("🔧 Redaction Mode: %s\n", mode)
		
		// Update detector config
		piiConfig.RedactionMode = mode
		detector.UpdateConfig(piiConfig)

		result, err := detector.DetectPII(context.Background(), testText)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("Original: %s\n", testText)
		fmt.Printf("Redacted: %s\n", result.Text)
		fmt.Println()
	}

	// Demo 3: Custom Patterns
	fmt.Println("📝 Demo 3: Custom Patterns")
	fmt.Println("---------------------------")

	// Add custom patterns
	detector.AddCustomPattern("employee_id", `\bEMP\d{6}\b`)
	detector.AddCustomPattern("product_key", `\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`)

	customText := "Employee EMP123456 has product key ABCDE-12345-FGHIJ and email test@company.com"
	fmt.Printf("Text with custom PII: %s\n", customText)

	result, err := detector.DetectPII(context.Background(), customText)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
	} else {
		fmt.Printf("Detected %d PII items:\n", len(result.Matches))
		for _, match := range result.Matches {
			fmt.Printf("  - %s: %s\n", match.Type, match.Value)
		}
		fmt.Printf("Redacted: %s\n", result.Text)
	}
	fmt.Println()

	// Demo 4: Sensitivity Levels
	fmt.Println("📝 Demo 4: Sensitivity Levels")
	fmt.Println("------------------------------")

	sensitivityText := "Contact: user@example.org"
	levels := []string{"low", "medium", "high"}

	for _, level := range levels {
		fmt.Printf("🎚️  Sensitivity Level: %s\n", level)
		
		piiConfig.SensitivityLevel = level
		detector.UpdateConfig(piiConfig)

		result, err := detector.DetectPII(context.Background(), sensitivityText)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			continue
		}

		if result.HasPII {
			fmt.Printf("Confidence: %.2f\n", result.Matches[0].Confidence)
		} else {
			fmt.Printf("No PII detected\n")
		}
	}
	fmt.Println()

	// Demo 5: Complex Document Analysis
	fmt.Println("📝 Demo 5: Complex Document Analysis")
	fmt.Println("------------------------------------")

	complexDoc := `
CONFIDENTIAL EMPLOYEE RECORD

Personal Information:
Name: Sarah Johnson
Employee ID: EMP234567
Email: sarah.johnson@techcorp.com
Phone: (555) 987-6543
Emergency Contact: (555) 123-9876

Financial Details:
Social Security: 987-65-4321
Bank Account: 1234567890123456
Credit Card: 4532-1234-5678-9012
Salary: $85,000

Address:
123 Main Street
Anytown, CA 90210
IP Address: 192.168.1.100

Date of Birth: 03/15/1990
Driver's License: D1234567
`

	fmt.Printf("📄 Analyzing complex document (%d characters)...\n", len(complexDoc))
	
	// Reset to mask mode for final demo
	piiConfig.RedactionMode = "mask"
	detector.UpdateConfig(piiConfig)

	start := time.Now()
	result, err := detector.DetectPII(context.Background(), complexDoc)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	fmt.Printf("⚡ Analysis completed in %v\n", duration)
	fmt.Printf("📊 Results:\n")
	fmt.Printf("  - PII Detected: %t\n", result.HasPII)
	fmt.Printf("  - Total Matches: %d\n", result.Statistics.TotalMatches)
	fmt.Printf("  - Average Confidence: %.2f\n", result.Statistics.ConfidenceAvg)
	fmt.Printf("  - Text Length: %d → %d characters\n", 
		result.Statistics.TextLength, result.Statistics.RedactedLength)

	fmt.Printf("\n🏷️  PII Types Found:\n")
	for piiType, count := range result.Statistics.MatchesByType {
		fmt.Printf("  - %s: %d\n", piiType, count)
	}

	fmt.Printf("\n🔍 Detailed Matches:\n")
	for i, match := range result.Matches {
		fmt.Printf("  %d. %s: %s → %s (confidence: %.2f)\n", 
			i+1, match.Type, match.Value, match.Redacted, match.Confidence)
		if match.Context != "" {
			fmt.Printf("     Context: %s\n", match.Context)
		}
	}

	fmt.Printf("\n📝 Redacted Document:\n")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println(result.Text)
	fmt.Println(strings.Repeat("-", 50))

	// Demo 6: Performance Test
	fmt.Println("\n📝 Demo 6: Performance Test")
	fmt.Println("----------------------------")

	// Generate large text with PII
	largeText := ""
	for i := 0; i < 100; i++ {
		largeText += fmt.Sprintf("User %d: email%d@company.com, phone: 555-%03d-%04d, SSN: %03d-%02d-%04d. ", 
			i, i, i%1000, 1000+i, i%1000, i%100, 1000+i)
	}

	fmt.Printf("📏 Testing with large document (%d characters, ~300 PII items)...\n", len(largeText))
	
	start = time.Now()
	result, err = detector.DetectPII(context.Background(), largeText)
	duration = time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
	} else {
		fmt.Printf("⚡ Performance Results:\n")
		fmt.Printf("  - Processing Time: %v\n", duration)
		fmt.Printf("  - Throughput: %.2f chars/ms\n", float64(len(largeText))/float64(duration.Milliseconds()))
		fmt.Printf("  - PII Items Found: %d\n", len(result.Matches))
		fmt.Printf("  - Detection Rate: %.2f items/second\n", 
			float64(len(result.Matches))/duration.Seconds())
	}

	// Final summary
	fmt.Println("\n🎉 PII Detection Demo Completed Successfully!")
	fmt.Println("=============================================")
	
	supportedTypes := detector.GetSupportedTypes()
	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  - Supported PII Types: %d\n", len(supportedTypes))
	fmt.Printf("  - Custom Patterns: %d\n", len(piiConfig.CustomPatterns))
	fmt.Printf("  - Redaction Modes: mask, remove, hash\n")
	fmt.Printf("  - Sensitivity Levels: low, medium, high\n")
	fmt.Printf("  - Max Text Size: %d bytes\n", piiConfig.MaxTextSize)
	
	fmt.Printf("\n🔧 Supported PII Types:\n")
	for i, piiType := range supportedTypes {
		fmt.Printf("  %d. %s\n", i+1, piiType)
	}

	fmt.Println("\n✅ Ready for production use!")
} 