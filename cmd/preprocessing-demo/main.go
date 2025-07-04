package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"ai-gateway-poc/internal/analysis"
)

func main() {
	fmt.Println("🔧 AI Gateway PoC - Content Preprocessing Pipeline Demo")
	fmt.Println("===========================================================")
	fmt.Println()

	// Test cases with different types of content
	testCases := []struct {
		name        string
		description string
		text        string
		profile     string
	}{
		{
			name:        "English Business Document",
			description: "Clean English business content with formatting issues",
			text:        "   The    quarterly   revenue   report   shows   significant   growth.   \n\n\n   Our   company   has   achieved   $1,250,000   in   sales   this   quarter!!!   \t\t\n   Contact   john.doe@company.com   for   more   details.   ",
			profile:     "default",
		},
		{
			name:        "Mixed Language Content",
			description: "Content with multiple languages",
			text:        "Hello world! Bonjour le monde! Hola mundo! Guten Tag Welt! The quick brown fox jumps over the lazy dog. Le renard brun rapide saute par-dessus le chien paresseux.",
			profile:     "default",
		},
		{
			name:        "Spanish Technical Document",
			description: "Spanish text with technical content",
			text:        "El sistema de inteligencia artificial utiliza algoritmos avanzados para procesar información confidencial. Los datos incluyen números de teléfono como +34-123-456-789 y correos electrónicos como usuario@empresa.es.",
			profile:     "default",
		},
		{
			name:        "French Legal Text",
			description: "French legal document with special characters",
			text:        "Conformément à la réglementation européenne, cette société doit protéger les données personnelles. Les numéros d'identification français (1-23-45-67-890-123) sont considérés comme confidentiels.",
			profile:     "default",
		},
		{
			name:        "Noisy Social Media Content",
			description: "Social media content with excessive formatting",
			text:        "OMG!!! This is AMAZING 😀!!! Check out this CRAZY deal!!! Contact us at 555-0123 or email@test.com... Use promo code: ABC123!!! #awesome #deal #amazing",
			profile:     "aggressive",
		},
		{
			name:        "German Technical Specification",
			description: "German technical content with umlauts",
			text:        "Die Softwareentwicklung für künstliche Intelligenz erfordert präzise Algorithmen. Technische Spezifikationen müssen sorgfältig überprüft werden. Kontakt: müller@technik.de",
			profile:     "default",
		},
		{
			name:        "Minimal Processing Test",
			description: "Testing minimal preprocessing options",
			text:        "  Raw   Content   with   VARIOUS   Formatting   123   and   Punctuation!!!   ",
			profile:     "minimal",
		},
		{
			name:        "Unicode and Special Characters",
			description: "Content with various Unicode characters",
			text:        "\u201cSmart quotes\u201d and \u2018fancy apostrophes\u2019 \u2014 em dashes\u2026 ellipses \u2605 symbols \u2665 hearts and émojis \U0001F31F mixed with regular text.",
			profile:     "default",
		},
	}

	// Run preprocessing demos for each test case
	for i, testCase := range testCases {
		fmt.Printf("📄 Test Case %d: %s\n", i+1, testCase.name)
		fmt.Printf("   Description: %s\n", testCase.description)
		fmt.Printf("   Profile: %s\n", testCase.profile)
		fmt.Println()

		runPreprocessingDemo(testCase.text, testCase.profile)
		
		if i < len(testCases)-1 {
			fmt.Println()
			fmt.Println(strings.Repeat("-", 60))
			fmt.Println()
		}
	}

	// Performance benchmarking
	fmt.Println()
	fmt.Println("⚡ Performance Benchmarking")
	fmt.Println("===========================")
	runPerformanceBenchmark()

	// Language detection showcase
	fmt.Println()
	fmt.Println("🌍 Language Detection Showcase")
	fmt.Println("===============================")
	runLanguageDetectionDemo()

	// Configuration examples
	fmt.Println()
	fmt.Println("⚙️ Configuration Examples")
	fmt.Println("==========================")
	demonstrateConfigurationOptions()

	fmt.Println()
	fmt.Println("✅ Preprocessing Pipeline Demo Complete!")
	fmt.Println("🎯 Key achievements:")
	fmt.Println("   • Text normalization with configurable options")
	fmt.Println("   • Multi-language detection with confidence scoring")
	fmt.Println("   • Multiple preprocessing profiles (default, aggressive, minimal)")
	fmt.Println("   • High-performance processing with detailed statistics")
	fmt.Println("   • Comprehensive Unicode and special character handling")
}

func runPreprocessingDemo(text, profileName string) {
	// Get preprocessing options based on profile
	var options analysis.PreprocessingOptions
	switch profileName {
	case "aggressive":
		options = analysis.GetAggressiveOptions()
	case "minimal":
		options = analysis.GetMinimalOptions()
	default:
		options = analysis.GetDefaultOptions()
	}

	// Create preprocessor
	processor := analysis.NewContentPreprocessor(options)

	// Process the text
	result, err := processor.Process(text)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	// Display original text (truncated if too long)
	originalDisplay := text
	if len(originalDisplay) > 100 {
		originalDisplay = originalDisplay[:97] + "..."
	}
	fmt.Printf("   📝 Original: %q\n", originalDisplay)

	// Display processed text
	processedDisplay := result.ProcessedText
	if len(processedDisplay) > 100 {
		processedDisplay = processedDisplay[:97] + "..."
	}
	fmt.Printf("   ✨ Processed: %q\n", processedDisplay)

	// Display detected languages
	if len(result.Languages) > 0 {
		fmt.Printf("   🌍 Languages detected:\n")
		for i, lang := range result.Languages {
			fmt.Printf("      %d. %s (%s) - Confidence: %.1f%%\n", 
				i+1, lang.Name, lang.Code, lang.Confidence*100)
		}
	} else {
		fmt.Printf("   🌍 No languages detected\n")
	}

	// Display statistics
	stats := result.Statistics
	fmt.Printf("   📊 Statistics:\n")
	fmt.Printf("      • Original length: %d characters\n", stats.OriginalLength)
	fmt.Printf("      • Processed length: %d characters\n", stats.ProcessedLength)
	fmt.Printf("      • Characters removed: %d\n", stats.CharactersRemoved)
	fmt.Printf("      • Compression ratio: %.2f\n", stats.CompressionRatio)
	fmt.Printf("      • Processing time: %dms\n", result.ProcessingTimeMs)
	
	if stats.PrimaryLanguage != "" {
		fmt.Printf("      • Primary language: %s (%.1f%% confidence)\n", 
			stats.PrimaryLanguage, stats.PrimaryConfidence*100)
	}
	
	if stats.HasMultipleLanguages {
		fmt.Printf("      • Multiple languages detected: Yes\n")
	}
}

func runPerformanceBenchmark() {
	// Create test content of various sizes
	sizes := []struct {
		name string
		size int
	}{
		{"Small (100 chars)", 100},
		{"Medium (1K chars)", 1000},
		{"Large (10K chars)", 10000},
		{"Extra Large (50K chars)", 50000},
	}

	options := analysis.GetDefaultOptions()
	processor := analysis.NewContentPreprocessor(options)

	for _, sizeTest := range sizes {
		// Generate test content
		testContent := generateTestContent(sizeTest.size)
		
		// Benchmark processing
		iterations := 10
		totalTime := int64(0)
		
		for i := 0; i < iterations; i++ {
			start := time.Now()
			result, err := processor.Process(testContent)
			duration := time.Since(start)
			
			if err != nil {
				fmt.Printf("❌ Error in %s: %v\n", sizeTest.name, err)
				continue
			}
			
			totalTime += duration.Milliseconds()
			
			// Only show details for first iteration
			if i == 0 {
				fmt.Printf("   📏 %s:\n", sizeTest.name)
				fmt.Printf("      • Characters processed: %d\n", len(testContent))
				fmt.Printf("      • Languages detected: %d\n", len(result.Languages))
				fmt.Printf("      • Compression ratio: %.2f\n", result.Statistics.CompressionRatio)
			}
		}
		
		avgTime := float64(totalTime) / float64(iterations)
		throughput := float64(sizeTest.size) / (avgTime / 1000) // chars per second
		
		fmt.Printf("      • Average processing time: %.1fms\n", avgTime)
		fmt.Printf("      • Throughput: %.0f chars/sec\n", throughput)
		fmt.Println()
	}
}

func runLanguageDetectionDemo() {
	languageTests := []struct {
		language string
		text     string
	}{
		{"English", "The quick brown fox jumps over the lazy dog. This is a comprehensive test of English language detection capabilities."},
		{"Spanish", "El rápido zorro marrón salta sobre el perro perezoso. Esta es una prueba integral de las capacidades de detección del idioma español."},
		{"French", "Le renard brun rapide saute par-dessus le chien paresseux. Il s'agit d'un test complet des capacités de détection de la langue française."},
		{"German", "Der schnelle braune Fuchs springt über den faulen Hund. Dies ist ein umfassender Test der deutschen Spracherkennungsfähigkeiten."},
		{"Italian", "La volpe marrone veloce salta sopra il cane pigro. Questo è un test completo delle capacità di rilevamento della lingua italiana."},
		{"Portuguese", "A raposa marrom rápida salta sobre o cão preguiçoso. Este é um teste abrangente dos recursos de detecção de idioma português."},
	}

	options := analysis.GetDefaultOptions()
	options.EnableLanguageDetection = true
	options.ConfidenceThreshold = 0.1 // Lower threshold to see more results
	processor := analysis.NewContentPreprocessor(options)

	for _, test := range languageTests {
		fmt.Printf("   🔍 Testing %s Detection:\n", test.language)
		
		result, err := processor.Process(test.text)
		if err != nil {
			fmt.Printf("      ❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("      📝 Text: %q\n", test.text[:min(len(test.text), 60)]+"...")
		
		if len(result.Languages) > 0 {
			fmt.Printf("      🎯 Detected languages:\n")
			for i, lang := range result.Languages {
				status := ""
				if i == 0 {
					status = " ✅ PRIMARY"
				}
				fmt.Printf("         %d. %s (%s) - %.1f%% confidence%s\n", 
					i+1, lang.Name, lang.Code, lang.Confidence*100, status)
			}
		} else {
			fmt.Printf("      ❌ No languages detected\n")
		}
		fmt.Println()
	}
}

func demonstrateConfigurationOptions() {
	text := "  Hello,   WORLD!!!   This   is   a   TEST   with   123   numbers   and   émojis 🌟.  "

	configurations := []struct {
		name        string
		description string
		options     analysis.PreprocessingOptions
	}{
		{
			name:        "Default Configuration",
			description: "Balanced preprocessing for general use",
			options:     analysis.GetDefaultOptions(),
		},
		{
			name:        "Aggressive Cleaning",
			description: "Maximum text cleaning and normalization",
			options:     analysis.GetAggressiveOptions(),
		},
		{
			name:        "Minimal Processing",
			description: "Preserve original text with minimal changes",
			options:     analysis.GetMinimalOptions(),
		},
		{
			name:        "Custom Configuration",
			description: "Custom settings for specific use case",
			options: analysis.PreprocessingOptions{
				NormalizeWhitespace:     true,
				RemoveControlChars:      true,
				NormalizeUnicode:        true,
				PreservePunctuation:     false,
				PreserveNumbers:         true,
				ConvertToLowercase:      true,
				RemoveExtraSpaces:       true,
				TrimWhitespace:          true,
				EnableLanguageDetection: true,
				MinTextLength:           5,
				MaxLanguages:            2,
				ConfidenceThreshold:     0.4,
				MaxProcessingTime:       3 * time.Second,
				ChunkSize:               5000,
			},
		},
	}

	for i, config := range configurations {
		fmt.Printf("   ⚙️ Configuration %d: %s\n", i+1, config.name)
		fmt.Printf("      Description: %s\n", config.description)
		
		processor := analysis.NewContentPreprocessor(config.options)
		result, err := processor.Process(text)
		if err != nil {
			fmt.Printf("      ❌ Error: %v\n", err)
			continue
		}

		fmt.Printf("      📝 Input:  %q\n", text)
		fmt.Printf("      ✨ Output: %q\n", result.ProcessedText)
		fmt.Printf("      📊 Compression: %.2f, Time: %dms\n", 
			result.Statistics.CompressionRatio, result.ProcessingTimeMs)
		
		if len(result.Languages) > 0 {
			fmt.Printf("      🌍 Languages: ")
			langNames := make([]string, len(result.Languages))
			for j, lang := range result.Languages {
				langNames[j] = fmt.Sprintf("%s(%.0f%%)", lang.Code, lang.Confidence*100)
			}
			fmt.Printf("%s\n", strings.Join(langNames, ", "))
		}
		fmt.Println()
	}
}

func generateTestContent(size int) string {
	baseText := "This is a test document with various content types. It includes numbers like 123 and 456, email addresses such as test@example.com, and different punctuation marks!!! The content is designed to test preprocessing performance with realistic text patterns. "
	
	result := ""
	for len(result) < size {
		result += baseText
	}
	
	// Truncate to exact size
	if len(result) > size {
		result = result[:size]
	}
	
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	// Set up basic error handling
	if len(os.Args) > 1 && os.Args[1] == "--help" {
		fmt.Println("AI Gateway PoC - Content Preprocessing Pipeline Demo")
		fmt.Println()
		fmt.Println("This demo showcases the text preprocessing capabilities including:")
		fmt.Println("• Text normalization (whitespace, Unicode, punctuation)")
		fmt.Println("• Language detection with confidence scoring")
		fmt.Println("• Multiple preprocessing profiles")
		fmt.Println("• Performance benchmarking")
		fmt.Println("• Configuration options")
		fmt.Println()
		fmt.Println("Usage: go run cmd/preprocessing-demo/main.go")
		os.Exit(0)
	}
} 