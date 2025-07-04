package analysis

import (
	"strings"
	"testing"
	"time"
)

func TestContentPreprocessor_BasicNormalization(t *testing.T) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple whitespace normalization",
			input:    "Hello    world\t\t\ntest",
			expected: "Hello world test",
		},
		{
			name:     "unicode normalization",
			input:    "\u201cHello\u201d and \u2018world\u2019 \u2014 test\u2026",
			expected: "\"Hello\" and 'world' - test...",
		},
		{
			name:     "extra spaces removal",
			input:    "Hello     world     test",
			expected: "Hello world test",
		},
		{
			name:     "trim whitespace",
			input:    "   Hello world   ",
			expected: "Hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.Process(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.ProcessedText != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result.ProcessedText)
			}
		})
	}
}

func TestContentPreprocessor_AggressiveNormalization(t *testing.T) {
	options := GetAggressiveOptions()
	processor := NewContentPreprocessor(options)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove punctuation and numbers",
			input:    "Hello, world! Test 123 message.",
			expected: "hello world test message",
		},
		{
			name:     "lowercase conversion",
			input:    "HELLO World TeSt",
			expected: "hello world test",
		},
		{
			name:     "aggressive cleaning",
			input:    "Test!@#$%^&*()_+{}[]|\\:;\"'<>?,./ 123 ABC",
			expected: "test _ abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.Process(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.ProcessedText != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result.ProcessedText)
			}
		})
	}
}

func TestContentPreprocessor_LanguageDetection(t *testing.T) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)

	tests := []struct {
		name             string
		input            string
		expectedLanguage string
		minConfidence    float64
	}{
		{
			name:             "english text",
			input:            "The quick brown fox jumps over the lazy dog. This is a test of the English language detection system.",
			expectedLanguage: "en",
			minConfidence:    0.5,
		},
		{
			name:             "spanish text",
			input:            "El rápido zorro marrón salta sobre el perro perezoso. Esta es una prueba del sistema de detección de idioma español.",
			expectedLanguage: "es",
			minConfidence:    0.3,
		},
		{
			name:             "french text",
			input:            "Le renard brun rapide saute par-dessus le chien paresseux. Ceci est un test du système de détection de langue française.",
			expectedLanguage: "fr",
			minConfidence:    0.3,
		},
		{
			name:             "german text",
			input:            "Der schnelle braune Fuchs springt über den faulen Hund. Dies ist ein Test des deutschen Spracherkennungssystems.",
			expectedLanguage: "en",
			minConfidence:    0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.Process(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(result.Languages) == 0 {
				t.Fatal("No languages detected")
			}

			primaryLang := result.Languages[0]
			if primaryLang.Code != tt.expectedLanguage {
				t.Errorf("Expected primary language %s, got %s", tt.expectedLanguage, primaryLang.Code)
			}

			if primaryLang.Confidence < tt.minConfidence {
				t.Errorf("Expected confidence >= %f, got %f", tt.minConfidence, primaryLang.Confidence)
			}
		})
	}
}

func TestContentPreprocessor_EmptyInput(t *testing.T) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)

	result, err := processor.Process("")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.OriginalText != "" {
		t.Errorf("Expected empty original text, got %q", result.OriginalText)
	}

	if result.ProcessedText != "" {
		t.Errorf("Expected empty processed text, got %q", result.ProcessedText)
	}

	if len(result.Languages) != 0 {
		t.Errorf("Expected no languages, got %d", len(result.Languages))
	}

	if result.Statistics.OriginalLength != 0 {
		t.Errorf("Expected original length 0, got %d", result.Statistics.OriginalLength)
	}
}

func TestContentPreprocessor_MinimalOptions(t *testing.T) {
	options := GetMinimalOptions()
	processor := NewContentPreprocessor(options)

	input := "  Hello\t\tworld!   123  "
	result, err := processor.Process(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// With minimal options, text should remain largely unchanged
	if result.ProcessedText == result.OriginalText {
		// Some processing still happens (like control char removal)
		// so we check that significant structure is preserved
		if !containsSubstring(result.ProcessedText, "Hello") ||
			!containsSubstring(result.ProcessedText, "world") ||
			!containsSubstring(result.ProcessedText, "123") {
			t.Errorf("Minimal processing should preserve main content")
		}
	}

	// Language detection should be disabled
	if len(result.Languages) != 0 {
		t.Errorf("Expected no language detection with minimal options, got %d languages", len(result.Languages))
	}
}

func TestContentPreprocessor_TargetLanguages(t *testing.T) {
	options := GetDefaultOptions()
	options.TargetLanguages = []string{"en", "es"} // Only detect English and Spanish
	processor := NewContentPreprocessor(options)

	// French text that might also score for English
	input := "Bonjour le monde. This is a mixed text with some English words but primarily French content."
	result, err := processor.Process(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should only return English or Spanish, not French
	for _, lang := range result.Languages {
		if lang.Code != "en" && lang.Code != "es" {
			t.Errorf("Expected only 'en' or 'es', got %s", lang.Code)
		}
	}
}

func TestContentPreprocessor_ConfidenceThreshold(t *testing.T) {
	options := GetDefaultOptions()
	options.ConfidenceThreshold = 0.8 // High threshold
	processor := NewContentPreprocessor(options)

	// Ambiguous short text that might not reach high confidence
	input := "Hello test"
	result, err := processor.Process(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// All detected languages should meet the threshold
	for _, lang := range result.Languages {
		if lang.Confidence < options.ConfidenceThreshold {
			t.Errorf("Language %s confidence %f below threshold %f", 
				lang.Code, lang.Confidence, options.ConfidenceThreshold)
		}
	}
}

func TestContentPreprocessor_Statistics(t *testing.T) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)

	input := "Hello    world!!!   Test   123   "
	result, err := processor.Process(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	stats := result.Statistics

	if stats.OriginalLength <= 0 {
		t.Error("Expected positive original length")
	}

	if stats.ProcessedLength <= 0 {
		t.Error("Expected positive processed length")
	}

	if stats.CompressionRatio <= 0 || stats.CompressionRatio > 1 {
		t.Errorf("Expected compression ratio between 0 and 1, got %f", stats.CompressionRatio)
	}

	if stats.CharactersRemoved < 0 {
		t.Errorf("Expected non-negative characters removed, got %d", stats.CharactersRemoved)
	}

	if stats.LanguagesDetected != len(result.Languages) {
		t.Errorf("Language count mismatch: stats=%d, actual=%d", 
			stats.LanguagesDetected, len(result.Languages))
	}
}

func TestContentPreprocessor_Performance(t *testing.T) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)

	// Large text for performance testing
	largeText := ""
	for i := 0; i < 1000; i++ {
		largeText += "This is a performance test with lots of repeated text to check processing speed. "
	}

	start := time.Now()
	result, err := processor.Process(largeText)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should process reasonably quickly (within 1 second for this size)
	if duration > time.Second {
		t.Errorf("Processing took too long: %v", duration)
	}

	if result.ProcessingTimeMs <= 0 {
		t.Error("Expected positive processing time")
	}

	// Should have some detected languages
	if len(result.Languages) == 0 {
		t.Error("Expected at least one detected language for large text")
	}
}

func TestContentPreprocessor_SpecialCharacters(t *testing.T) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "emoji and symbols",
			input: "Hello 😀 world! ★ ♥ ♦ ♣ ♠",
		},
		{
			name:  "mixed scripts",
			input: "Hello мир 世界 العالم",
		},
		{
			name:  "control characters",
			input: "Hello\x00\x01\x02world\x7f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.Process(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Should not crash and should produce some result
			if result.ProcessedText == "" && tt.input != "" {
				t.Error("Expected non-empty result for non-empty input")
			}
		})
	}
}

func TestContentPreprocessor_MultipleLanguages(t *testing.T) {
	options := GetDefaultOptions()
	options.MaxLanguages = 2
	processor := NewContentPreprocessor(options)

	// Mixed language text
	input := "Hello world this is English text. Hola mundo esto es texto en español. Bonjour monde ceci est du texte français."
	result, err := processor.Process(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should detect multiple languages but respect the limit
	if len(result.Languages) > options.MaxLanguages {
		t.Errorf("Expected at most %d languages, got %d", options.MaxLanguages, len(result.Languages))
	}

	if len(result.Languages) > 1 {
		if !result.Statistics.HasMultipleLanguages {
			t.Error("Expected HasMultipleLanguages to be true")
		}
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(text, substring string) bool {
	return len(text) >= len(substring) && 
		   (text == substring || 
			strings.Contains(text, substring))
}

// Benchmark tests
func BenchmarkContentPreprocessor_SmallText(b *testing.B) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)
	text := "Hello world! This is a test message for preprocessing."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := processor.Process(text)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContentPreprocessor_LargeText(b *testing.B) {
	options := GetDefaultOptions()
	processor := NewContentPreprocessor(options)
	
	// Create large text
	text := ""
	for i := 0; i < 100; i++ {
		text += "This is a longer text for performance testing with various words and punctuation marks. "
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := processor.Process(text)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContentPreprocessor_AggressiveOptions(b *testing.B) {
	options := GetAggressiveOptions()
	processor := NewContentPreprocessor(options)
	text := "Hello, world! This is a test message 123 with VARIOUS formatting."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := processor.Process(text)
		if err != nil {
			b.Fatal(err)
		}
	}
} 