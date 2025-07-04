package analysis

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
	"time"
)

// Language represents a detected language
type Language struct {
	Code       string  `json:"code"`       // ISO 639-1 language code (e.g., "en", "es", "fr")
	Name       string  `json:"name"`       // Human-readable language name
	Confidence float64 `json:"confidence"` // Confidence score (0.0-1.0)
}

// PreprocessingOptions configures the preprocessing pipeline
type PreprocessingOptions struct {
	// Text normalization options
	NormalizeWhitespace    bool `json:"normalize_whitespace"`     // Normalize spaces, tabs, newlines
	RemoveControlChars     bool `json:"remove_control_chars"`     // Remove control characters
	NormalizeUnicode       bool `json:"normalize_unicode"`        // Normalize Unicode characters
	PreservePunctuation    bool `json:"preserve_punctuation"`     // Keep punctuation marks
	PreserveNumbers        bool `json:"preserve_numbers"`         // Keep numeric content
	ConvertToLowercase     bool `json:"convert_to_lowercase"`     // Convert to lowercase
	RemoveExtraSpaces      bool `json:"remove_extra_spaces"`      // Remove multiple consecutive spaces
	TrimWhitespace         bool `json:"trim_whitespace"`          // Trim leading/trailing whitespace
	
	// Language detection options
	EnableLanguageDetection bool     `json:"enable_language_detection"` // Enable language detection
	MinTextLength          int      `json:"min_text_length"`            // Minimum text length for language detection
	MaxLanguages           int      `json:"max_languages"`              // Maximum languages to detect
	ConfidenceThreshold    float64  `json:"confidence_threshold"`       // Minimum confidence for language detection
	TargetLanguages        []string `json:"target_languages"`           // Specific languages to detect (empty = all)
	
	// Performance options
	MaxProcessingTime time.Duration `json:"max_processing_time"` // Maximum time to spend preprocessing
	ChunkSize         int           `json:"chunk_size"`          // Size of text chunks for processing
}

// PreprocessingResult contains the results of text preprocessing
type PreprocessingResult struct {
	OriginalText     string     `json:"original_text"`
	ProcessedText    string     `json:"processed_text"`
	Languages        []Language `json:"languages"`
	ProcessingTimeMs int64      `json:"processing_time_ms"`
	Statistics       PreprocessingStats `json:"statistics"`
}

// PreprocessingStats provides detailed statistics about the preprocessing
type PreprocessingStats struct {
	OriginalLength      int     `json:"original_length"`
	ProcessedLength     int     `json:"processed_length"`
	CharactersRemoved   int     `json:"characters_removed"`
	CompressionRatio    float64 `json:"compression_ratio"`
	LanguagesDetected   int     `json:"languages_detected"`
	PrimaryLanguage     string  `json:"primary_language"`
	PrimaryConfidence   float64 `json:"primary_confidence"`
	HasMultipleLanguages bool   `json:"has_multiple_languages"`
}

// ContentPreprocessor handles text normalization and language detection
type ContentPreprocessor struct {
	options       PreprocessingOptions
	languageMap   map[string]string
	stopWords     map[string][]string
	commonPatterns map[string]*regexp.Regexp
}

// NewContentPreprocessor creates a new content preprocessor with the given options
func NewContentPreprocessor(options PreprocessingOptions) *ContentPreprocessor {
	processor := &ContentPreprocessor{
		options:     options,
		languageMap: getLanguageMap(),
		stopWords:   getStopWords(),
		commonPatterns: make(map[string]*regexp.Regexp),
	}
	
	// Compile common regex patterns for performance
	processor.compilePatterns()
	
	return processor
}

// Process performs text preprocessing including normalization and language detection
func (cp *ContentPreprocessor) Process(text string) (*PreprocessingResult, error) {
	startTime := time.Now()
	
	if text == "" {
		return &PreprocessingResult{
			OriginalText:  "",
			ProcessedText: "",
			Languages:     []Language{},
			Statistics: PreprocessingStats{
				OriginalLength:    0,
				ProcessedLength:   0,
				CharactersRemoved: 0,
				CompressionRatio:  1.0,
			},
		}, nil
	}
	
	originalText := text
	processedText := text
	
	// Apply text normalization steps
	if cp.options.NormalizeWhitespace {
		processedText = cp.normalizeWhitespace(processedText)
	}
	
	if cp.options.RemoveControlChars {
		processedText = cp.removeControlCharacters(processedText)
	}
	
	if cp.options.NormalizeUnicode {
		processedText = cp.normalizeUnicode(processedText)
	}
	
	if !cp.options.PreservePunctuation {
		processedText = cp.removePunctuation(processedText)
	}
	
	if !cp.options.PreserveNumbers {
		processedText = cp.removeNumbers(processedText)
	}
	
	if cp.options.ConvertToLowercase {
		processedText = strings.ToLower(processedText)
	}
	
	if cp.options.RemoveExtraSpaces {
		processedText = cp.removeExtraSpaces(processedText)
	}
	
	if cp.options.TrimWhitespace {
		processedText = strings.TrimSpace(processedText)
	}
	
	// Detect languages
	var languages []Language
	if cp.options.EnableLanguageDetection && len(processedText) >= cp.options.MinTextLength {
		languages = cp.detectLanguages(processedText)
	}
	
	// Calculate statistics
	stats := cp.calculateStatistics(originalText, processedText, languages)
	
	processingTime := time.Since(startTime)
	
	return &PreprocessingResult{
		OriginalText:     originalText,
		ProcessedText:    processedText,
		Languages:        languages,
		ProcessingTimeMs: processingTime.Milliseconds(),
		Statistics:       stats,
	}, nil
}

// normalizeWhitespace standardizes whitespace characters
func (cp *ContentPreprocessor) normalizeWhitespace(text string) string {
	// Replace various whitespace characters with standard space
	pattern := cp.commonPatterns["whitespace"]
	normalized := pattern.ReplaceAllString(text, " ")
	
	// Replace multiple newlines with single newline
	pattern = cp.commonPatterns["multiple_newlines"]
	normalized = pattern.ReplaceAllString(normalized, "\n")
	
	return normalized
}

// removeControlCharacters removes control characters except tabs and newlines
func (cp *ContentPreprocessor) removeControlCharacters(text string) string {
	var result strings.Builder
	for _, r := range text {
		if !unicode.IsControl(r) || r == '\t' || r == '\n' || r == '\r' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// normalizeUnicode performs Unicode normalization
func (cp *ContentPreprocessor) normalizeUnicode(text string) string {
	// Simple approach: remove combining characters and normalize common replacements
	var result strings.Builder
	
	for _, r := range text {
		// Skip combining characters
		if unicode.In(r, unicode.Mn, unicode.Me, unicode.Mc) {
			continue
		}
		
		// Normalize common characters
		switch r {
		case '\u201c', '\u201d', '\u0022': // Smart quotes to regular quotes
			result.WriteRune('"')
		case '\u2018', '\u2019': // Smart apostrophes to regular apostrophe
			result.WriteRune('\'')
		case '\u2013', '\u2014': // En dash, em dash to hyphen
			result.WriteRune('-')
		case '\u2026': // Ellipsis to three dots
			result.WriteString("...")
		default:
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// removePunctuation removes punctuation characters
func (cp *ContentPreprocessor) removePunctuation(text string) string {
	pattern := cp.commonPatterns["punctuation"]
	return pattern.ReplaceAllString(text, " ")
}

// removeNumbers removes numeric content
func (cp *ContentPreprocessor) removeNumbers(text string) string {
	pattern := cp.commonPatterns["numbers"]
	return pattern.ReplaceAllString(text, " ")
}

// removeExtraSpaces removes multiple consecutive spaces
func (cp *ContentPreprocessor) removeExtraSpaces(text string) string {
	pattern := cp.commonPatterns["extra_spaces"]
	return pattern.ReplaceAllString(text, " ")
}

// detectLanguages performs language detection on the text
func (cp *ContentPreprocessor) detectLanguages(text string) []Language {
	// This is a mock implementation - in production you'd use a proper language detection library
	// like github.com/pemistahl/lingua-go or similar
	
	languages := []Language{}
	
	// Simple heuristic-based language detection
	detectedLangs := cp.simpleLanguageDetection(text)
	
	// Filter by target languages if specified
	if len(cp.options.TargetLanguages) > 0 {
		filteredLangs := []Language{}
		for _, lang := range detectedLangs {
			for _, target := range cp.options.TargetLanguages {
				if lang.Code == target {
					filteredLangs = append(filteredLangs, lang)
					break
				}
			}
		}
		detectedLangs = filteredLangs
	}
	
	// Filter by confidence threshold
	for _, lang := range detectedLangs {
		if lang.Confidence >= cp.options.ConfidenceThreshold {
			languages = append(languages, lang)
		}
	}
	
	// Limit number of languages
	if len(languages) > cp.options.MaxLanguages {
		languages = languages[:cp.options.MaxLanguages]
	}
	
	return languages
}

// simpleLanguageDetection performs basic language detection using character frequency analysis
func (cp *ContentPreprocessor) simpleLanguageDetection(text string) []Language {
	// Character frequency analysis for common languages
	charFreq := make(map[rune]int)
	totalChars := 0
	
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) {
			charFreq[r]++
			totalChars++
		}
	}
	
	if totalChars == 0 {
		return []Language{}
	}
	
	// Language scoring based on character frequencies and common words
	languageScores := map[string]float64{
		"en": cp.scoreEnglish(text, charFreq, totalChars),
		"es": cp.scoreSpanish(text, charFreq, totalChars),
		"fr": cp.scoreFrench(text, charFreq, totalChars),
		"de": cp.scoreGerman(text, charFreq, totalChars),
		"it": cp.scoreItalian(text, charFreq, totalChars),
		"pt": cp.scorePortuguese(text, charFreq, totalChars),
	}
	
	// Convert scores to languages
	var languages []Language
	for code, score := range languageScores {
		if score > 0.1 { // Minimum threshold
			languages = append(languages, Language{
				Code:       code,
				Name:       cp.languageMap[code],
				Confidence: score,
			})
		}
	}
	
	// Sort by confidence (highest first)
	for i := 0; i < len(languages)-1; i++ {
		for j := i + 1; j < len(languages); j++ {
			if languages[j].Confidence > languages[i].Confidence {
				languages[i], languages[j] = languages[j], languages[i]
			}
		}
	}
	
	return languages
}

// scoreEnglish calculates English language score
func (cp *ContentPreprocessor) scoreEnglish(text string, charFreq map[rune]int, totalChars int) float64 {
	score := 0.0
	
	// Common English letter frequencies
	englishFreq := map[rune]float64{
		'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
		's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
	}
	
	for char, expectedFreq := range englishFreq {
		actualFreq := float64(charFreq[char]) / float64(totalChars) * 100
		diff := expectedFreq - actualFreq
		if diff < 0 {
			diff = -diff
		}
		score += (10 - diff) / 10 // Higher score for closer match
	}
	
	// Check for common English words
	words := strings.Fields(strings.ToLower(text))
	englishWords := []string{"the", "and", "of", "to", "a", "in", "is", "it", "you", "that"}
	englishWordCount := 0
	for _, word := range words {
		for _, englishWord := range englishWords {
			if word == englishWord {
				englishWordCount++
				break
			}
		}
	}
	
	if len(words) > 0 {
		score += float64(englishWordCount) / float64(len(words)) * 10
	}
	
	return score / 20 // Normalize to 0-1
}

// scoreSpanish calculates Spanish language score
func (cp *ContentPreprocessor) scoreSpanish(text string, charFreq map[rune]int, totalChars int) float64 {
	score := 0.0
	
	// Look for Spanish-specific characters
	spanishChars := []rune{'ñ', 'á', 'é', 'í', 'ó', 'ú', 'ü'}
	for _, char := range spanishChars {
		if charFreq[char] > 0 {
			score += 0.2
		}
	}
	
	// Check for common Spanish words
	words := strings.Fields(strings.ToLower(text))
	spanishWords := []string{"el", "la", "de", "que", "y", "en", "un", "es", "se", "no"}
	spanishWordCount := 0
	for _, word := range words {
		for _, spanishWord := range spanishWords {
			if word == spanishWord {
				spanishWordCount++
				break
			}
		}
	}
	
	if len(words) > 0 {
		score += float64(spanishWordCount) / float64(len(words))
	}
	
	return score
}

// scoreFrench calculates French language score
func (cp *ContentPreprocessor) scoreFrench(text string, charFreq map[rune]int, totalChars int) float64 {
	score := 0.0
	
	// Look for French-specific characters
	frenchChars := []rune{'à', 'â', 'ä', 'ç', 'é', 'è', 'ê', 'ë', 'î', 'ï', 'ô', 'ù', 'û', 'ü', 'ÿ'}
	for _, char := range frenchChars {
		if charFreq[char] > 0 {
			score += 0.1
		}
	}
	
	// Check for common French words
	words := strings.Fields(strings.ToLower(text))
	frenchWords := []string{"le", "de", "et", "à", "un", "il", "être", "et", "en", "avoir"}
	frenchWordCount := 0
	for _, word := range words {
		for _, frenchWord := range frenchWords {
			if word == frenchWord {
				frenchWordCount++
				break
			}
		}
	}
	
	if len(words) > 0 {
		score += float64(frenchWordCount) / float64(len(words))
	}
	
	return score
}

// scoreGerman calculates German language score
func (cp *ContentPreprocessor) scoreGerman(text string, charFreq map[rune]int, totalChars int) float64 {
	score := 0.0
	
	// Look for German-specific characters
	germanChars := []rune{'ä', 'ö', 'ü', 'ß'}
	for _, char := range germanChars {
		if charFreq[char] > 0 {
			score += 0.2
		}
	}
	
	// Check for common German words
	words := strings.Fields(strings.ToLower(text))
	germanWords := []string{"der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich"}
	germanWordCount := 0
	for _, word := range words {
		for _, germanWord := range germanWords {
			if word == germanWord {
				germanWordCount++
				break
			}
		}
	}
	
	if len(words) > 0 {
		score += float64(germanWordCount) / float64(len(words))
	}
	
	return score
}

// scoreItalian calculates Italian language score
func (cp *ContentPreprocessor) scoreItalian(text string, charFreq map[rune]int, totalChars int) float64 {
	score := 0.0
	
	// Look for Italian-specific characters
	italianChars := []rune{'à', 'è', 'é', 'ì', 'í', 'î', 'ò', 'ó', 'ù', 'ú'}
	for _, char := range italianChars {
		if charFreq[char] > 0 {
			score += 0.1
		}
	}
	
	// Check for common Italian words
	words := strings.Fields(strings.ToLower(text))
	italianWords := []string{"il", "di", "che", "e", "la", "per", "un", "in", "con", "non"}
	italianWordCount := 0
	for _, word := range words {
		for _, italianWord := range italianWords {
			if word == italianWord {
				italianWordCount++
				break
			}
		}
	}
	
	if len(words) > 0 {
		score += float64(italianWordCount) / float64(len(words))
	}
	
	return score
}

// scorePortuguese calculates Portuguese language score
func (cp *ContentPreprocessor) scorePortuguese(text string, charFreq map[rune]int, totalChars int) float64 {
	score := 0.0
	
	// Look for Portuguese-specific characters
	portugueseChars := []rune{'ã', 'á', 'â', 'à', 'ç', 'é', 'ê', 'í', 'ó', 'ô', 'õ', 'ú'}
	for _, char := range portugueseChars {
		if charFreq[char] > 0 {
			score += 0.1
		}
	}
	
	// Check for common Portuguese words
	words := strings.Fields(strings.ToLower(text))
	portugueseWords := []string{"o", "de", "que", "e", "do", "da", "em", "um", "para", "é"}
	portugueseWordCount := 0
	for _, word := range words {
		for _, portugueseWord := range portugueseWords {
			if word == portugueseWord {
				portugueseWordCount++
				break
			}
		}
	}
	
	if len(words) > 0 {
		score += float64(portugueseWordCount) / float64(len(words))
	}
	
	return score
}

// calculateStatistics computes detailed preprocessing statistics
func (cp *ContentPreprocessor) calculateStatistics(original, processed string, languages []Language) PreprocessingStats {
	originalLen := utf8.RuneCountInString(original)
	processedLen := utf8.RuneCountInString(processed)
	removedChars := originalLen - processedLen
	
	compressionRatio := 1.0
	if originalLen > 0 {
		compressionRatio = float64(processedLen) / float64(originalLen)
	}
	
	primaryLang := ""
	primaryConf := 0.0
	if len(languages) > 0 {
		primaryLang = languages[0].Code
		primaryConf = languages[0].Confidence
	}
	
	return PreprocessingStats{
		OriginalLength:       originalLen,
		ProcessedLength:      processedLen,
		CharactersRemoved:    removedChars,
		CompressionRatio:     compressionRatio,
		LanguagesDetected:    len(languages),
		PrimaryLanguage:      primaryLang,
		PrimaryConfidence:    primaryConf,
		HasMultipleLanguages: len(languages) > 1,
	}
}

// compilePatterns compiles regex patterns for performance
func (cp *ContentPreprocessor) compilePatterns() {
	cp.commonPatterns["whitespace"] = regexp.MustCompile(`[\t\r\f\v]+`)
	cp.commonPatterns["multiple_newlines"] = regexp.MustCompile(`\n\s*\n\s*\n+`)
	cp.commonPatterns["punctuation"] = regexp.MustCompile(`[^\w\s]`)
	cp.commonPatterns["numbers"] = regexp.MustCompile(`\d+`)
	cp.commonPatterns["extra_spaces"] = regexp.MustCompile(`\s+`)
}

// getLanguageMap returns a mapping of language codes to names
func getLanguageMap() map[string]string {
	return map[string]string{
		"en": "English",
		"es": "Spanish",
		"fr": "French",
		"de": "German",
		"it": "Italian",
		"pt": "Portuguese",
		"nl": "Dutch",
		"sv": "Swedish",
		"da": "Danish",
		"no": "Norwegian",
		"fi": "Finnish",
		"ru": "Russian",
		"zh": "Chinese",
		"ja": "Japanese",
		"ko": "Korean",
		"ar": "Arabic",
		"hi": "Hindi",
	}
}

// getStopWords returns stop words for various languages
func getStopWords() map[string][]string {
	return map[string][]string{
		"en": {"the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "from", "up", "about", "into", "through", "during", "before", "after", "above", "below", "out", "off", "down", "under", "again", "further", "then", "once"},
		"es": {"el", "la", "de", "que", "y", "a", "en", "un", "ser", "se", "no", "te", "lo", "le", "da", "su", "por", "son", "con", "para", "mi", "está", "si", "pero", "o"},
		"fr": {"le", "de", "et", "à", "un", "il", "être", "et", "en", "avoir", "que", "pour", "dans", "ce", "son", "une", "sur", "avec", "ne", "se", "pas", "tout", "plus", "par"},
		"de": {"der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich", "des", "auf", "für", "ist", "im", "dem", "nicht", "ein", "eine", "als", "auch", "es", "an", "werden"},
		"it": {"il", "di", "che", "e", "la", "per", "un", "in", "con", "non", "a", "da", "su", "del", "le", "al", "si", "come", "più", "o", "ma", "se", "ci", "io"},
		"pt": {"o", "de", "que", "e", "do", "da", "em", "um", "para", "é", "com", "não", "uma", "os", "no", "se", "na", "por", "mais", "as", "dos", "como", "mas", "foi"},
	}
}

// GetDefaultOptions returns default preprocessing options
func GetDefaultOptions() PreprocessingOptions {
	return PreprocessingOptions{
		// Text normalization
		NormalizeWhitespace:    true,
		RemoveControlChars:     true,
		NormalizeUnicode:       true,
		PreservePunctuation:    true,
		PreserveNumbers:        true,
		ConvertToLowercase:     false,
		RemoveExtraSpaces:      true,
		TrimWhitespace:         true,
		
		// Language detection
		EnableLanguageDetection: true,
		MinTextLength:          10,
		MaxLanguages:           3,
		ConfidenceThreshold:    0.3,
		TargetLanguages:        []string{}, // All languages
		
		// Performance
		MaxProcessingTime: 5 * time.Second,
		ChunkSize:         10000,
	}
}

// GetAggressiveOptions returns options for aggressive text cleaning
func GetAggressiveOptions() PreprocessingOptions {
	options := GetDefaultOptions()
	options.RemoveControlChars = true
	options.PreservePunctuation = false
	options.PreserveNumbers = false
	options.ConvertToLowercase = true
	options.ConfidenceThreshold = 0.5
	return options
}

// GetMinimalOptions returns options for minimal preprocessing
func GetMinimalOptions() PreprocessingOptions {
	options := GetDefaultOptions()
	options.NormalizeWhitespace = false
	options.NormalizeUnicode = false
	options.RemoveExtraSpaces = false
	options.EnableLanguageDetection = false
	return options
} 