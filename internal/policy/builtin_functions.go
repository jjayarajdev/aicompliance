package policy

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// initializeBuiltinFunctions initializes all built-in functions
func (ace *AdvancedConditionEvaluator) initializeBuiltinFunctions() {
	ace.mu.Lock()
	defer ace.mu.Unlock()

	// String functions
	ace.functionRegistry["length"] = BuiltinFunction{
		Name:        "length",
		Description: "Returns the length of a string",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.stringLengthFunc,
		Examples: []FunctionExample{
			{
				Description: "Get string length",
				Input:       map[string]interface{}{"text": "hello world"},
				Expression:  "length($text)",
				Expected:    11,
			},
		},
	}

	ace.functionRegistry["upper"] = BuiltinFunction{
		Name:        "upper",
		Description: "Converts string to uppercase",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "string",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.stringUpperFunc,
		Examples: []FunctionExample{
			{
				Description: "Convert to uppercase",
				Input:       map[string]interface{}{"text": "hello"},
				Expression:  "upper($text)",
				Expected:    "HELLO",
			},
		},
	}

	ace.functionRegistry["lower"] = BuiltinFunction{
		Name:        "lower",
		Description: "Converts string to lowercase",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "string",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.stringLowerFunc,
		Examples: []FunctionExample{
			{
				Description: "Convert to lowercase",
				Input:       map[string]interface{}{"text": "HELLO"},
				Expression:  "lower($text)",
				Expected:    "hello",
			},
		},
	}

	ace.functionRegistry["trim"] = BuiltinFunction{
		Name:        "trim",
		Description: "Trims whitespace from string",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "string",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.stringTrimFunc,
		Examples: []FunctionExample{
			{
				Description: "Trim whitespace",
				Input:       map[string]interface{}{"text": "  hello  "},
				Expression:  "trim($text)",
				Expected:    "hello",
			},
		},
	}

	ace.functionRegistry["contains"] = BuiltinFunction{
		Name:        "contains",
		Description: "Check if string contains substring",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
			{Name: "substring", Type: "string", Required: true, Description: "Substring to find"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n*m) operation",
		Implementation:  ace.stringContainsFunc,
		Examples: []FunctionExample{
			{
				Description: "Check if text contains substring",
				Input:       map[string]interface{}{"text": "hello world", "substring": "world"},
				Expression:  "contains($text, $substring)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["starts_with"] = BuiltinFunction{
		Name:        "starts_with",
		Description: "Check if string starts with prefix",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
			{Name: "prefix", Type: "string", Required: true, Description: "Prefix to check"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(m) operation",
		Implementation:  ace.stringStartsWithFunc,
		Examples: []FunctionExample{
			{
				Description: "Check if text starts with prefix",
				Input:       map[string]interface{}{"text": "hello world", "prefix": "hello"},
				Expression:  "starts_with($text, $prefix)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["ends_with"] = BuiltinFunction{
		Name:        "ends_with",
		Description: "Check if string ends with suffix",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
			{Name: "suffix", Type: "string", Required: true, Description: "Suffix to check"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(m) operation",
		Implementation:  ace.stringEndsWithFunc,
		Examples: []FunctionExample{
			{
				Description: "Check if text ends with suffix",
				Input:       map[string]interface{}{"text": "hello world", "suffix": "world"},
				Expression:  "ends_with($text, $suffix)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["word_count"] = BuiltinFunction{
		Name:        "word_count",
		Description: "Count words in text",
		Category:    CategoryString,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.stringWordCountFunc,
		Examples: []FunctionExample{
			{
				Description: "Count words in text",
				Input:       map[string]interface{}{"text": "hello world test"},
				Expression:  "word_count($text)",
				Expected:    3,
			},
		},
	}

	// Math functions
	ace.functionRegistry["abs"] = BuiltinFunction{
		Name:        "abs",
		Description: "Absolute value of a number",
		Category:    CategoryMath,
		Parameters: []FunctionParameter{
			{Name: "number", Type: "number", Required: true, Description: "Input number"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.mathAbsFunc,
		Examples: []FunctionExample{
			{
				Description: "Get absolute value",
				Input:       map[string]interface{}{"number": -5},
				Expression:  "abs($number)",
				Expected:    5.0,
			},
		},
	}

	ace.functionRegistry["max"] = BuiltinFunction{
		Name:        "max",
		Description: "Maximum of two numbers",
		Category:    CategoryMath,
		Parameters: []FunctionParameter{
			{Name: "a", Type: "number", Required: true, Description: "First number"},
			{Name: "b", Type: "number", Required: true, Description: "Second number"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.mathMaxFunc,
		Examples: []FunctionExample{
			{
				Description: "Get maximum of two numbers",
				Input:       map[string]interface{}{"a": 5, "b": 10},
				Expression:  "max($a, $b)",
				Expected:    10.0,
			},
		},
	}

	ace.functionRegistry["min"] = BuiltinFunction{
		Name:        "min",
		Description: "Minimum of two numbers",
		Category:    CategoryMath,
		Parameters: []FunctionParameter{
			{Name: "a", Type: "number", Required: true, Description: "First number"},
			{Name: "b", Type: "number", Required: true, Description: "Second number"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.mathMinFunc,
		Examples: []FunctionExample{
			{
				Description: "Get minimum of two numbers",
				Input:       map[string]interface{}{"a": 5, "b": 10},
				Expression:  "min($a, $b)",
				Expected:    5.0,
			},
		},
	}

	ace.functionRegistry["round"] = BuiltinFunction{
		Name:        "round",
		Description: "Round number to nearest integer",
		Category:    CategoryMath,
		Parameters: []FunctionParameter{
			{Name: "number", Type: "number", Required: true, Description: "Input number"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.mathRoundFunc,
		Examples: []FunctionExample{
			{
				Description: "Round number",
				Input:       map[string]interface{}{"number": 3.7},
				Expression:  "round($number)",
				Expected:    4.0,
			},
		},
	}

	// Date/time functions
	ace.functionRegistry["now"] = BuiltinFunction{
		Name:        "now",
		Description: "Get current timestamp",
		Category:    CategoryDate,
		Parameters:  []FunctionParameter{},
		ReturnType:  "number",
		SecurityLevel: SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation: ace.dateNowFunc,
		Examples: []FunctionExample{
			{
				Description: "Get current timestamp",
				Input:       map[string]interface{}{},
				Expression:  "now()",
				Expected:    time.Now().Unix(),
			},
		},
	}

	ace.functionRegistry["time_diff"] = BuiltinFunction{
		Name:        "time_diff",
		Description: "Calculate time difference in seconds",
		Category:    CategoryDate,
		Parameters: []FunctionParameter{
			{Name: "time1", Type: "number", Required: true, Description: "First timestamp"},
			{Name: "time2", Type: "number", Required: true, Description: "Second timestamp"},
		},
		ReturnType:      "number",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.dateTimeDiffFunc,
		Examples: []FunctionExample{
			{
				Description: "Calculate time difference",
				Input:       map[string]interface{}{"time1": 1000, "time2": 2000},
				Expression:  "time_diff($time1, $time2)",
				Expected:    1000.0,
			},
		},
	}

	// Regex functions
	ace.functionRegistry["regex_match"] = BuiltinFunction{
		Name:        "regex_match",
		Description: "Test if text matches regex pattern",
		Category:    CategoryRegex,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
			{Name: "pattern", Type: "string", Required: true, Description: "Regex pattern"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelMedium,
		PerformanceHint: "O(n) operation, compiled regex is cached",
		Implementation:  ace.regexMatchFunc,
		Examples: []FunctionExample{
			{
				Description: "Test regex match",
				Input:       map[string]interface{}{"text": "hello123", "pattern": `\d+`},
				Expression:  "regex_match($text, $pattern)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["regex_extract"] = BuiltinFunction{
		Name:        "regex_extract",
		Description: "Extract matched groups from regex",
		Category:    CategoryRegex,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
			{Name: "pattern", Type: "string", Required: true, Description: "Regex pattern with groups"},
		},
		ReturnType:      "array",
		SecurityLevel:   SecurityLevelMedium,
		PerformanceHint: "O(n) operation, compiled regex is cached",
		Implementation:  ace.regexExtractFunc,
		Examples: []FunctionExample{
			{
				Description: "Extract regex groups",
				Input:       map[string]interface{}{"text": "phone: 123-456-7890", "pattern": `(\d{3})-(\d{3})-(\d{4})`},
				Expression:  "regex_extract($text, $pattern)",
				Expected:    []string{"123-456-7890", "123", "456", "7890"},
			},
		},
	}

	// Security functions
	ace.functionRegistry["hash_md5"] = BuiltinFunction{
		Name:        "hash_md5",
		Description: "Calculate MD5 hash of text",
		Category:    CategorySecurity,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "string",
		SecurityLevel:   SecurityLevelMedium,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.securityHashMD5Func,
		Examples: []FunctionExample{
			{
				Description: "Calculate MD5 hash",
				Input:       map[string]interface{}{"text": "hello"},
				Expression:  "hash_md5($text)",
				Expected:    "5d41402abc4b2a76b9719d911017c592",
			},
		},
	}

	ace.functionRegistry["hash_sha256"] = BuiltinFunction{
		Name:        "hash_sha256",
		Description: "Calculate SHA256 hash of text",
		Category:    CategorySecurity,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "string",
		SecurityLevel:   SecurityLevelMedium,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.securityHashSHA256Func,
		Examples: []FunctionExample{
			{
				Description: "Calculate SHA256 hash",
				Input:       map[string]interface{}{"text": "hello"},
				Expression:  "hash_sha256($text)",
				Expected:    "2cf24dba4f21d4288094c14b6c2c9c8d366ed3b8bf2f7dcda1d1a1a3b11b4e3a",
			},
		},
	}

	// Analysis functions
	ace.functionRegistry["detect_pii"] = BuiltinFunction{
		Name:        "detect_pii",
		Description: "Detect PII patterns in text",
		Category:    CategoryAnalysis,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelHigh,
		PerformanceHint: "O(n) operation with multiple regex patterns",
		Implementation:  ace.analysisDetectPIIFunc,
		Examples: []FunctionExample{
			{
				Description: "Detect PII in text",
				Input:       map[string]interface{}{"text": "My SSN is 123-45-6789"},
				Expression:  "detect_pii($text)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["detect_credit_card"] = BuiltinFunction{
		Name:        "detect_credit_card",
		Description: "Detect credit card numbers in text",
		Category:    CategoryAnalysis,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelHigh,
		PerformanceHint: "O(n) operation with Luhn algorithm",
		Implementation:  ace.analysisDetectCreditCardFunc,
		Examples: []FunctionExample{
			{
				Description: "Detect credit card in text",
				Input:       map[string]interface{}{"text": "Card: 4532-1234-5678-9012"},
				Expression:  "detect_credit_card($text)",
				Expected:    true,
			},
		},
	}

	// Validation functions
	ace.functionRegistry["is_email"] = BuiltinFunction{
		Name:        "is_email",
		Description: "Validate email address format",
		Category:    CategoryValidation,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation with regex",
		Implementation:  ace.validationIsEmailFunc,
		Examples: []FunctionExample{
			{
				Description: "Validate email format",
				Input:       map[string]interface{}{"text": "user@example.com"},
				Expression:  "is_email($text)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["is_url"] = BuiltinFunction{
		Name:        "is_url",
		Description: "Validate URL format",
		Category:    CategoryValidation,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.validationIsURLFunc,
		Examples: []FunctionExample{
			{
				Description: "Validate URL format",
				Input:       map[string]interface{}{"text": "https://example.com"},
				Expression:  "is_url($text)",
				Expected:    true,
			},
		},
	}

	ace.functionRegistry["is_ip"] = BuiltinFunction{
		Name:        "is_ip",
		Description: "Validate IP address format",
		Category:    CategoryValidation,
		Parameters: []FunctionParameter{
			{Name: "text", Type: "string", Required: true, Description: "Input text"},
		},
		ReturnType:      "boolean",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.validationIsIPFunc,
		Examples: []FunctionExample{
			{
				Description: "Validate IP address format",
				Input:       map[string]interface{}{"text": "192.168.1.1"},
				Expression:  "is_ip($text)",
				Expected:    true,
			},
		},
	}

	// Utility functions
	ace.functionRegistry["coalesce"] = BuiltinFunction{
		Name:        "coalesce",
		Description: "Return first non-null value",
		Category:    CategoryUtility,
		Parameters: []FunctionParameter{
			{Name: "values", Type: "array", Required: true, Description: "Array of values"},
		},
		ReturnType:      "any",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(n) operation",
		Implementation:  ace.utilityCoalesceFunc,
		Examples: []FunctionExample{
			{
				Description: "Get first non-null value",
				Input:       map[string]interface{}{"values": []interface{}{nil, "", "hello"}},
				Expression:  "coalesce($values)",
				Expected:    "hello",
			},
		},
	}

	ace.functionRegistry["type_of"] = BuiltinFunction{
		Name:        "type_of",
		Description: "Get type of value",
		Category:    CategoryUtility,
		Parameters: []FunctionParameter{
			{Name: "value", Type: "any", Required: true, Description: "Input value"},
		},
		ReturnType:      "string",
		SecurityLevel:   SecurityLevelLow,
		PerformanceHint: "O(1) operation",
		Implementation:  ace.utilityTypeOfFunc,
		Examples: []FunctionExample{
			{
				Description: "Get type of value",
				Input:       map[string]interface{}{"value": 42},
				Expression:  "type_of($value)",
				Expected:    "number",
			},
		},
	}
}

// ===== STRING FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) stringLengthFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("length() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	return len(text), nil
}

func (ace *AdvancedConditionEvaluator) stringUpperFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("upper() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	return strings.ToUpper(text), nil
}

func (ace *AdvancedConditionEvaluator) stringLowerFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("lower() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	return strings.ToLower(text), nil
}

func (ace *AdvancedConditionEvaluator) stringTrimFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("trim() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	return strings.TrimSpace(text), nil
}

func (ace *AdvancedConditionEvaluator) stringContainsFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("contains() requires exactly 2 arguments")
	}
	
	text := fmt.Sprintf("%v", args[0])
	substring := fmt.Sprintf("%v", args[1])
	return strings.Contains(text, substring), nil
}

func (ace *AdvancedConditionEvaluator) stringStartsWithFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("starts_with() requires exactly 2 arguments")
	}
	
	text := fmt.Sprintf("%v", args[0])
	prefix := fmt.Sprintf("%v", args[1])
	return strings.HasPrefix(text, prefix), nil
}

func (ace *AdvancedConditionEvaluator) stringEndsWithFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("ends_with() requires exactly 2 arguments")
	}
	
	text := fmt.Sprintf("%v", args[0])
	suffix := fmt.Sprintf("%v", args[1])
	return strings.HasSuffix(text, suffix), nil
}

func (ace *AdvancedConditionEvaluator) stringWordCountFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("word_count() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	words := strings.Fields(text)
	return len(words), nil
}

// ===== MATH FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) mathAbsFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("abs() requires exactly 1 argument")
	}
	
	num := ace.toFloat64(args[0])
	return math.Abs(num), nil
}

func (ace *AdvancedConditionEvaluator) mathMaxFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("max() requires exactly 2 arguments")
	}
	
	a := ace.toFloat64(args[0])
	b := ace.toFloat64(args[1])
	return math.Max(a, b), nil
}

func (ace *AdvancedConditionEvaluator) mathMinFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("min() requires exactly 2 arguments")
	}
	
	a := ace.toFloat64(args[0])
	b := ace.toFloat64(args[1])
	return math.Min(a, b), nil
}

func (ace *AdvancedConditionEvaluator) mathRoundFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("round() requires exactly 1 argument")
	}
	
	num := ace.toFloat64(args[0])
	return math.Round(num), nil
}

// ===== DATE FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) dateNowFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("now() requires no arguments")
	}
	
	return float64(time.Now().Unix()), nil
}

func (ace *AdvancedConditionEvaluator) dateTimeDiffFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("time_diff() requires exactly 2 arguments")
	}
	
	time1 := ace.toFloat64(args[0])
	time2 := ace.toFloat64(args[1])
	return math.Abs(time2 - time1), nil
}

// ===== REGEX FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) regexMatchFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("regex_match() requires exactly 2 arguments")
	}
	
	text := fmt.Sprintf("%v", args[0])
	pattern := fmt.Sprintf("%v", args[1])
	
	regex, err := ace.getCompiledRegex(pattern, true)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %v", err)
	}
	
	return regex.MatchString(text), nil
}

func (ace *AdvancedConditionEvaluator) regexExtractFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("regex_extract() requires exactly 2 arguments")
	}
	
	text := fmt.Sprintf("%v", args[0])
	pattern := fmt.Sprintf("%v", args[1])
	
	regex, err := ace.getCompiledRegex(pattern, true)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %v", err)
	}
	
	matches := regex.FindStringSubmatch(text)
	result := make([]string, len(matches))
	for i, match := range matches {
		result[i] = match
	}
	
	return result, nil
}

// ===== SECURITY FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) securityHashMD5Func(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("hash_md5() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:]), nil
}

func (ace *AdvancedConditionEvaluator) securityHashSHA256Func(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("hash_sha256() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:]), nil
}

// ===== ANALYSIS FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) analysisDetectPIIFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("detect_pii() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	
	// Common PII patterns
	piiPatterns := []string{
		`\b\d{3}-\d{2}-\d{4}\b`,                    // SSN
		`\b\d{3}-\d{3}-\d{4}\b`,                    // Phone
		`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Email
		`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`, // Credit Card
	}
	
	for _, pattern := range piiPatterns {
		if matched, _ := regexp.MatchString(pattern, text); matched {
			return true, nil
		}
	}
	
	return false, nil
}

func (ace *AdvancedConditionEvaluator) analysisDetectCreditCardFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("detect_credit_card() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	
	// Credit card pattern (simplified)
	ccPattern := `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`
	matched, _ := regexp.MatchString(ccPattern, text)
	
	return matched, nil
}

// ===== VALIDATION FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) validationIsEmailFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("is_email() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	
	// Simple email regex
	emailPattern := `^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$`
	matched, _ := regexp.MatchString(emailPattern, text)
	
	return matched, nil
}

func (ace *AdvancedConditionEvaluator) validationIsURLFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("is_url() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	
	_, err := url.Parse(text)
	return err == nil && (strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://")), nil
}

func (ace *AdvancedConditionEvaluator) validationIsIPFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("is_ip() requires exactly 1 argument")
	}
	
	text := fmt.Sprintf("%v", args[0])
	
	ip := net.ParseIP(text)
	return ip != nil, nil
}

// ===== UTILITY FUNCTION IMPLEMENTATIONS =====

func (ace *AdvancedConditionEvaluator) utilityCoalesceFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("coalesce() requires at least 1 argument")
	}
	
	// If first argument is an array, use its elements
	if arr, ok := args[0].([]interface{}); ok {
		args = arr
	}
	
	for _, arg := range args {
		if arg != nil {
			if str, ok := arg.(string); ok && str != "" {
				return arg, nil
			} else if str, ok := arg.(string); !ok || str != "" {
				return arg, nil
			}
		}
	}
	
	return nil, nil
}

func (ace *AdvancedConditionEvaluator) utilityTypeOfFunc(ctx *EvaluationContext, args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("type_of() requires exactly 1 argument")
	}
	
	value := args[0]
	
	if value == nil {
		return "null", nil
	}
	
	switch value.(type) {
	case bool:
		return "boolean", nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return "number", nil
	case string:
		return "string", nil
	case []interface{}:
		return "array", nil
	case map[string]interface{}:
		return "object", nil
	default:
		return "unknown", nil
	}
}

// GetAvailableFunctions returns all available built-in functions
func (ace *AdvancedConditionEvaluator) GetAvailableFunctions() map[string]BuiltinFunction {
	ace.mu.RLock()
	defer ace.mu.RUnlock()
	
	result := make(map[string]BuiltinFunction)
	for name, function := range ace.functionRegistry {
		result[name] = function
	}
	
	return result
}

// GetFunctionsByCategory returns functions grouped by category
func (ace *AdvancedConditionEvaluator) GetFunctionsByCategory() map[FunctionCategory][]BuiltinFunction {
	ace.mu.RLock()
	defer ace.mu.RUnlock()
	
	result := make(map[FunctionCategory][]BuiltinFunction)
	
	for _, function := range ace.functionRegistry {
		result[function.Category] = append(result[function.Category], function)
	}
	
	return result
}

// ValidateFunction validates a function call
func (ace *AdvancedConditionEvaluator) ValidateFunction(name string, args []interface{}) error {
	ace.mu.RLock()
	function, exists := ace.functionRegistry[name]
	ace.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("unknown function: %s", name)
	}
	
	// Check argument count
	requiredCount := 0
	for _, param := range function.Parameters {
		if param.Required {
			requiredCount++
		}
	}
	
	if len(args) < requiredCount {
		return fmt.Errorf("function %s requires at least %d arguments, got %d", name, requiredCount, len(args))
	}
	
	if len(args) > len(function.Parameters) {
		return fmt.Errorf("function %s accepts at most %d arguments, got %d", name, len(function.Parameters), len(args))
	}
	
	return nil
} 