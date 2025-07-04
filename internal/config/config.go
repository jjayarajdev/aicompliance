package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
	"ai-gateway-poc/internal/providers"
)

// Config represents the complete application configuration
type Config struct {
	Environment string         `mapstructure:"environment"`
	LogLevel    string         `mapstructure:"log_level"`
	Server      ServerConfig   `mapstructure:"server"`
	Database    DatabaseConfig `mapstructure:"database"`
	Redis       RedisConfig    `mapstructure:"redis"`
	Providers   ProvidersConfig `mapstructure:"providers"`
	Proxy       ProxyConfig    `mapstructure:"proxy"`
	Security    SecurityConfig `mapstructure:"security"`
	Cache       CacheConfig    `mapstructure:"cache"`
	RateLimit   RateLimitConfig `mapstructure:"rate_limit"`
	Monitoring  MonitoringConfig `mapstructure:"monitoring"`
	Router      providers.RouterConfig `mapstructure:"router"`
	Timeouts    TimeoutConfig `mapstructure:"timeouts"`
	Logging     LoggingConfig `mapstructure:"logging"`
	PIIDetection PIIDetectionConfig `mapstructure:"pii_detection"`
	ContentClassification ContentClassificationConfig `mapstructure:"content_classification"`
	MLAnalysis MLAnalysisConfig `mapstructure:"ml_analysis"`
	Preprocessing PreprocessingConfig `mapstructure:"preprocessing"`
	AnalysisPipeline AnalysisPipelineConfig `mapstructure:"analysis_pipeline"`
	PolicyEngine     PolicyEngineConfig     `mapstructure:"policy_engine"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port         int `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int `mapstructure:"read_timeout"`
	WriteTimeout int `mapstructure:"write_timeout"`
	IdleTimeout  int `mapstructure:"idle_timeout"`
}

// DatabaseConfig holds PostgreSQL database configuration
type DatabaseConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Username     string `mapstructure:"username"`
	Password     string `mapstructure:"password"`
	Database     string `mapstructure:"database"`
	SSLMode      string `mapstructure:"ssl_mode"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
	ConnMaxLife  time.Duration `mapstructure:"conn_max_life"`
}

// RedisConfig holds Redis cache configuration
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	Database int    `mapstructure:"database"`
	PoolSize int    `mapstructure:"pool_size"`
}

// ProvidersConfig holds AI provider configurations
type ProvidersConfig struct {
	OpenAI    OpenAIConfig    `mapstructure:"openai"`
	Anthropic AnthropicConfig `mapstructure:"anthropic"`
}

// OpenAIConfig holds OpenAI API configuration
type OpenAIConfig struct {
	APIKey     string        `mapstructure:"api_key"`
	BaseURL    string        `mapstructure:"base_url"`
	Timeout    time.Duration `mapstructure:"timeout"`
	MaxRetries int           `mapstructure:"max_retries"`
}

// AnthropicConfig holds Anthropic Claude API configuration
type AnthropicConfig struct {
	APIKey     string        `mapstructure:"api_key"`
	BaseURL    string        `mapstructure:"base_url"`
	Timeout    time.Duration `mapstructure:"timeout"`
	MaxRetries int           `mapstructure:"max_retries"`
}

// ProxyConfig holds forward proxy configuration
type ProxyConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	Port        int      `mapstructure:"port"`
	SSLBump     bool     `mapstructure:"ssl_bump"`
	CertFile    string   `mapstructure:"cert_file"`
	KeyFile     string   `mapstructure:"key_file"`
	TargetHosts []string `mapstructure:"target_hosts"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	JWTSecret     string        `mapstructure:"jwt_secret"`
	JWTExpiry     time.Duration `mapstructure:"jwt_expiry"`
	APIKeyHeader  string        `mapstructure:"api_key_header"`
	CorsEnabled   bool          `mapstructure:"cors_enabled"`
	CorsOrigins   []string      `mapstructure:"cors_origins"`
	TLSMinVersion string        `mapstructure:"tls_min_version"`
}

// CacheConfig holds caching configuration
type CacheConfig struct {
	Enabled    bool          `mapstructure:"enabled"`
	DefaultTTL time.Duration `mapstructure:"default_ttl"`
	MaxSize    string        `mapstructure:"max_size"`
	Prefix     string        `mapstructure:"prefix"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool `mapstructure:"enabled"`
	RequestsPerMin int  `mapstructure:"requests_per_min"`
	BurstSize      int  `mapstructure:"burst_size"`
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

// MonitoringConfig holds monitoring and metrics configuration
type MonitoringConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	MetricsPort    int    `mapstructure:"metrics_port"`
	MetricsPath    string `mapstructure:"metrics_path"`
	HealthPath     string `mapstructure:"health_path"`
	PrometheusAddr string `mapstructure:"prometheus_addr"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level           string            `mapstructure:"level"`
	Format          string            `mapstructure:"format"`
	Output          string            `mapstructure:"output"`
	File            LogFileConfig     `mapstructure:"file"`
	Fields          map[string]string `mapstructure:"fields"`
	RequestLogging  RequestLogging    `mapstructure:"request_logging"`
	ComponentLevels map[string]string `mapstructure:"component_levels"`
}

// LogFileConfig holds file logging configuration
type LogFileConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Path       string `mapstructure:"path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// RequestLogging holds HTTP request logging configuration
type RequestLogging struct {
	Enabled       bool     `mapstructure:"enabled"`
	Headers       bool     `mapstructure:"headers"`
	Body          bool     `mapstructure:"body"`
	QueryParams   bool     `mapstructure:"query_params"`
	ResponseBody  bool     `mapstructure:"response_body"`
	ExcludePaths  []string `mapstructure:"exclude_paths"`
	MaxBodySize   int      `mapstructure:"max_body_size"`
}

// PIIDetectionConfig holds PII detection configuration
type PIIDetectionConfig struct {
	Enabled          bool                `mapstructure:"enabled"`
	Patterns         map[string]string   `mapstructure:"patterns"`
	SensitivityLevel string              `mapstructure:"sensitivity_level"`
	RedactionMode    string              `mapstructure:"redaction_mode"`
	CustomPatterns   map[string]string   `mapstructure:"custom_patterns"`
	ExcludePatterns  []string            `mapstructure:"exclude_patterns"`
	MaxTextSize      int                 `mapstructure:"max_text_size"`
}

// ContentClassificationConfig holds content classification configuration
type ContentClassificationConfig struct {
	Enabled       bool                              `mapstructure:"enabled"`
	DefaultLevel  string                            `mapstructure:"default_level"`
	MinConfidence float64                           `mapstructure:"min_confidence"`
	MaxTextSize   int                               `mapstructure:"max_text_size"`
	LevelConfigs  map[string]LevelClassifierConfig  `mapstructure:"level_configs"`
	GlobalRules   []GlobalRuleConfig                `mapstructure:"global_rules"`
}

// LevelClassifierConfig holds configuration for a specific sensitivity level
type LevelClassifierConfig struct {
	Enabled          bool      `mapstructure:"enabled"`
	Weight           float64   `mapstructure:"weight"`
	Keywords         []string  `mapstructure:"keywords"`
	Patterns         []string  `mapstructure:"patterns"`
	RequiredPIITypes []string  `mapstructure:"required_pii_types"`
	MinPIICount      int       `mapstructure:"min_pii_count"`
}

// GlobalRuleConfig holds configuration for global classification rules
type GlobalRuleConfig struct {
	Name       string                    `mapstructure:"name"`
	Level      string                    `mapstructure:"level"`
	Weight     float64                   `mapstructure:"weight"`
	Enabled    bool                      `mapstructure:"enabled"`
	Conditions []RuleConditionConfig     `mapstructure:"conditions"`
}

// RuleConditionConfig holds configuration for rule conditions
type RuleConditionConfig struct {
	Type          string      `mapstructure:"type"`
	Operator      string      `mapstructure:"operator"`
	Value         interface{} `mapstructure:"value"`
	CaseSensitive bool        `mapstructure:"case_sensitive"`
}

// MLAnalysisConfig holds ML-powered analysis configuration
type MLAnalysisConfig struct {
	Enabled             bool                    `mapstructure:"enabled"`
	DefaultProvider     string                  `mapstructure:"default_provider"`
	CacheEnabled        bool                    `mapstructure:"cache_enabled"`
	CacheTTL           string                  `mapstructure:"cache_ttl"`
	Timeout            string                  `mapstructure:"timeout"`
	MinConfidenceScore  float64                 `mapstructure:"min_confidence_score"`
	EnableSentiment     bool                    `mapstructure:"enable_sentiment"`
	EnableTopics        bool                    `mapstructure:"enable_topics"`
	EnableEntities      bool                    `mapstructure:"enable_entities"`
	ProviderConfigs     map[string]MLProviderConfig `mapstructure:"providers"`
	FeatureExtraction   MLFeatureConfig         `mapstructure:"feature_extraction"`
}

// MLProviderConfig holds ML provider configuration
type MLProviderConfig struct {
	Enabled   bool              `mapstructure:"enabled"`
	Endpoint  string            `mapstructure:"endpoint"`
	APIKey    string            `mapstructure:"api_key"`
	Model     string            `mapstructure:"model"`
	Timeout   string            `mapstructure:"timeout"`
	Options   map[string]interface{} `mapstructure:"options"`
}

// MLFeatureConfig holds feature extraction configuration
type MLFeatureConfig struct {
	EnableKeywordExtraction bool     `mapstructure:"enable_keyword_extraction"`
	EnablePhraseExtraction  bool     `mapstructure:"enable_phrase_extraction"`
	MaxKeywords             int      `mapstructure:"max_keywords"`
	MaxPhrases              int      `mapstructure:"max_phrases"`
	MinTermFrequency        int      `mapstructure:"min_term_frequency"`
}

// PreprocessingConfig holds content preprocessing configuration
type PreprocessingConfig struct {
	Enabled             bool                `mapstructure:"enabled"`
	NormalizeWhitespace bool                `mapstructure:"normalize_whitespace"`
	RemoveControlChars  bool                `mapstructure:"remove_control_chars"`
	NormalizeUnicode    bool                `mapstructure:"normalize_unicode"`
	PreservePunctuation bool                `mapstructure:"preserve_punctuation"`
	PreserveNumbers     bool                `mapstructure:"preserve_numbers"`
	ConvertToLowercase  bool                `mapstructure:"convert_to_lowercase"`
	RemoveExtraSpaces   bool                `mapstructure:"remove_extra_spaces"`
	TrimWhitespace      bool                `mapstructure:"trim_whitespace"`
	LanguageDetection   LanguageDetectionConfig `mapstructure:"language_detection"`
	MaxProcessingTime   time.Duration       `mapstructure:"max_processing_time"`
	ChunkSize           int                 `mapstructure:"chunk_size"`
	Profiles            map[string]PreprocessingProfileConfig `mapstructure:"profiles"`
}

// LanguageDetectionConfig holds language detection configuration
type LanguageDetectionConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	MinTextLength       int      `mapstructure:"min_text_length"`
	MaxLanguages        int      `mapstructure:"max_languages"`
	ConfidenceThreshold float64  `mapstructure:"confidence_threshold"`
	TargetLanguages     []string `mapstructure:"target_languages"`
}

// PreprocessingProfileConfig holds configuration for preprocessing profiles
type PreprocessingProfileConfig struct {
	NormalizeWhitespace bool                     `mapstructure:"normalize_whitespace"`
	RemoveControlChars  bool                     `mapstructure:"remove_control_chars"`
	NormalizeUnicode    bool                     `mapstructure:"normalize_unicode"`
	PreservePunctuation bool                     `mapstructure:"preserve_punctuation"`
	PreserveNumbers     bool                     `mapstructure:"preserve_numbers"`
	ConvertToLowercase  bool                     `mapstructure:"convert_to_lowercase"`
	RemoveExtraSpaces   bool                     `mapstructure:"remove_extra_spaces"`
	TrimWhitespace      bool                     `mapstructure:"trim_whitespace"`
	LanguageDetection   LanguageDetectionConfig  `mapstructure:"language_detection"`
}

// AnalysisPipelineConfig holds configuration for the parallel analysis pipeline
type AnalysisPipelineConfig struct {
	Enabled         bool                                    `mapstructure:"enabled"`
	Components      PipelineComponentsConfig                `mapstructure:"components"`
	Performance     PipelinePerformanceConfig               `mapstructure:"performance"`
	ErrorHandling   PipelineErrorHandlingConfig             `mapstructure:"error_handling"`
	Profiles        map[string]PipelineProfileConfig        `mapstructure:"profiles"`
	Aggregation     PipelineAggregationConfig               `mapstructure:"aggregation"`
	Monitoring      PipelineMonitoringConfig                `mapstructure:"monitoring"`
	EnsembleVoting  EnsembleVotingSystemConfig              `mapstructure:"ensemble_voting"`
	CustomPatterns  CustomPatternConfig                     `mapstructure:"custom_patterns"`
}

// PipelineComponentsConfig configures which analysis components are enabled
type PipelineComponentsConfig struct {
	EnablePreprocessing   bool `mapstructure:"enable_preprocessing"`
	EnablePIIDetection    bool `mapstructure:"enable_pii_detection"`
	EnableClassification  bool `mapstructure:"enable_classification"`
	EnableMLAnalysis      bool `mapstructure:"enable_ml_analysis"`
	EnableFileScanning    bool `mapstructure:"enable_file_scanning"`
}

// PipelinePerformanceConfig configures performance settings
type PipelinePerformanceConfig struct {
	MaxConcurrency    int           `mapstructure:"max_concurrency"`
	ComponentTimeout  time.Duration `mapstructure:"component_timeout"`
	OverallTimeout    time.Duration `mapstructure:"overall_timeout"`
	WarmupComponents  bool          `mapstructure:"warmup_components"`
	EnableMetrics     bool          `mapstructure:"enable_metrics"`
}

// PipelineErrorHandlingConfig configures error handling behavior
type PipelineErrorHandlingConfig struct {
	ContinueOnError      bool `mapstructure:"continue_on_error"`
	RequireAllComponents bool `mapstructure:"require_all_components"`
}

// PipelineProfileConfig defines a complete pipeline profile
type PipelineProfileConfig struct {
	Components    PipelineComponentsConfig     `mapstructure:"components"`
	Performance   PipelinePerformanceConfig    `mapstructure:"performance"`
	ErrorHandling PipelineErrorHandlingConfig  `mapstructure:"error_handling"`
}

// PipelineAggregationConfig configures result aggregation
type PipelineAggregationConfig struct {
	ConfidenceWeights map[string]float64 `mapstructure:"confidence_weights"`
	RiskLevelMapping  map[string]int     `mapstructure:"risk_level_mapping"`
}

// PipelineMonitoringConfig configures pipeline monitoring
type PipelineMonitoringConfig struct {
	TrackComponentStats   bool          `mapstructure:"track_component_stats"`
	TrackBottlenecks      bool          `mapstructure:"track_bottlenecks"`
	CalculateSpeedup      bool          `mapstructure:"calculate_speedup"`
	LogSlowRequests       bool          `mapstructure:"log_slow_requests"`
	SlowRequestThreshold  time.Duration `mapstructure:"slow_request_threshold"`
}

// EnsembleVotingSystemConfig configures the ensemble voting system
type EnsembleVotingSystemConfig struct {
	Enabled                 bool                                       `mapstructure:"enabled"`
	VotingStrategy          string                                     `mapstructure:"voting_strategy"`
	WeightedVoting          bool                                       `mapstructure:"weighted_voting"`
	ConsensusThreshold      float64                                    `mapstructure:"consensus_threshold"`
	DisagreementThreshold   float64                                    `mapstructure:"disagreement_threshold"`
	EnableCalibration       bool                                       `mapstructure:"enable_calibration"`
	HistoricalSamples       int                                        `mapstructure:"historical_samples"`
	CalibrationDecayFactor  float64                                    `mapstructure:"calibration_decay_factor"`
	ComponentWeights        map[string]float64                         `mapstructure:"component_weights"`
	DynamicWeighting        bool                                       `mapstructure:"dynamic_weighting"`
	EnableUncertainty       bool                                       `mapstructure:"enable_uncertainty"`
	UncertaintyMethod       string                                     `mapstructure:"uncertainty_method"`
	MinConfidenceThreshold  float64                                    `mapstructure:"min_confidence_threshold"`
	HighConfidenceThreshold float64                                    `mapstructure:"high_confidence_threshold"`
	Profiles                map[string]EnsembleVotingProfileConfig     `mapstructure:"profiles"`
}

// EnsembleVotingProfileConfig defines a profile for ensemble voting settings
type EnsembleVotingProfileConfig struct {
	VotingStrategy          string  `mapstructure:"voting_strategy"`
	ConsensusThreshold      float64 `mapstructure:"consensus_threshold"`
	DisagreementThreshold   float64 `mapstructure:"disagreement_threshold"`
	MinConfidenceThreshold  float64 `mapstructure:"min_confidence_threshold"`
}

// CustomPatternConfig configures the custom pattern management system
type CustomPatternConfig struct {
	Enabled                  bool                                   `mapstructure:"enabled"`
	MaxPatternsPerOrg        int                                    `mapstructure:"max_patterns_per_org"`
	MaxPatternLength         int                                    `mapstructure:"max_pattern_length"`
	MaxExecutionTime         time.Duration                          `mapstructure:"max_execution_time"`
	EnableVersioning         bool                                   `mapstructure:"enable_versioning"`
	MaxVersionsPerPattern    int                                    `mapstructure:"max_versions_per_pattern"`
	RequireValidation        bool                                   `mapstructure:"require_validation"`
	AutoDeactivateOnErrors   bool                                   `mapstructure:"auto_deactivate_on_errors"`
	PerformanceTracking      bool                                   `mapstructure:"performance_tracking"`
	DefaultPatterns          map[string][]DefaultPatternConfig      `mapstructure:"default_patterns"`
	Categories               []PatternCategoryConfig                `mapstructure:"categories"`
	Testing                  PatternTestingConfig                   `mapstructure:"testing"`
	AutoSuggestions          PatternAutoSuggestionsConfig           `mapstructure:"auto_suggestions"`
}

// DefaultPatternConfig defines a default pattern template
type DefaultPatternConfig struct {
	Name        string  `mapstructure:"name"`
	Pattern     string  `mapstructure:"pattern"`
	PIIType     string  `mapstructure:"pii_type"`
	Confidence  float64 `mapstructure:"confidence"`
	Description string  `mapstructure:"description"`
}

// PatternCategoryConfig defines a pattern category
type PatternCategoryConfig struct {
	Name        string `mapstructure:"name"`
	Description string `mapstructure:"description"`
}

// PatternTestingConfig configures pattern testing and validation
type PatternTestingConfig struct {
	RequiredTestCases      int      `mapstructure:"required_test_cases"`
	PerformanceThresholdMs int      `mapstructure:"performance_threshold_ms"`
	ComplexityThreshold    int      `mapstructure:"complexity_threshold"`
	BannedConstructs       []string `mapstructure:"banned_constructs"`
}

// PatternAutoSuggestionsConfig configures automatic pattern suggestions
type PatternAutoSuggestionsConfig struct {
	Enabled              bool    `mapstructure:"enabled"`
	MinOccurrences       int     `mapstructure:"min_occurrences"`
	ConfidenceThreshold  float64 `mapstructure:"confidence_threshold"`
	SuggestImprovements  bool    `mapstructure:"suggest_improvements"`
}

// PolicyEngineConfig represents policy engine configuration
type PolicyEngineConfig struct {
	Enabled            bool                        `mapstructure:"enabled"`
	Validation         PolicyValidationConfig      `mapstructure:"validation"`
	Evaluation         PolicyEvaluationConfig      `mapstructure:"evaluation"`
	ConflictResolution PolicyConflictConfig        `mapstructure:"conflict_resolution"`
	Storage            PolicyStorageConfig         `mapstructure:"storage"`
	Metrics            PolicyMetricsConfig         `mapstructure:"metrics"`
	Logging            PolicyLoggingConfig         `mapstructure:"logging"`

	// Real-time engine configuration
	RealTimeEngine         RealTimePolicyConfig `mapstructure:"real_time_engine"`
	
	// Version management configuration
	VersionManager         PolicyVersionConfig  `mapstructure:"version_manager"`
}

// PolicyValidationConfig represents policy validation settings
type PolicyValidationConfig struct {
	StrictMode        bool `mapstructure:"strict_mode"`
	RequireDescription bool `mapstructure:"require_description"`
	MaxRulesPerPolicy int  `mapstructure:"max_rules_per_policy"`
	MaxConditionDepth int  `mapstructure:"max_condition_depth"`
}

// PolicyEvaluationConfig represents policy evaluation settings
type PolicyEvaluationConfig struct {
	Timeout            time.Duration `mapstructure:"timeout"`
	CacheEnabled       bool          `mapstructure:"cache_enabled"`
	CacheTTL           time.Duration `mapstructure:"cache_ttl"`
	ParallelEvaluation bool          `mapstructure:"parallel_evaluation"`
}

// PolicyConflictConfig represents conflict resolution settings
type PolicyConflictConfig struct {
	Strategy               string `mapstructure:"strategy"`
	LogConflicts           bool   `mapstructure:"log_conflicts"`
	RequireManualResolution bool   `mapstructure:"require_manual_resolution"`
}

// PolicyStorageConfig represents policy storage settings
type PolicyStorageConfig struct {
	Type           string        `mapstructure:"type"`
	BackupEnabled  bool          `mapstructure:"backup_enabled"`
	BackupInterval time.Duration `mapstructure:"backup_interval"`
}

// PolicyMetricsConfig represents policy metrics settings
type PolicyMetricsConfig struct {
	Enabled         bool `mapstructure:"enabled"`
	TrackPerformance bool `mapstructure:"track_performance"`
	TrackDecisions  bool `mapstructure:"track_decisions"`
	RetentionDays   int  `mapstructure:"retention_days"`
}

// PolicyLoggingConfig represents policy logging settings
type PolicyLoggingConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	LogLevel        string `mapstructure:"log_level"`
	LogDecisions    bool   `mapstructure:"log_decisions"`
	LogConflicts    bool   `mapstructure:"log_conflicts"`
	LogPerformance  bool   `mapstructure:"log_performance"`
}

// RealTimePolicyConfig configures the real-time policy engine
type RealTimePolicyConfig struct {
	Enabled                bool          `mapstructure:"enabled"`
	MaxLatency             time.Duration `mapstructure:"max_latency"`
	MaxConcurrency         int           `mapstructure:"max_concurrency"`
	WorkerPoolSize         int           `mapstructure:"worker_pool_size"`
	
	// Caching configuration
	PolicyCacheTTL         time.Duration `mapstructure:"policy_cache_ttl"`
	ResultCacheTTL         time.Duration `mapstructure:"result_cache_ttl"`
	ConditionCacheTTL      time.Duration `mapstructure:"condition_cache_ttl"`
	MaxCacheSize           int           `mapstructure:"max_cache_size"`
	
	// Circuit breaker configuration
	FailureThreshold       int           `mapstructure:"failure_threshold"`
	RecoveryTimeout        time.Duration `mapstructure:"recovery_timeout"`
	
	// Monitoring configuration
	MetricsEnabled         bool          `mapstructure:"metrics_enabled"`
	HealthCheckInterval    time.Duration `mapstructure:"health_check_interval"`
}

// PolicyVersionConfig configures the policy version management system
type PolicyVersionConfig struct {
	Enabled                bool          `mapstructure:"enabled"`
	AutoApprovalEnabled    bool          `mapstructure:"auto_approval_enabled"`
	RequiredApprovers      []string      `mapstructure:"required_approvers"`
	MaxVersionsPerPolicy   int           `mapstructure:"max_versions_per_policy"`
	VersionRetentionPeriod time.Duration `mapstructure:"version_retention_period"`
	ChangeDetectionEnabled bool          `mapstructure:"change_detection_enabled"`
	ImpactAnalysisEnabled  bool          `mapstructure:"impact_analysis_enabled"`
	RollbackChecksEnabled  bool          `mapstructure:"rollback_checks_enabled"`
	AuditLoggingEnabled    bool          `mapstructure:"audit_logging_enabled"`
	
	// Approval workflow configuration
	ApprovalWorkflow       PolicyApprovalWorkflowConfig `mapstructure:"approval_workflow"`
	
	// Rollback configuration
	RollbackSettings       PolicyRollbackConfig         `mapstructure:"rollback_settings"`
	
	// Archive and cleanup configuration
	ArchiveSettings        PolicyArchiveConfig          `mapstructure:"archive_settings"`
}

// PolicyApprovalWorkflowConfig configures the approval workflow
type PolicyApprovalWorkflowConfig struct {
	Enabled              bool          `mapstructure:"enabled"`
	RequireApproval      bool          `mapstructure:"require_approval"`
	ParallelApproval     bool          `mapstructure:"parallel_approval"`
	ApprovalTimeout      time.Duration `mapstructure:"approval_timeout"`
	NotificationEnabled  bool          `mapstructure:"notification_enabled"`
	NotificationChannels []string      `mapstructure:"notification_channels"`
}

// PolicyRollbackConfig configures rollback operations
type PolicyRollbackConfig struct {
	Enabled              bool          `mapstructure:"enabled"`
	RequireApproval      bool          `mapstructure:"require_approval"`
	AutoBackup           bool          `mapstructure:"auto_backup"`
	ValidationRequired   bool          `mapstructure:"validation_required"`
	MaxRollbackDepth     int           `mapstructure:"max_rollback_depth"`
	RollbackTimeout      time.Duration `mapstructure:"rollback_timeout"`
	PostRollbackChecks   bool          `mapstructure:"post_rollback_checks"`
}

// PolicyArchiveConfig configures archive and cleanup settings
type PolicyArchiveConfig struct {
	Enabled              bool          `mapstructure:"enabled"`
	AutoArchiveEnabled   bool          `mapstructure:"auto_archive_enabled"`
	ArchiveAfterDays     int           `mapstructure:"archive_after_days"`
	PurgeAfterDays       int           `mapstructure:"purge_after_days"`
	KeepActiveVersions   int           `mapstructure:"keep_active_versions"`
	CompressArchives     bool          `mapstructure:"compress_archives"`
}

// Load reads configuration from files and environment variables
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// Set environment variable prefix
	viper.SetEnvPrefix("GATEWAY")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set defaults
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error since we have defaults
			fmt.Println("No config file found, using defaults and environment variables")
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	// Validate configuration
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("environment", "development")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.idle_timeout", 60)

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.database", "ai_gateway")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.conn_max_life", "1h")

	// Redis defaults
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.database", 0)
	viper.SetDefault("redis.pool_size", 10)

	// Provider defaults
	viper.SetDefault("providers.openai.base_url", "https://api.openai.com/v1")
	viper.SetDefault("providers.openai.timeout", "60s")
	viper.SetDefault("providers.openai.max_retries", 3)
	viper.SetDefault("providers.anthropic.base_url", "https://api.anthropic.com")
	viper.SetDefault("providers.anthropic.timeout", "60s")
	viper.SetDefault("providers.anthropic.max_retries", 3)

	// Proxy defaults
	viper.SetDefault("proxy.enabled", true)
	viper.SetDefault("proxy.port", 8443)
	viper.SetDefault("proxy.ssl_bump", true)
	viper.SetDefault("proxy.target_hosts", []string{"api.openai.com", "api.anthropic.com"})

	// Security defaults
	viper.SetDefault("security.jwt_expiry", "24h")
	viper.SetDefault("security.api_key_header", "X-API-Key")
	viper.SetDefault("security.cors_enabled", true)
	viper.SetDefault("security.cors_origins", []string{"*"})
	viper.SetDefault("security.tls_min_version", "1.2")

	// Cache defaults
	viper.SetDefault("cache.enabled", true)
	viper.SetDefault("cache.default_ttl", "1h")
	viper.SetDefault("cache.max_size", "100MB")
	viper.SetDefault("cache.prefix", "gateway:")

	// Rate limit defaults
	viper.SetDefault("rate_limit.enabled", true)
	viper.SetDefault("rate_limit.requests_per_min", 60)
	viper.SetDefault("rate_limit.burst_size", 100)
	viper.SetDefault("rate_limit.cleanup_interval", "5m")

	// Monitoring defaults
	viper.SetDefault("monitoring.enabled", true)
	viper.SetDefault("monitoring.metrics_port", 9090)
	viper.SetDefault("monitoring.metrics_path", "/metrics")
	viper.SetDefault("monitoring.health_path", "/health")

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.file.enabled", false)
	viper.SetDefault("logging.file.path", "logs/gateway.log")
	viper.SetDefault("logging.file.max_size", 100)
	viper.SetDefault("logging.file.max_backups", 3)
	viper.SetDefault("logging.file.max_age", 28)
	viper.SetDefault("logging.file.compress", true)
	viper.SetDefault("logging.request_logging.enabled", true)
	viper.SetDefault("logging.request_logging.headers", false)
	viper.SetDefault("logging.request_logging.body", false)
	viper.SetDefault("logging.request_logging.query_params", true)
	viper.SetDefault("logging.request_logging.response_body", false)
	viper.SetDefault("logging.request_logging.max_body_size", 1024)

	// PII Detection defaults
	viper.SetDefault("pii_detection.enabled", true)
	viper.SetDefault("pii_detection.sensitivity_level", "medium")
	viper.SetDefault("pii_detection.redaction_mode", "mask")
	viper.SetDefault("pii_detection.max_text_size", 1048576)

	// Content Classification defaults
	viper.SetDefault("content_classification.enabled", true)
	viper.SetDefault("content_classification.default_level", "internal")
	viper.SetDefault("content_classification.min_confidence", 0.3)
	viper.SetDefault("content_classification.max_text_size", 1048576)

	// ML Analysis defaults
	viper.SetDefault("ml_analysis.enabled", true)
	viper.SetDefault("ml_analysis.default_provider", "mock")
	viper.SetDefault("ml_analysis.cache_enabled", true)
	viper.SetDefault("ml_analysis.cache_ttl", "1h")
	viper.SetDefault("ml_analysis.timeout", "30s")
	viper.SetDefault("ml_analysis.min_confidence_score", 0.3)
	viper.SetDefault("ml_analysis.enable_sentiment", true)
	viper.SetDefault("ml_analysis.enable_topics", true)
	viper.SetDefault("ml_analysis.enable_entities", true)
	viper.SetDefault("ml_analysis.feature_extraction.enable_keyword_extraction", true)
	viper.SetDefault("ml_analysis.feature_extraction.enable_phrase_extraction", true)
	viper.SetDefault("ml_analysis.feature_extraction.max_keywords", 20)
	viper.SetDefault("ml_analysis.feature_extraction.max_phrases", 10)
	viper.SetDefault("ml_analysis.feature_extraction.min_term_frequency", 2)

	// Timeout defaults
	viper.SetDefault("timeouts.default_request_timeout", "30s")
	viper.SetDefault("timeouts.chat_completion_timeout", "60s")
	viper.SetDefault("timeouts.streaming_timeout", "300s")
	viper.SetDefault("timeouts.health_check_timeout", "10s")
	viper.SetDefault("timeouts.provider_connect_timeout", "10s")
	viper.SetDefault("timeouts.provider_read_timeout", "45s")
	viper.SetDefault("timeouts.provider_write_timeout", "10s")
	viper.SetDefault("timeouts.database_query_timeout", "5s")
	viper.SetDefault("timeouts.database_connection_timeout", "15s")
	viper.SetDefault("timeouts.cache_operation_timeout", "2s")
	viper.SetDefault("timeouts.shutdown_timeout", "30s")

	// Preprocessing defaults
	viper.SetDefault("preprocessing.enabled", true)
	viper.SetDefault("preprocessing.normalize_whitespace", true)
	viper.SetDefault("preprocessing.remove_control_chars", true)
	viper.SetDefault("preprocessing.normalize_unicode", true)
	viper.SetDefault("preprocessing.preserve_punctuation", true)
	viper.SetDefault("preprocessing.preserve_numbers", true)
	viper.SetDefault("preprocessing.convert_to_lowercase", false)
	viper.SetDefault("preprocessing.remove_extra_spaces", true)
	viper.SetDefault("preprocessing.trim_whitespace", true)
	viper.SetDefault("preprocessing.language_detection.enabled", true)
	viper.SetDefault("preprocessing.language_detection.min_text_length", 10)
	viper.SetDefault("preprocessing.language_detection.max_languages", 3)
	viper.SetDefault("preprocessing.language_detection.confidence_threshold", 0.3)
	viper.SetDefault("preprocessing.max_processing_time", "5s")
	viper.SetDefault("preprocessing.chunk_size", 10000)

	// Analysis Pipeline defaults
	viper.SetDefault("analysis_pipeline.enabled", true)
	viper.SetDefault("analysis_pipeline.components.enable_preprocessing", true)
	viper.SetDefault("analysis_pipeline.components.enable_pii_detection", true)
	viper.SetDefault("analysis_pipeline.components.enable_classification", true)
	viper.SetDefault("analysis_pipeline.components.enable_ml_analysis", true)
	viper.SetDefault("analysis_pipeline.components.enable_file_scanning", false)
	viper.SetDefault("analysis_pipeline.performance.max_concurrency", 4)
	viper.SetDefault("analysis_pipeline.performance.component_timeout", "30s")
	viper.SetDefault("analysis_pipeline.performance.overall_timeout", "60s")
	viper.SetDefault("analysis_pipeline.performance.warmup_components", true)
	viper.SetDefault("analysis_pipeline.performance.enable_metrics", true)
	viper.SetDefault("analysis_pipeline.error_handling.continue_on_error", true)
	viper.SetDefault("analysis_pipeline.error_handling.require_all_components", false)
	viper.SetDefault("analysis_pipeline.monitoring.track_component_stats", true)
	viper.SetDefault("analysis_pipeline.monitoring.track_bottlenecks", true)
	viper.SetDefault("analysis_pipeline.monitoring.calculate_speedup", true)
	viper.SetDefault("analysis_pipeline.monitoring.log_slow_requests", true)
	viper.SetDefault("analysis_pipeline.monitoring.slow_request_threshold", "1s")

	// Ensemble Voting defaults
	viper.SetDefault("analysis_pipeline.ensemble_voting.enabled", true)
	viper.SetDefault("analysis_pipeline.ensemble_voting.voting_strategy", "weighted")
	viper.SetDefault("analysis_pipeline.ensemble_voting.weighted_voting", true)
	viper.SetDefault("analysis_pipeline.ensemble_voting.consensus_threshold", 0.7)
	viper.SetDefault("analysis_pipeline.ensemble_voting.disagreement_threshold", 0.5)
	viper.SetDefault("analysis_pipeline.ensemble_voting.enable_calibration", true)
	viper.SetDefault("analysis_pipeline.ensemble_voting.historical_samples", 100)
	viper.SetDefault("analysis_pipeline.ensemble_voting.calibration_decay_factor", 0.95)
	viper.SetDefault("analysis_pipeline.ensemble_voting.dynamic_weighting", false)
	viper.SetDefault("analysis_pipeline.ensemble_voting.enable_uncertainty", true)
	viper.SetDefault("analysis_pipeline.ensemble_voting.uncertainty_method", "variance")
	viper.SetDefault("analysis_pipeline.ensemble_voting.min_confidence_threshold", 0.3)
	viper.SetDefault("analysis_pipeline.ensemble_voting.high_confidence_threshold", 0.8)

	// Custom Patterns defaults
	viper.SetDefault("analysis_pipeline.custom_patterns.enabled", true)
	viper.SetDefault("analysis_pipeline.custom_patterns.patterns", map[string]string{})
	viper.SetDefault("analysis_pipeline.custom_patterns.sensitivity_level", "high")
	viper.SetDefault("analysis_pipeline.custom_patterns.redaction_mode", "mask")
	viper.SetDefault("analysis_pipeline.custom_patterns.max_text_size", 1048576)

	// Policy Engine defaults
	viper.SetDefault("policy_engine.enabled", true)
	viper.SetDefault("policy_engine.validation.strict_mode", true)
	viper.SetDefault("policy_engine.validation.require_description", true)
	viper.SetDefault("policy_engine.validation.max_rules_per_policy", 20)
	viper.SetDefault("policy_engine.validation.max_condition_depth", 5)
	viper.SetDefault("policy_engine.evaluation.timeout", "200ms")
	viper.SetDefault("policy_engine.evaluation.cache_enabled", true)
	viper.SetDefault("policy_engine.evaluation.cache_ttl", "5m")
	viper.SetDefault("policy_engine.evaluation.parallel_evaluation", true)
	viper.SetDefault("policy_engine.conflict_resolution.strategy", "most_restrictive")
	viper.SetDefault("policy_engine.conflict_resolution.log_conflicts", true)
	viper.SetDefault("policy_engine.conflict_resolution.require_manual_resolution", false)
	viper.SetDefault("policy_engine.storage.type", "memory")
	viper.SetDefault("policy_engine.storage.backup_enabled", true)
	viper.SetDefault("policy_engine.storage.backup_interval", "1h")
	viper.SetDefault("policy_engine.metrics.enabled", true)
	viper.SetDefault("policy_engine.metrics.track_performance", true)
	viper.SetDefault("policy_engine.metrics.track_decisions", true)
	viper.SetDefault("policy_engine.metrics.retention_days", 30)
	viper.SetDefault("policy_engine.logging.enabled", true)
	viper.SetDefault("policy_engine.logging.log_level", "info")
	viper.SetDefault("policy_engine.logging.log_decisions", true)
	viper.SetDefault("policy_engine.logging.log_conflicts", true)
	viper.SetDefault("policy_engine.logging.log_performance", true)

	// Real-time engine defaults
	viper.SetDefault("policy_engine.real_time_engine.enabled", true)
	viper.SetDefault("policy_engine.real_time_engine.max_latency", "1s")
	viper.SetDefault("policy_engine.real_time_engine.max_concurrency", 10)
	viper.SetDefault("policy_engine.real_time_engine.worker_pool_size", 5)
	viper.SetDefault("policy_engine.real_time_engine.policy_cache_ttl", "5m")
	viper.SetDefault("policy_engine.real_time_engine.result_cache_ttl", "10m")
	viper.SetDefault("policy_engine.real_time_engine.condition_cache_ttl", "1m")
	viper.SetDefault("policy_engine.real_time_engine.max_cache_size", 1000)
	viper.SetDefault("policy_engine.real_time_engine.failure_threshold", 5)
	viper.SetDefault("policy_engine.real_time_engine.recovery_timeout", "10s")
	viper.SetDefault("policy_engine.real_time_engine.metrics_enabled", true)
	viper.SetDefault("policy_engine.real_time_engine.health_check_interval", "30s")
}

// validate performs basic configuration validation
func validate(config *Config) error {
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	if config.Redis.Host == "" {
		return fmt.Errorf("redis host is required")
	}

	if config.Security.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	return nil
}

// GetDSN returns the PostgreSQL connection string
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.Username, c.Password, c.Database, c.SSLMode)
}

// GetRedisAddr returns the Redis connection address
func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
} 