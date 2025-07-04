package interfaces

import (
	"context"
	"fmt"
	"time"
)

// Provider represents the interface that all AI providers must implement
type Provider interface {
	// GetName returns the provider's name (e.g., "openai", "anthropic")
	GetName() string
	
	// ChatCompletion sends a chat completion request to the provider
	ChatCompletion(ctx context.Context, request *ChatCompletionRequest) (*ChatCompletionResponse, error)
	
	// StreamChatCompletion sends a streaming chat completion request
	StreamChatCompletion(ctx context.Context, request *ChatCompletionRequest) (<-chan *ChatCompletionStreamResponse, error)
	
	// ValidateCredentials checks if the provider credentials are valid
	ValidateCredentials(ctx context.Context) error
	
	// GetModels returns the list of available models for this provider
	GetModels(ctx context.Context) ([]Model, error)
	
	// GetUsage returns current usage statistics (if supported)
	GetUsage(ctx context.Context) (*UsageStats, error)
	
	// Close closes any persistent connections
	Close() error
}

// ChatCompletionRequest represents a standardized chat completion request
type ChatCompletionRequest struct {
	Messages          []Message          `json:"messages"`
	Model             string             `json:"model"`
	MaxTokens         *int               `json:"max_tokens,omitempty"`
	Temperature       *float64           `json:"temperature,omitempty"`
	TopP              *float64           `json:"top_p,omitempty"`
	PresencePenalty   *float64           `json:"presence_penalty,omitempty"`
	FrequencyPenalty  *float64           `json:"frequency_penalty,omitempty"`
	Stop              []string           `json:"stop,omitempty"`
	Stream            bool               `json:"stream,omitempty"`
	User              string             `json:"user,omitempty"`
	
	// Provider-specific parameters
	ProviderParams    map[string]interface{} `json:"provider_params,omitempty"`
	
	// Gateway-specific metadata
	RequestID         string             `json:"-"`
	UserID            string             `json:"-"`
	SessionID         string             `json:"-"`
	Timestamp         time.Time          `json:"-"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`    // "system", "user", "assistant"
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

// ChatCompletionResponse represents a standardized chat completion response
type ChatCompletionResponse struct {
	ID                string                 `json:"id"`
	Object            string                 `json:"object"`
	Created           int64                  `json:"created"`
	Model             string                 `json:"model"`
	Choices           []Choice               `json:"choices"`
	Usage             *Usage                 `json:"usage,omitempty"`
	
	// Provider-specific fields
	ProviderResponse  map[string]interface{} `json:"provider_response,omitempty"`
	
	// Gateway-specific metadata
	Provider          string                 `json:"provider"`
	ProcessingTimeMs  int64                  `json:"processing_time_ms"`
	CacheHit          bool                   `json:"cache_hit"`
	RequestID         string                 `json:"request_id"`
}

// Choice represents a completion choice
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage represents token usage information
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletionStreamResponse represents a streaming response chunk
type ChatCompletionStreamResponse struct {
	ID                string                 `json:"id"`
	Object            string                 `json:"object"`
	Created           int64                  `json:"created"`
	Model             string                 `json:"model"`
	Choices           []StreamChoice         `json:"choices"`
	
	// Provider-specific fields
	ProviderResponse  map[string]interface{} `json:"provider_response,omitempty"`
	
	// Gateway metadata
	Provider          string                 `json:"provider"`
	RequestID         string                 `json:"request_id"`
	
	// Stream control
	Done              bool                   `json:"done"`
	Error             *StreamError           `json:"error,omitempty"`
}

// StreamChoice represents a streaming choice
type StreamChoice struct {
	Index       int          `json:"index"`
	Delta       MessageDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

// MessageDelta represents incremental message content
type MessageDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// StreamError represents a streaming error
type StreamError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type,omitempty"`
}

// Model represents an AI model
type Model struct {
	ID          string   `json:"id"`
	Object      string   `json:"object"`
	Created     int64    `json:"created"`
	OwnedBy     string   `json:"owned_by"`
	Permissions []string `json:"permissions,omitempty"`
	
	// Model capabilities
	MaxTokens           *int     `json:"max_tokens,omitempty"`
	ContextWindow       *int     `json:"context_window,omitempty"`
	SupportsStreaming   bool     `json:"supports_streaming"`
	SupportsCompletion  bool     `json:"supports_completion"`
	SupportsChat        bool     `json:"supports_chat"`
	
	// Pricing information (if available)
	PricePerToken       *float64 `json:"price_per_token,omitempty"`
	PricePerInputToken  *float64 `json:"price_per_input_token,omitempty"`
	PricePerOutputToken *float64 `json:"price_per_output_token,omitempty"`
}

// UsageStats represents provider usage statistics
type UsageStats struct {
	TotalRequests     int64   `json:"total_requests"`
	TotalTokens       int64   `json:"total_tokens"`
	TotalCost         float64 `json:"total_cost"`
	RequestsToday     int64   `json:"requests_today"`
	TokensToday       int64   `json:"tokens_today"`
	CostToday         float64 `json:"cost_today"`
	RateLimitRemaining int64  `json:"rate_limit_remaining"`
	RateLimitReset     *time.Time `json:"rate_limit_reset,omitempty"`
}

// ProviderConfig represents provider-specific configuration
type ProviderConfig struct {
	Name            string            `yaml:"name" mapstructure:"name"`
	APIKey          string            `yaml:"api_key" mapstructure:"api_key"`
	BaseURL         string            `yaml:"base_url" mapstructure:"base_url"`
	Timeout         time.Duration     `yaml:"timeout" mapstructure:"timeout"`
	MaxRetries      int               `yaml:"max_retries" mapstructure:"max_retries"`
	RetryDelay      time.Duration     `yaml:"retry_delay" mapstructure:"retry_delay"`
	RateLimit       *RateLimitConfig  `yaml:"rate_limit" mapstructure:"rate_limit"`
	DefaultModel    string            `yaml:"default_model" mapstructure:"default_model"`
	CustomHeaders   map[string]string `yaml:"custom_headers" mapstructure:"custom_headers"`
	
	// Provider-specific settings
	Organization    string            `yaml:"organization,omitempty" mapstructure:"organization"`
	APIVersion      string            `yaml:"api_version,omitempty" mapstructure:"api_version"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled         bool          `yaml:"enabled" mapstructure:"enabled"`
	RequestsPerMin  int           `yaml:"requests_per_min" mapstructure:"requests_per_min"`
	TokensPerMin    int           `yaml:"tokens_per_min" mapstructure:"tokens_per_min"`
	BurstSize       int           `yaml:"burst_size" mapstructure:"burst_size"`
	CleanupInterval time.Duration `yaml:"cleanup_interval" mapstructure:"cleanup_interval"`
}

// ProviderError represents a provider-specific error
type ProviderError struct {
	Code           string    `json:"code"`
	Message        string    `json:"message"`
	Type           string    `json:"type"`
	Provider       string    `json:"provider"`
	HTTPStatusCode int       `json:"http_status_code,omitempty"`
	Details        string    `json:"details,omitempty"`
	Retryable      bool      `json:"retryable"`
	RetryAfter     *time.Duration `json:"retry_after,omitempty"`
	
	// Original error for debugging
	OriginalError  error     `json:"-"`
}

// Error implements the error interface
func (e *ProviderError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("[%s] %s: %s - %s", e.Provider, e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Provider, e.Code, e.Message)
}

// Unwrap returns the original error for error unwrapping
func (e *ProviderError) Unwrap() error {
	return e.OriginalError
}

// IsRetryable returns true if the error indicates a retryable condition
func (e *ProviderError) IsRetryable() bool {
	return e.Retryable
}

// IsRateLimited returns true if the error is due to rate limiting
func (e *ProviderError) IsRateLimited() bool {
	return e.Code == "rate_limit_exceeded" || e.HTTPStatusCode == 429
}

// IsAuthenticationError returns true if the error is due to authentication issues
func (e *ProviderError) IsAuthenticationError() bool {
	return e.Code == "invalid_api_key" || e.HTTPStatusCode == 401
}

// IsQuotaExceeded returns true if the error is due to quota/billing issues
func (e *ProviderError) IsQuotaExceeded() bool {
	return e.Code == "quota_exceeded" || e.Code == "insufficient_quota" || e.HTTPStatusCode == 402
}

// Common error codes
const (
	ErrorCodeInvalidAPIKey      = "invalid_api_key"
	ErrorCodeRateLimitExceeded  = "rate_limit_exceeded"
	ErrorCodeQuotaExceeded      = "quota_exceeded"
	ErrorCodeInsufficientQuota  = "insufficient_quota"
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeModelNotFound      = "model_not_found"
	ErrorCodeTokenLimitExceeded = "token_limit_exceeded"
	ErrorCodeServerError        = "server_error"
	ErrorCodeServiceUnavailable = "service_unavailable"
	ErrorCodeTimeout            = "timeout"
	ErrorCodeNetworkError       = "network_error"
	ErrorCodeUnknownError       = "unknown_error"
)

// ProviderMetrics represents metrics for monitoring providers
type ProviderMetrics struct {
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	AverageLatency      time.Duration `json:"average_latency"`
	TotalTokens         int64         `json:"total_tokens"`
	TotalCost           float64       `json:"total_cost"`
	LastRequestTime     *time.Time    `json:"last_request_time,omitempty"`
	
	// Error breakdown
	ErrorsByCode        map[string]int64 `json:"errors_by_code"`
	
	// Rate limiting
	RateLimitHits       int64         `json:"rate_limit_hits"`
	LastRateLimitHit    *time.Time    `json:"last_rate_limit_hit,omitempty"`
} 