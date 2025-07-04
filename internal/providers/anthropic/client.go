package anthropic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
	"github.com/sirupsen/logrus"
)

// Client implements the Provider interface for Anthropic
type Client struct {
	config      *interfaces.ProviderConfig
	httpClient  *http.Client
	logger      *logrus.Logger
	rateLimiter *RateLimiter
	metrics     *interfaces.ProviderMetrics
}

// NewClient creates a new Anthropic client
func NewClient(config *interfaces.ProviderConfig) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.APIKey == "" {
		return nil, fmt.Errorf("API key is required for Anthropic provider")
	}

	if config.BaseURL == "" {
		config.BaseURL = "https://api.anthropic.com/v1"
	}

	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}

	if config.APIVersion == "" {
		config.APIVersion = "2023-06-01"
	}

	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	client := &Client{
		config:     config,
		httpClient: httpClient,
		metrics: &interfaces.ProviderMetrics{
			ErrorsByCode: make(map[string]int64),
		},
	}

	// Initialize rate limiter if enabled
	if config.RateLimit != nil && config.RateLimit.Enabled {
		client.rateLimiter = NewRateLimiter(config.RateLimit)
	}

	return client, nil
}

// GetName returns the provider name
func (c *Client) GetName() string {
	return "anthropic"
}

// ChatCompletion sends a chat completion request to Anthropic
func (c *Client) ChatCompletion(ctx context.Context, request *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error) {
	startTime := time.Now()
	c.metrics.TotalRequests++

	// Check rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			c.metrics.RateLimitHits++
			now := time.Now()
			c.metrics.LastRateLimitHit = &now
			return nil, &interfaces.ProviderError{
				Code:      interfaces.ErrorCodeRateLimitExceeded,
				Message:   "Rate limit exceeded",
				Type:      "rate_limit",
				Provider:  "anthropic",
				Retryable: true,
			}
		}
	}

	// Convert to Anthropic request format
	anthropicReq := c.convertToAnthropicRequest(request)

	// Execute request with retries
	response, err := c.executeWithRetry(ctx, anthropicReq)
	if err != nil {
		c.metrics.FailedRequests++
		c.recordError(err)
		return nil, err
	}

	// Convert response
	result := c.convertFromAnthropicResponse(response, request.RequestID)
	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	c.metrics.SuccessfulRequests++
	c.updateMetrics(startTime, result.Usage)

	return result, nil
}

// StreamChatCompletion sends a streaming chat completion request
func (c *Client) StreamChatCompletion(ctx context.Context, request *interfaces.ChatCompletionRequest) (<-chan *interfaces.ChatCompletionStreamResponse, error) {
	// Check rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			c.metrics.RateLimitHits++
			now := time.Now()
			c.metrics.LastRateLimitHit = &now
			return nil, &interfaces.ProviderError{
				Code:      interfaces.ErrorCodeRateLimitExceeded,
				Message:   "Rate limit exceeded",
				Type:      "rate_limit",
				Provider:  "anthropic",
				Retryable: true,
			}
		}
	}

	// Convert to Anthropic request format
	anthropicReq := c.convertToAnthropicRequest(request)
	anthropicReq.Stream = true

	// Create response channel
	responseChan := make(chan *interfaces.ChatCompletionStreamResponse, 100)

	// Start streaming in goroutine
	go func() {
		defer close(responseChan)
		c.executeStreamingRequest(ctx, anthropicReq, responseChan, request.RequestID)
	}()

	return responseChan, nil
}

// ValidateCredentials validates the Anthropic API key
func (c *Client) ValidateCredentials(ctx context.Context) error {
	// Anthropic doesn't have a dedicated auth endpoint, so we'll try a simple messages request
	testReq := &AnthropicRequest{
		Model:     "claude-3-haiku-20240307",
		MaxTokens: nil,
		Messages: []AnthropicMessage{
			{Role: "user", Content: "Hello"},
		},
	}

	url := fmt.Sprintf("%s/messages", c.config.BaseURL)
	jsonData, err := json.Marshal(testReq)
	if err != nil {
		return fmt.Errorf("failed to marshal test request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &interfaces.ProviderError{
			Code:          interfaces.ErrorCodeNetworkError,
			Message:       "Failed to connect to Anthropic API",
			Provider:      "anthropic",
			OriginalError: err,
			Retryable:     true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return &interfaces.ProviderError{
			Code:           interfaces.ErrorCodeInvalidAPIKey,
			Message:        "Invalid API key",
			Provider:       "anthropic",
			HTTPStatusCode: resp.StatusCode,
			Retryable:      false,
		}
	}

	// Any response other than 401 means auth is working
	// (we expect this test request to succeed or fail for other reasons)
	return nil
}

// GetModels returns available models for Anthropic
func (c *Client) GetModels(ctx context.Context) ([]interfaces.Model, error) {
	// Anthropic doesn't provide a models endpoint, so we return known models
	models := []interfaces.Model{
		{
			ID:                "claude-3-opus-20240229",
			Object:            "model",
			Created:           time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC).Unix(),
			OwnedBy:           "anthropic",
			SupportsChat:      true,
			SupportsStreaming: true,
			ContextWindow:     &[]int{200000}[0],
			MaxTokens:         &[]int{4096}[0],
		},
		{
			ID:                "claude-3-sonnet-20240229",
			Object:            "model",
			Created:           time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC).Unix(),
			OwnedBy:           "anthropic",
			SupportsChat:      true,
			SupportsStreaming: true,
			ContextWindow:     &[]int{200000}[0],
			MaxTokens:         &[]int{4096}[0],
		},
		{
			ID:                "claude-3-haiku-20240307",
			Object:            "model",
			Created:           time.Date(2024, 3, 7, 0, 0, 0, 0, time.UTC).Unix(),
			OwnedBy:           "anthropic",
			SupportsChat:      true,
			SupportsStreaming: true,
			ContextWindow:     &[]int{200000}[0],
			MaxTokens:         &[]int{4096}[0],
		},
	}

	return models, nil
}

// GetUsage returns usage statistics (Anthropic doesn't provide this via API)
func (c *Client) GetUsage(ctx context.Context) (*interfaces.UsageStats, error) {
	// Anthropic doesn't provide usage statistics via API
	// Return basic metrics from our tracking
	return &interfaces.UsageStats{
		TotalRequests:      c.metrics.TotalRequests,
		TotalTokens:        c.metrics.TotalTokens,
		TotalCost:          c.metrics.TotalCost,
		RateLimitRemaining: 0, // Unknown
		RateLimitReset:     nil,
	}, nil
}

// Close closes any persistent connections
func (c *Client) Close() error {
	if c.rateLimiter != nil {
		c.rateLimiter.Stop()
	}
	return nil
}

// Private methods

// convertToAnthropicRequest converts a generic request to Anthropic format
func (c *Client) convertToAnthropicRequest(request *interfaces.ChatCompletionRequest) *AnthropicRequest {
	anthropicReq := &AnthropicRequest{
		Model:       request.Model,
		MaxTokens:   request.MaxTokens,
		Temperature: request.Temperature,
		TopP:        request.TopP,
		Stream:      request.Stream,
	}

	// Set default max tokens if not specified
	if anthropicReq.MaxTokens == nil {
		defaultMaxTokens := 4096
		anthropicReq.MaxTokens = &defaultMaxTokens
	}

	// Convert messages, handling system messages specially
	var systemMessage string
	var messages []AnthropicMessage

	for _, msg := range request.Messages {
		if msg.Role == "system" {
			// Anthropic handles system messages separately
			if systemMessage != "" {
				systemMessage += "\n\n" + msg.Content
			} else {
				systemMessage = msg.Content
			}
		} else {
			messages = append(messages, AnthropicMessage{
				Role:    msg.Role,
				Content: msg.Content,
			})
		}
	}

	if systemMessage != "" {
		anthropicReq.System = systemMessage
	}
	anthropicReq.Messages = messages

	// Apply provider-specific parameters
	if request.ProviderParams != nil {
		if topK, ok := request.ProviderParams["top_k"]; ok {
			if topKInt, ok := topK.(int); ok {
				anthropicReq.TopK = &topKInt
			}
		}
	}

	return anthropicReq
}

// convertFromAnthropicResponse converts Anthropic response to generic format
func (c *Client) convertFromAnthropicResponse(response *AnthropicResponse, requestID string) *interfaces.ChatCompletionResponse {
	choices := make([]interfaces.Choice, 1)
	
	// Anthropic returns a single choice
	var content string
	for _, contentBlock := range response.Content {
		if contentBlock.Type == "text" {
			content += contentBlock.Text
		}
	}

	choices[0] = interfaces.Choice{
		Index: 0,
		Message: interfaces.Message{
			Role:    "assistant",
			Content: content,
		},
		FinishReason: response.StopReason,
	}

	var usage *interfaces.Usage
	if response.Usage != nil {
		usage = &interfaces.Usage{
			PromptTokens:     response.Usage.InputTokens,
			CompletionTokens: response.Usage.OutputTokens,
			TotalTokens:      response.Usage.InputTokens + response.Usage.OutputTokens,
		}
	}

	return &interfaces.ChatCompletionResponse{
		ID:        response.ID,
		Object:    "chat.completion",
		Created:   time.Now().Unix(),
		Model:     response.Model,
		Choices:   choices,
		Usage:     usage,
		Provider:  "anthropic",
		RequestID: requestID,
	}
}

// executeWithRetry executes a request with retry logic
func (c *Client) executeWithRetry(ctx context.Context, request *AnthropicRequest) (*AnthropicResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			delay := time.Duration(attempt) * c.config.RetryDelay
			c.logger.WithFields(logrus.Fields{
				"attempt": attempt,
				"delay":   delay,
			}).Debug("Retrying Anthropic request")

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		response, err := c.executeRequest(ctx, request)
		if err == nil {
			return response, nil
		}

		lastErr = err

		// Check if error is retryable
		if providerErr, ok := err.(*interfaces.ProviderError); ok {
			if !providerErr.IsRetryable() {
				break
			}
		}
	}

	return nil, lastErr
}

// executeRequest executes a single request
func (c *Client) executeRequest(ctx context.Context, request *AnthropicRequest) (*AnthropicResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/messages", c.config.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &interfaces.ProviderError{
			Code:          interfaces.ErrorCodeNetworkError,
			Message:       "Failed to execute request",
			Provider:      "anthropic",
			OriginalError: err,
			Retryable:     true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, c.handleErrorResponse(resp)
	}

	var response AnthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// executeStreamingRequest executes a streaming request
func (c *Client) executeStreamingRequest(ctx context.Context, request *AnthropicRequest, responseChan chan<- *interfaces.ChatCompletionStreamResponse, requestID string) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		responseChan <- &interfaces.ChatCompletionStreamResponse{
			Error: &interfaces.StreamError{
				Code:    interfaces.ErrorCodeInvalidRequest,
				Message: "Failed to marshal request",
			},
			RequestID: requestID,
			Provider:  "anthropic",
			Done:      true,
		}
		return
	}

	url := fmt.Sprintf("%s/messages", c.config.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		responseChan <- &interfaces.ChatCompletionStreamResponse{
			Error: &interfaces.StreamError{
				Code:    interfaces.ErrorCodeNetworkError,
				Message: "Failed to create request",
			},
			RequestID: requestID,
			Provider:  "anthropic",
			Done:      true,
		}
		return
	}

	c.setAuthHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		responseChan <- &interfaces.ChatCompletionStreamResponse{
			Error: &interfaces.StreamError{
				Code:    interfaces.ErrorCodeNetworkError,
				Message: "Failed to execute request",
			},
			RequestID: requestID,
			Provider:  "anthropic",
			Done:      true,
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		providerErr := c.handleErrorResponse(resp)
		responseChan <- &interfaces.ChatCompletionStreamResponse{
			Error: &interfaces.StreamError{
				Code:    providerErr.Code,
				Message: providerErr.Message,
			},
			RequestID: requestID,
			Provider:  "anthropic",
			Done:      true,
		}
		return
	}

	// Parse SSE stream
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			responseChan <- &interfaces.ChatCompletionStreamResponse{
				RequestID: requestID,
				Provider:  "anthropic",
				Done:      true,
			}
			break
		}

		var streamEvent AnthropicStreamEvent
		if err := json.Unmarshal([]byte(data), &streamEvent); err != nil {
			c.logger.WithError(err).Warn("Failed to parse streaming response")
			continue
		}

		// Convert to generic format based on event type
		switch streamEvent.Type {
		case "content_block_delta":
			if streamEvent.Delta != nil && streamEvent.Delta.Text != "" {
				responseChan <- &interfaces.ChatCompletionStreamResponse{
					ID:      "anthropic-stream",
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   request.Model,
					Choices: []interfaces.StreamChoice{
						{
							Index: 0,
							Delta: interfaces.MessageDelta{
								Content: streamEvent.Delta.Text,
							},
						},
					},
					RequestID: requestID,
					Provider:  "anthropic",
					Done:      false,
				}
			}
		case "message_stop":
			responseChan <- &interfaces.ChatCompletionStreamResponse{
				RequestID: requestID,
				Provider:  "anthropic",
				Done:      true,
			}
			return
		}
	}

	if err := scanner.Err(); err != nil {
		responseChan <- &interfaces.ChatCompletionStreamResponse{
			Error: &interfaces.StreamError{
				Code:    interfaces.ErrorCodeNetworkError,
				Message: "Failed to read streaming response",
			},
			RequestID: requestID,
			Provider:  "anthropic",
			Done:      true,
		}
	}
}

// setAuthHeaders sets authentication headers
func (c *Client) setAuthHeaders(req *http.Request) {
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("anthropic-version", c.config.APIVersion)

	// Add custom headers
	for key, value := range c.config.CustomHeaders {
		req.Header.Set(key, value)
	}
}

// handleErrorResponse handles error responses from Anthropic API
func (c *Client) handleErrorResponse(resp *http.Response) *interfaces.ProviderError {
	body, _ := io.ReadAll(resp.Body)
	
	var errorResp struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}

	json.Unmarshal(body, &errorResp)

	providerErr := &interfaces.ProviderError{
		HTTPStatusCode: resp.StatusCode,
		Provider:       "anthropic",
		Details:        string(body),
	}

	// Map Anthropic errors to provider errors
	switch resp.StatusCode {
	case 400:
		providerErr.Code = interfaces.ErrorCodeInvalidRequest
		providerErr.Message = "Invalid request"
		providerErr.Retryable = false
	case 401:
		providerErr.Code = interfaces.ErrorCodeInvalidAPIKey
		providerErr.Message = "Invalid API key"
		providerErr.Retryable = false
	case 403:
		providerErr.Code = interfaces.ErrorCodeQuotaExceeded
		providerErr.Message = "Forbidden - quota may be exceeded"
		providerErr.Retryable = false
	case 429:
		providerErr.Code = interfaces.ErrorCodeRateLimitExceeded
		providerErr.Message = "Rate limit exceeded"
		providerErr.Retryable = true
		
		// Parse retry-after header
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if seconds, err := strconv.Atoi(retryAfter); err == nil {
				duration := time.Duration(seconds) * time.Second
				providerErr.RetryAfter = &duration
			}
		}
	case 500, 502, 503, 504:
		providerErr.Code = interfaces.ErrorCodeServerError
		providerErr.Message = "Server error"
		providerErr.Retryable = true
	default:
		providerErr.Code = interfaces.ErrorCodeUnknownError
		providerErr.Message = "Unknown error"
		providerErr.Retryable = resp.StatusCode >= 500
	}

	// Use Anthropic's error message if available
	if errorResp.Error.Message != "" {
		providerErr.Message = errorResp.Error.Message
		providerErr.Type = errorResp.Error.Type
	}

	return providerErr
}

// recordError records error metrics
func (c *Client) recordError(err error) {
	if providerErr, ok := err.(*interfaces.ProviderError); ok {
		c.metrics.ErrorsByCode[providerErr.Code]++
	} else {
		c.metrics.ErrorsByCode[interfaces.ErrorCodeUnknownError]++
	}
}

// updateMetrics updates provider metrics
func (c *Client) updateMetrics(startTime time.Time, usage *interfaces.Usage) {
	duration := time.Since(startTime)
	
	// Update average latency
	totalRequests := c.metrics.TotalRequests
	if totalRequests > 0 {
		currentAvg := c.metrics.AverageLatency
		c.metrics.AverageLatency = (currentAvg*time.Duration(totalRequests-1) + duration) / time.Duration(totalRequests)
	} else {
		c.metrics.AverageLatency = duration
	}

	if usage != nil {
		c.metrics.TotalTokens += int64(usage.TotalTokens)
		// Estimate cost (simplified pricing)
		c.metrics.TotalCost += c.estimateCost(usage.TotalTokens)
	}

	now := time.Now()
	c.metrics.LastRequestTime = &now
}

// estimateCost estimates the cost of a request (simplified)
func (c *Client) estimateCost(tokens int) float64 {
	// Simplified cost estimation - actual pricing varies by model
	return float64(tokens) * 0.015 / 1000 // ~$0.015 per 1K tokens (Claude pricing)
} 