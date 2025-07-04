package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ai-gateway-poc/internal/providers/interfaces"
)

// Client represents an OpenAI API client
type Client struct {
	httpClient   *http.Client
	apiKey       string
	baseURL      string
	organization string
	timeout      time.Duration
	maxRetries   int
	retryDelay   time.Duration
	rateLimiter  *RateLimiter
	metrics      *interfaces.ProviderMetrics
}

// Ensure Client implements the Provider interface
var _ interfaces.Provider = (*Client)(nil)

// NewClient creates a new OpenAI client
func NewClient(config *interfaces.ProviderConfig) (*Client, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key is required")
	}

	client := &Client{
		httpClient:   &http.Client{Timeout: config.Timeout},
		apiKey:       config.APIKey,
		baseURL:      config.BaseURL,
		organization: config.Organization,
		timeout:      config.Timeout,
		maxRetries:   config.MaxRetries,
		retryDelay:   config.RetryDelay,
		metrics: &interfaces.ProviderMetrics{
			ErrorsByCode: make(map[string]int64),
		},
	}

	// Initialize rate limiter if configured
	if config.RateLimit != nil && config.RateLimit.Enabled {
		rateLimiter := NewRateLimiter(config.RateLimit)
		client.rateLimiter = rateLimiter
	}

	return client, nil
}

// GetName returns the provider name
func (c *Client) GetName() string {
	return "openai"
}

// ChatCompletion sends a chat completion request to OpenAI
func (c *Client) ChatCompletion(ctx context.Context, request *interfaces.ChatCompletionRequest) (*interfaces.ChatCompletionResponse, error) {
	start := time.Now()
	
	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			c.metrics.RateLimitHits++
			now := time.Now()
			c.metrics.LastRateLimitHit = &now
			return nil, &interfaces.ProviderError{
				Code:      interfaces.ErrorCodeRateLimitExceeded,
				Message:   "Rate limit exceeded",
				Type:      "rate_limit",
				Provider:  "openai",
				Retryable: true,
				OriginalError: err,
			}
		}
	}

	// Convert to OpenAI format
	openaiReq := c.convertToOpenAIRequest(request)

	// Make the API call
	resp, err := c.makeRequest(ctx, "POST", "/chat/completions", openaiReq)
	if err != nil {
		c.updateMetrics(start, false, nil)
		return nil, err
	}

	// Parse response
	var openaiResp OpenAIResponse
	if err := json.Unmarshal(resp, &openaiResp); err != nil {
		c.updateMetrics(start, false, nil)
		return nil, &interfaces.ProviderError{
			Code:    interfaces.ErrorCodeUnknownError,
			Message: "Failed to parse OpenAI response",
			Type:    "parse_error",
			Provider: "openai",
			OriginalError: err,
		}
	}

	// Convert to standard format
	standardResp := c.convertFromOpenAIResponse(&openaiResp)
	standardResp.Provider = "openai"
	standardResp.ProcessingTimeMs = time.Since(start).Milliseconds()
	standardResp.RequestID = request.RequestID

	c.updateMetrics(start, true, standardResp.Usage)
	return standardResp, nil
}

// StreamChatCompletion sends a streaming chat completion request
func (c *Client) StreamChatCompletion(ctx context.Context, request *interfaces.ChatCompletionRequest) (<-chan *interfaces.ChatCompletionStreamResponse, error) {
	// Apply rate limiting
	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx); err != nil {
			c.metrics.RateLimitHits++
			now := time.Now()
			c.metrics.LastRateLimitHit = &now
			return nil, &interfaces.ProviderError{
				Code:      interfaces.ErrorCodeRateLimitExceeded,
				Message:   "Rate limit exceeded",
				Type:      "rate_limit",
				Provider:  "openai",
				Retryable: true,
				OriginalError: err,
			}
		}
	}

	// Convert to OpenAI format with streaming enabled
	openaiReq := c.convertToOpenAIRequest(request)
	openaiReq.Stream = true

	// Make streaming request
	req, err := c.createHTTPRequest(ctx, "POST", "/chat/completions", openaiReq)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.handleHTTPError(err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, c.handleAPIError(resp.StatusCode, body)
	}

	// Create response channel
	respChan := make(chan *interfaces.ChatCompletionStreamResponse, 10)

	// Process streaming response in goroutine
	go func() {
		defer close(respChan)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			
			// Skip empty lines and comments
			if line == "" || !strings.HasPrefix(line, "data: ") {
				continue
			}

			// Remove "data: " prefix
			data := strings.TrimPrefix(line, "data: ")
			
			// Check for end of stream
			if data == "[DONE]" {
				respChan <- &interfaces.ChatCompletionStreamResponse{
					Done: true,
				}
				return
			}

			// Parse JSON chunk
			var chunk OpenAIStreamResponse
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				respChan <- &interfaces.ChatCompletionStreamResponse{
					Error: &interfaces.StreamError{
						Code:    interfaces.ErrorCodeUnknownError,
						Message: "Failed to parse stream chunk",
						Type:    "parse_error",
					},
				}
				return
			}

			// Convert to standard format
			standardChunk := c.convertFromOpenAIStreamResponse(&chunk)
			standardChunk.Provider = "openai"
			standardChunk.RequestID = request.RequestID

			respChan <- standardChunk
		}

		if err := scanner.Err(); err != nil {
			respChan <- &interfaces.ChatCompletionStreamResponse{
				Error: &interfaces.StreamError{
					Code:    interfaces.ErrorCodeNetworkError,
					Message: "Stream reading error",
					Type:    "network_error",
				},
			}
		}
	}()

	return respChan, nil
}

// ValidateCredentials validates the API key
func (c *Client) ValidateCredentials(ctx context.Context) error {
	req := map[string]interface{}{
		"model": "gpt-3.5-turbo",
		"messages": []map[string]string{
			{"role": "user", "content": "test"},
		},
		"max_tokens": 1,
	}

	_, err := c.makeRequest(ctx, "POST", "/chat/completions", req)
	return err
}

// GetModels returns available models
func (c *Client) GetModels(ctx context.Context) ([]interfaces.Model, error) {
	resp, err := c.makeRequest(ctx, "GET", "/models", nil)
	if err != nil {
		return nil, err
	}

	var modelsResp struct {
		Data []OpenAIModel `json:"data"`
	}

	if err := json.Unmarshal(resp, &modelsResp); err != nil {
		return nil, &interfaces.ProviderError{
			Code:    interfaces.ErrorCodeUnknownError,
			Message: "Failed to parse models response",
			Type:    "parse_error",
			Provider: "openai",
			OriginalError: err,
		}
	}

	models := make([]interfaces.Model, 0, len(modelsResp.Data))
	for _, model := range modelsResp.Data {
		standardModel := c.convertFromOpenAIModel(&model)
		models = append(models, standardModel)
	}

	return models, nil
}

// GetUsage returns usage statistics (OpenAI doesn't provide this via API)
func (c *Client) GetUsage(ctx context.Context) (*interfaces.UsageStats, error) {
	return &interfaces.UsageStats{
		TotalRequests: c.metrics.TotalRequests,
		TotalTokens:   c.metrics.TotalTokens,
		TotalCost:     c.metrics.TotalCost,
	}, nil
}

// Close closes any persistent connections
func (c *Client) Close() error {
	if c.rateLimiter != nil {
		c.rateLimiter.Stop()
	}
	return nil
}

// Helper methods

func (c *Client) convertToOpenAIRequest(req *interfaces.ChatCompletionRequest) *OpenAIRequest {
	openaiReq := &OpenAIRequest{
		Model:       req.Model,
		Messages:    make([]OpenAIMessage, len(req.Messages)),
		Stream:      req.Stream,
		User:        req.User,
	}

	// Convert messages
	for i, msg := range req.Messages {
		openaiReq.Messages[i] = OpenAIMessage{
			Role:    msg.Role,
			Content: msg.Content,
			Name:    msg.Name,
		}
	}

	// Copy optional parameters
	if req.MaxTokens != nil {
		openaiReq.MaxTokens = req.MaxTokens
	}
	if req.Temperature != nil {
		openaiReq.Temperature = req.Temperature
	}
	if req.TopP != nil {
		openaiReq.TopP = req.TopP
	}
	if req.PresencePenalty != nil {
		openaiReq.PresencePenalty = req.PresencePenalty
	}
	if req.FrequencyPenalty != nil {
		openaiReq.FrequencyPenalty = req.FrequencyPenalty
	}
	if len(req.Stop) > 0 {
		openaiReq.Stop = req.Stop
	}

	return openaiReq
}

func (c *Client) convertFromOpenAIResponse(resp *OpenAIResponse) *interfaces.ChatCompletionResponse {
	choices := make([]interfaces.Choice, len(resp.Choices))
	for i, choice := range resp.Choices {
		choices[i] = interfaces.Choice{
			Index: choice.Index,
			Message: interfaces.Message{
				Role:    choice.Message.Role,
				Content: choice.Message.Content,
				Name:    choice.Message.Name,
			},
			FinishReason: choice.FinishReason,
		}
	}

	standardResp := &interfaces.ChatCompletionResponse{
		ID:      resp.ID,
		Object:  resp.Object,
		Created: resp.Created,
		Model:   resp.Model,
		Choices: choices,
	}

	if resp.Usage != nil {
		standardResp.Usage = &interfaces.Usage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	return standardResp
}

func (c *Client) convertFromOpenAIStreamResponse(resp *OpenAIStreamResponse) *interfaces.ChatCompletionStreamResponse {
	choices := make([]interfaces.StreamChoice, len(resp.Choices))
	for i, choice := range resp.Choices {
		choices[i] = interfaces.StreamChoice{
			Index: choice.Index,
			Delta: interfaces.MessageDelta{
				Role:    choice.Delta.Role,
				Content: choice.Delta.Content,
			},
			FinishReason: choice.FinishReason,
		}
	}

	return &interfaces.ChatCompletionStreamResponse{
		ID:      resp.ID,
		Object:  resp.Object,
		Created: resp.Created,
		Model:   resp.Model,
		Choices: choices,
	}
}

func (c *Client) convertFromOpenAIModel(model *OpenAIModel) interfaces.Model {
	standardModel := interfaces.Model{
		ID:      model.ID,
		Object:  model.Object,
		Created: model.Created,
		OwnedBy: model.OwnedBy,
	}

	// Add model-specific information
	if contextWindow, exists := c.getContextWindow(model.ID); exists {
		standardModel.ContextWindow = &contextWindow
	}

	standardModel.SupportsStreaming = true
	standardModel.SupportsChat = strings.Contains(model.ID, "gpt") || strings.Contains(model.ID, "chat")
	standardModel.SupportsCompletion = true

	// Add pricing if available
	if inputPrice, outputPrice := c.getModelPricing(model.ID); inputPrice > 0 {
		standardModel.PricePerInputToken = &inputPrice
		standardModel.PricePerOutputToken = &outputPrice
	}

	return standardModel
}

func (c *Client) getContextWindow(modelID string) (int, bool) {
	contextWindows := map[string]int{
		"gpt-4":             8192,
		"gpt-4-0314":        8192,
		"gpt-4-0613":        8192,
		"gpt-4-32k":         32768,
		"gpt-4-32k-0314":    32768,
		"gpt-4-32k-0613":    32768,
		"gpt-3.5-turbo":     4096,
		"gpt-3.5-turbo-0301": 4096,
		"gpt-3.5-turbo-0613": 4096,
		"gpt-3.5-turbo-16k": 16384,
		"gpt-3.5-turbo-16k-0613": 16384,
	}

	window, exists := contextWindows[modelID]
	return window, exists
}

func (c *Client) getModelPricing(modelID string) (inputPrice, outputPrice float64) {
	// Pricing per 1K tokens as of 2024
	pricing := map[string][2]float64{
		"gpt-4":             {0.03, 0.06},
		"gpt-4-0314":        {0.03, 0.06},
		"gpt-4-0613":        {0.03, 0.06},
		"gpt-4-32k":         {0.06, 0.12},
		"gpt-4-32k-0314":    {0.06, 0.12},
		"gpt-4-32k-0613":    {0.06, 0.12},
		"gpt-3.5-turbo":     {0.0015, 0.002},
		"gpt-3.5-turbo-0301": {0.0015, 0.002},
		"gpt-3.5-turbo-0613": {0.0015, 0.002},
		"gpt-3.5-turbo-16k": {0.003, 0.004},
		"gpt-3.5-turbo-16k-0613": {0.003, 0.004},
	}

	if prices, exists := pricing[modelID]; exists {
		return prices[0] / 1000, prices[1] / 1000 // Convert to per-token pricing
	}
	return 0, 0
}

func (c *Client) makeRequest(ctx context.Context, method, endpoint string, body interface{}) ([]byte, error) {
	var attempt int
	var lastErr error

	for attempt = 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.retryDelay * time.Duration(attempt)):
			}
		}

		req, err := c.createHTTPRequest(ctx, method, endpoint, body)
		if err != nil {
			lastErr = err
			continue
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = c.handleHTTPError(err)
			if !lastErr.(*interfaces.ProviderError).IsRetryable() {
				break
			}
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			lastErr = &interfaces.ProviderError{
				Code:    interfaces.ErrorCodeNetworkError,
				Message: "Failed to read response body",
				Type:    "network_error",
				Provider: "openai",
				OriginalError: err,
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return respBody, nil
		}

		lastErr = c.handleAPIError(resp.StatusCode, respBody)
		if !lastErr.(*interfaces.ProviderError).IsRetryable() {
			break
		}
	}

	return nil, lastErr
}

func (c *Client) createHTTPRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Request, error) {
	url := c.baseURL + endpoint

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, &interfaces.ProviderError{
				Code:    interfaces.ErrorCodeInvalidRequest,
				Message: "Failed to marshal request body",
				Type:    "request_error",
				Provider: "openai",
				OriginalError: err,
			}
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, &interfaces.ProviderError{
			Code:    interfaces.ErrorCodeInvalidRequest,
			Message: "Failed to create HTTP request",
			Type:    "request_error",
			Provider: "openai",
			OriginalError: err,
		}
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ai-gateway-poc/1.0")

	if c.organization != "" {
		req.Header.Set("OpenAI-Organization", c.organization)
	}

	return req, nil
}

func (c *Client) handleHTTPError(err error) *interfaces.ProviderError {
	return &interfaces.ProviderError{
		Code:      interfaces.ErrorCodeNetworkError,
		Message:   "HTTP request failed",
		Type:      "network_error",
		Provider:  "openai",
		Retryable: true,
		OriginalError: err,
	}
}

func (c *Client) handleAPIError(statusCode int, body []byte) *interfaces.ProviderError {
	var errorResp OpenAIError
	json.Unmarshal(body, &errorResp)

	providerErr := &interfaces.ProviderError{
		HTTPStatusCode: statusCode,
		Provider:       "openai",
		Details:        string(body),
	}

	if errorResp.Error.Message != "" {
		providerErr.Code = errorResp.Error.Code
		providerErr.Message = errorResp.Error.Message
		providerErr.Type = errorResp.Error.Type
	}

	switch statusCode {
	case http.StatusUnauthorized:
		providerErr.Code = interfaces.ErrorCodeInvalidAPIKey
		providerErr.Message = "Invalid API key"
		providerErr.Type = "authentication_error"
		providerErr.Retryable = false
	case http.StatusPaymentRequired:
		providerErr.Code = interfaces.ErrorCodeQuotaExceeded
		providerErr.Message = "Quota exceeded"
		providerErr.Type = "quota_error"
		providerErr.Retryable = false
	case http.StatusTooManyRequests:
		providerErr.Code = interfaces.ErrorCodeRateLimitExceeded
		providerErr.Message = "Rate limit exceeded"
		providerErr.Type = "rate_limit_error"
		providerErr.Retryable = true
		
		// Parse retry-after header
		if retryAfter := parseRetryAfter(body); retryAfter > 0 {
			providerErr.RetryAfter = &retryAfter
		}
	case http.StatusBadRequest:
		providerErr.Code = interfaces.ErrorCodeInvalidRequest
		providerErr.Retryable = false
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
		providerErr.Code = interfaces.ErrorCodeServerError
		providerErr.Message = "OpenAI server error"
		providerErr.Type = "server_error"
		providerErr.Retryable = true
	default:
		providerErr.Code = interfaces.ErrorCodeUnknownError
		providerErr.Message = "Unknown error"
		providerErr.Type = "unknown_error"
		providerErr.Retryable = false
	}

	return providerErr
}

func parseRetryAfter(body []byte) time.Duration {
	// Try to parse retry-after from error response
	var errorResp struct {
		Error struct {
			RetryAfter int `json:"retry_after"`
		} `json:"error"`
	}
	
	if err := json.Unmarshal(body, &errorResp); err == nil && errorResp.Error.RetryAfter > 0 {
		return time.Duration(errorResp.Error.RetryAfter) * time.Second
	}
	
	return 0
}

func (c *Client) updateMetrics(start time.Time, success bool, usage *interfaces.Usage) {
	c.metrics.TotalRequests++
	
	if success {
		c.metrics.SuccessfulRequests++
	} else {
		c.metrics.FailedRequests++
	}

	// Update latency
	latency := time.Since(start)
	if c.metrics.TotalRequests == 1 {
		c.metrics.AverageLatency = latency
	} else {
		// Running average
		c.metrics.AverageLatency = time.Duration(
			(int64(c.metrics.AverageLatency)*int64(c.metrics.TotalRequests-1) + int64(latency)) / int64(c.metrics.TotalRequests),
		)
	}

	// Update token usage and cost
	if usage != nil {
		c.metrics.TotalTokens += int64(usage.TotalTokens)
		c.metrics.TotalCost += c.estimateCost(usage.TotalTokens)
	}

	now := time.Now()
	c.metrics.LastRequestTime = &now
}

func (c *Client) estimateCost(tokens int) float64 {
	// Use average pricing for estimation (this could be made more sophisticated)
	avgPricePerToken := 0.002 / 1000 // GPT-3.5-turbo average price per token
	return float64(tokens) * avgPricePerToken
} 