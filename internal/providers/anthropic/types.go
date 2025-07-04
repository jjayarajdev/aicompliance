package anthropic

// Anthropic API request and response types

// AnthropicRequest represents an Anthropic messages request
type AnthropicRequest struct {
	Model       string              `json:"model"`
	MaxTokens   *int                `json:"max_tokens"`
	Messages    []AnthropicMessage  `json:"messages"`
	System      string              `json:"system,omitempty"`
	Temperature *float64            `json:"temperature,omitempty"`
	TopP        *float64            `json:"top_p,omitempty"`
	TopK        *int                `json:"top_k,omitempty"`
	Stream      bool                `json:"stream,omitempty"`
	StopSequences []string          `json:"stop_sequences,omitempty"`
}

// AnthropicMessage represents an Anthropic message
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AnthropicResponse represents an Anthropic messages response
type AnthropicResponse struct {
	ID           string                    `json:"id"`
	Type         string                    `json:"type"`
	Role         string                    `json:"role"`
	Content      []AnthropicContentBlock   `json:"content"`
	Model        string                    `json:"model"`
	StopReason   string                    `json:"stop_reason"`
	StopSequence *string                   `json:"stop_sequence"`
	Usage        *AnthropicUsage           `json:"usage"`
}

// AnthropicContentBlock represents a content block in Anthropic response
type AnthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// AnthropicUsage represents Anthropic usage information
type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// AnthropicStreamEvent represents an Anthropic streaming event
type AnthropicStreamEvent struct {
	Type    string                     `json:"type"`
	Index   int                        `json:"index,omitempty"`
	Delta   *AnthropicStreamDelta      `json:"delta,omitempty"`
	Message *AnthropicResponse         `json:"message,omitempty"`
	Usage   *AnthropicUsage            `json:"usage,omitempty"`
}

// AnthropicStreamDelta represents incremental content from Anthropic
type AnthropicStreamDelta struct {
	Type         string `json:"type,omitempty"`
	Text         string `json:"text,omitempty"`
	StopReason   string `json:"stop_reason,omitempty"`
	StopSequence string `json:"stop_sequence,omitempty"`
}

// AnthropicError represents an error response from Anthropic
type AnthropicError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
} 