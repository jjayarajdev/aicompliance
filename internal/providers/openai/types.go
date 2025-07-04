package openai

// OpenAI API request and response types

// OpenAIRequest represents an OpenAI chat completion request
type OpenAIRequest struct {
	Model            string                 `json:"model"`
	Messages         []OpenAIMessage        `json:"messages"`
	MaxTokens        *int                   `json:"max_tokens,omitempty"`
	Temperature      *float64               `json:"temperature,omitempty"`
	TopP             *float64               `json:"top_p,omitempty"`
	N                *int                   `json:"n,omitempty"`
	Stream           bool                   `json:"stream,omitempty"`
	Stop             []string               `json:"stop,omitempty"`
	PresencePenalty  *float64               `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float64               `json:"frequency_penalty,omitempty"`
	LogitBias        map[string]interface{} `json:"logit_bias,omitempty"`
	User             string                 `json:"user,omitempty"`
}

// OpenAIMessage represents an OpenAI message
type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

// OpenAIResponse represents an OpenAI chat completion response
type OpenAIResponse struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Created int64           `json:"created"`
	Model   string          `json:"model"`
	Choices []OpenAIChoice  `json:"choices"`
	Usage   *OpenAIUsage    `json:"usage,omitempty"`
}

// OpenAIChoice represents an OpenAI choice
type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

// OpenAIUsage represents OpenAI usage information
type OpenAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// OpenAIStreamResponse represents an OpenAI streaming response chunk
type OpenAIStreamResponse struct {
	ID      string                `json:"id"`
	Object  string                `json:"object"`
	Created int64                 `json:"created"`
	Model   string                `json:"model"`
	Choices []OpenAIStreamChoice  `json:"choices"`
}

// OpenAIStreamChoice represents an OpenAI streaming choice
type OpenAIStreamChoice struct {
	Index        int                 `json:"index"`
	Delta        OpenAIMessageDelta  `json:"delta"`
	FinishReason *string             `json:"finish_reason"`
}

// OpenAIMessageDelta represents incremental message content from OpenAI
type OpenAIMessageDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// OpenAIError represents an error response from OpenAI
type OpenAIError struct {
	Error struct {
		Message string      `json:"message"`
		Type    string      `json:"type"`
		Param   interface{} `json:"param"`
		Code    string      `json:"code"`
	} `json:"error"`
}

// OpenAIModel represents an OpenAI model
type OpenAIModel struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	OwnedBy string   `json:"owned_by"`
	Root    string   `json:"root"`
	Parent  *string  `json:"parent"`
}

// OpenAIModelsResponse represents the response from the models endpoint
type OpenAIModelsResponse struct {
	Object string        `json:"object"`
	Data   []OpenAIModel `json:"data"`
} 