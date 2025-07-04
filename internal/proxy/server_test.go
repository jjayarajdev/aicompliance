package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyServer(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "valid config with defaults",
			config: &Config{
				ListenAddr: "127.0.0.1",
				Port:       8081,
			},
			expectError: false,
		},
		{
			name: "config with TLS enabled",
			config: &Config{
				ListenAddr: "127.0.0.1",
				Port:       8082,
				EnableTLS:  true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel) // Reduce test noise

			server, err := NewProxyServer(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, server)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, server)
				assert.Equal(t, tt.config.ListenAddr, server.config.ListenAddr)
				assert.Equal(t, tt.config.Port, server.config.Port)
			}
		})
	}
}

func TestProxyServer_ConfigDefaults(t *testing.T) {
	config := &Config{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0", server.config.ListenAddr)
	assert.Equal(t, 8080, server.config.Port)
	assert.Equal(t, 30*time.Second, server.config.ReadTimeout)
	assert.Equal(t, 30*time.Second, server.config.WriteTimeout)
	assert.Equal(t, 120*time.Second, server.config.IdleTimeout)
	assert.Equal(t, 10*time.Second, server.config.ConnectTimeout)
}

func TestProxyServer_StartStop(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       0, // Use random port
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test starting the server
	err = server.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, server.IsStarted())

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test that we can't start again
	err = server.Start(ctx)
	assert.Error(t, err)

	// Test stopping the server
	err = server.Stop()
	assert.NoError(t, err)
	assert.False(t, server.IsStarted())

	// Test that stopping again is safe
	err = server.Stop()
	assert.NoError(t, err)
}

func TestProxyServer_GetTargetHost(t *testing.T) {
	config := &Config{
		OpenAIEndpoint:    "https://custom-openai.example.com",
		AnthropicEndpoint: "https://custom-anthropic.example.com",
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "openai.com",
			host:     "api.openai.com",
			expected: "custom-openai.example.com",
		},
		{
			name:     "anthropic.com",
			host:     "api.anthropic.com",
			expected: "custom-anthropic.example.com",
		},
		{
			name:     "openai with port",
			host:     "api.openai.com:443",
			expected: "custom-openai.example.com",
		},
		{
			name:     "unknown host",
			host:     "example.com",
			expected: "",
		},
		{
			name:     "empty host",
			host:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.getTargetHost(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProxyServer_GetTargetHostDefaults(t *testing.T) {
	config := &Config{} // No custom endpoints
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "default openai",
			host:     "api.openai.com",
			expected: "api.openai.com",
		},
		{
			name:     "default anthropic",
			host:     "api.anthropic.com",
			expected: "api.anthropic.com",
		},
		{
			name:     "openai subdomain",
			host:     "chat.openai.com",
			expected: "api.openai.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.getTargetHost(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProxyServer_BuildTargetURL(t *testing.T) {
	config := &Config{
		EnableTLS: true,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	tests := []struct {
		name     string
		host     string
		path     string
		query    string
		expected string
	}{
		{
			name:     "openai chat completions",
			host:     "api.openai.com",
			path:     "/v1/chat/completions",
			query:    "",
			expected: "https://api.openai.com/v1/chat/completions",
		},
		{
			name:     "anthropic messages with query",
			host:     "api.anthropic.com",
			path:     "/v1/messages",
			query:    "model=claude-3",
			expected: "https://api.anthropic.com/v1/messages?model=claude-3",
		},
		{
			name:     "unknown host",
			host:     "example.com",
			path:     "/api",
			query:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host: tt.host,
				URL: &url.URL{
					Path:     tt.path,
					RawQuery: tt.query,
				},
			}

			result := server.buildTargetURL(req)
			if tt.expected == "" {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.expected, result.String())
			}
		})
	}
}

func TestProxyServer_HTTPRequest(t *testing.T) {
	// Create a test server to act as the target
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message":"success","path":"%s"}`, r.URL.Path)
	}))
	defer targetServer.Close()

	config := &Config{
		ListenAddr:        "127.0.0.1",
		Port:              0, // Random port
		OpenAIEndpoint:    targetServer.URL,
		AnthropicEndpoint: targetServer.URL,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.Start(ctx)
	require.NoError(t, err)
	defer server.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test HTTP request through proxy
	client := &http.Client{Timeout: 5 * time.Second}
	
	proxyURL := fmt.Sprintf("http://%s", server.GetAddr())
	req, err := http.NewRequest("GET", proxyURL+"/v1/test", nil)
	require.NoError(t, err)

	// Set the host header to simulate a request to OpenAI
	req.Host = "api.openai.com"

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	expectedBody := `{"message":"success","path":"/v1/test"}`
	assert.Equal(t, expectedBody, string(body))
}

func TestProxyServer_HTTPRequestForbidden(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       0, // Random port
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.Start(ctx)
	require.NoError(t, err)
	defer server.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test request to non-AI provider host
	client := &http.Client{Timeout: 5 * time.Second}
	
	proxyURL := fmt.Sprintf("http://%s", server.GetAddr())
	req, err := http.NewRequest("GET", proxyURL+"/api/test", nil)
	require.NoError(t, err)

	// Set host to non-AI provider
	req.Host = "example.com"

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestProxyServer_HandleConnect(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       0,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	// Test CONNECT request handler directly
	req := httptest.NewRequest("CONNECT", "/", nil)
	req.Host = "api.openai.com:443"
	
	rr := httptest.NewRecorder()

	// This will fail because httptest.NewRecorder doesn't support hijacking
	// but we can test the validation logic
	server.handleConnect(rr, req)

	// Should get internal server error because ResponseWriter doesn't support hijacking
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestProxyServer_HandleConnectForbidden(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       0,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	// Test CONNECT request to non-AI provider
	req := httptest.NewRequest("CONNECT", "/", nil)
	req.Host = "example.com:443"
	
	rr := httptest.NewRecorder()

	server.handleConnect(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestProxyServer_HandleConnectBadRequest(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       0,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	// Test CONNECT request with invalid host
	req := httptest.NewRequest("CONNECT", "/", nil)
	req.Host = "invalid-host-without-port"
	
	rr := httptest.NewRecorder()

	server.handleConnect(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestProxyServer_GetAddr(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       8090, // Use a different port to avoid conflicts
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	// Before starting, should return configured address
	addr := server.GetAddr()
	assert.Equal(t, "127.0.0.1:8090", addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.Start(ctx)
	require.NoError(t, err)
	defer server.Stop()

	// After starting, should return actual listener address
	addr = server.GetAddr()
	assert.Contains(t, addr, "127.0.0.1:")
	assert.Equal(t, "127.0.0.1:8090", addr) // Should be the configured port
}

func TestProxyServer_IsStarted(t *testing.T) {
	config := &Config{
		ListenAddr: "127.0.0.1",
		Port:       8091, // Use a different port to avoid conflicts
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(t, err)

	// Initially not started
	assert.False(t, server.IsStarted())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = server.Start(ctx)
	require.NoError(t, err)

	// Should be started
	assert.True(t, server.IsStarted())

	err = server.Stop()
	require.NoError(t, err)

	// Should be stopped
	assert.False(t, server.IsStarted())
}

// Benchmark tests
func BenchmarkProxyServer_GetTargetHost(b *testing.B) {
	config := &Config{
		OpenAIEndpoint:    "https://custom-openai.example.com",
		AnthropicEndpoint: "https://custom-anthropic.example.com",
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(b, err)

	hosts := []string{
		"api.openai.com",
		"api.anthropic.com",
		"chat.openai.com",
		"example.com",
		"api.openai.com:443",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := hosts[i%len(hosts)]
		server.getTargetHost(host)
	}
}

func BenchmarkProxyServer_BuildTargetURL(b *testing.B) {
	config := &Config{
		EnableTLS: true,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	server, err := NewProxyServer(config, logger)
	require.NoError(b, err)

	req := &http.Request{
		Host: "api.openai.com",
		URL: &url.URL{
			Path:     "/v1/chat/completions",
			RawQuery: "model=gpt-4",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.buildTargetURL(req)
	}
} 