package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name:      "nil config",
			config:    nil,
			expectErr: true,
		},
		{
			name: "valid json config",
			config: &Config{
				Level:  "info",
				Format: "json",
				Output: "stdout",
			},
			expectErr: false,
		},
		{
			name: "valid text config",
			config: &Config{
				Level:  "debug",
				Format: "text",
				Output: "stderr",
			},
			expectErr: false,
		},
		{
			name: "invalid log level",
			config: &Config{
				Level:  "invalid",
				Format: "json",
				Output: "stdout",
			},
			expectErr: true,
		},
		{
			name: "invalid format",
			config: &Config{
				Level:  "info",
				Format: "invalid",
				Output: "stdout",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := New(tt.config)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, logger)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestLoggerWithComponent(t *testing.T) {
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
		Fields: map[string]string{
			"service": "test-service",
		},
		ComponentLevels: map[string]string{
			"database": "warn",
		},
	}

	logger, err := New(config)
	require.NoError(t, err)

	// Test component without specific level
	serverLogger := logger.WithComponent("server")
	assert.Equal(t, logrus.InfoLevel, serverLogger.GetLevel())
	assert.Equal(t, "server", serverLogger.fields["component"])

	// Test component with specific level
	dbLogger := logger.WithComponent("database")
	assert.Equal(t, logrus.WarnLevel, dbLogger.GetLevel())
	assert.Equal(t, "database", dbLogger.fields["component"])
}

func TestLoggerWithContext(t *testing.T) {
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger, err := New(config)
	require.NoError(t, err)

	// Create context with values
	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIDKey, "test-request-123")
	ctx = context.WithValue(ctx, UserIDKey, "user-456")
	ctx = context.WithValue(ctx, ComponentKey, "test-component")
	ctx = context.WithValue(ctx, OperationKey, "test-operation")

	entry := logger.WithContext(ctx)

	// Check that context values are included in fields
	assert.Equal(t, "test-request-123", entry.Data["request_id"])
	assert.Equal(t, "user-456", entry.Data["user_id"])
	assert.Equal(t, "test-component", entry.Data["component"])
	assert.Equal(t, "test-operation", entry.Data["operation"])
}

func TestLoggerWithFields(t *testing.T) {
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
		Fields: map[string]string{
			"service": "test-service",
			"version": "1.0.0",
		},
	}

	logger, err := New(config)
	require.NoError(t, err)

	fields := logrus.Fields{
		"custom_field": "custom_value",
		"number":       42,
	}

	entry := logger.WithFields(fields)

	// Check that both base fields and custom fields are present
	assert.Equal(t, "test-service", entry.Data["service"])
	assert.Equal(t, "1.0.0", entry.Data["version"])
	assert.Equal(t, "custom_value", entry.Data["custom_field"])
	assert.Equal(t, 42, entry.Data["number"])
}

func TestLoggerPerformance(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger, err := New(config)
	require.NoError(t, err)
	logger.SetOutput(&buf)

	duration := 100 * time.Millisecond
	entry := logger.Performance("test_operation", duration)
	entry.Info("Performance test")

	// Parse logged JSON
	var logData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &logData)
	require.NoError(t, err)

	assert.Equal(t, "test_operation", logData["operation"])
	assert.Equal(t, float64(100), logData["duration_ms"])
	assert.Equal(t, true, logData["performance_log"])
}

func TestLoggerSecurity(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger, err := New(config)
	require.NoError(t, err)
	logger.SetOutput(&buf)

	entry := logger.Security("authentication_failure")
	entry.Warn("Security event detected")

	// Parse logged JSON
	var logData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &logData)
	require.NoError(t, err)

	assert.Equal(t, "authentication_failure", logData["security_event"])
	assert.Equal(t, true, logData["security_log"])
}

func TestLoggerAudit(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger, err := New(config)
	require.NoError(t, err)
	logger.SetOutput(&buf)

	entry := logger.Audit("policy_update")
	entry.Info("Audit event")

	// Parse logged JSON
	var logData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &logData)
	require.NoError(t, err)

	assert.Equal(t, "policy_update", logData["audit_action"])
	assert.Equal(t, true, logData["audit_log"])
}

func TestFileLogging(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "file",
		File: FileConfig{
			Enabled:    true,
			Path:       logFile,
			MaxSize:    1,
			MaxBackups: 2,
			MaxAge:     1,
			Compress:   false,
		},
	}

	logger, err := New(config)
	require.NoError(t, err)

	// Log a message
	logger.Info("Test log message")

	// Wait a moment for file write
	time.Sleep(100 * time.Millisecond)

	// Check if file exists and contains our message
	assert.FileExists(t, logFile)

	content, err := os.ReadFile(logFile)
	require.NoError(t, err)

	assert.Contains(t, string(content), "Test log message")
}

func TestGlobalLogger(t *testing.T) {
	// Test default global logger
	defaultLogger := GetGlobalLogger()
	assert.NotNil(t, defaultLogger)

	// Set a custom global logger
	config := &Config{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
		Fields: map[string]string{
			"global": "true",
		},
	}

	customLogger, err := New(config)
	require.NoError(t, err)

	SetGlobalLogger(customLogger)

	// Test that global logger was set
	globalLogger := GetGlobalLogger()
	assert.Equal(t, customLogger, globalLogger)
	assert.Equal(t, "true", globalLogger.fields["global"])

	// Test global convenience functions
	var buf bytes.Buffer
	globalLogger.SetOutput(&buf)

	Info("Test global info")
	
	assert.Contains(t, buf.String(), "Test global info")
}

func TestLogOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"stdout", "stdout"},
		{"stderr", "stderr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Level:  "info",
				Format: "json",
				Output: tt.output,
			}

			logger, err := New(config)
			assert.NoError(t, err)
			assert.NotNil(t, logger)
		})
	}
}

func TestLogLevels(t *testing.T) {
	levels := []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}

	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			config := &Config{
				Level:  level,
				Format: "json",
				Output: "stdout",
			}

			logger, err := New(config)
			assert.NoError(t, err)
			assert.NotNil(t, logger)
		})
	}
}

func TestJSONStructuredLogging(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
		Fields: map[string]string{
			"service": "test-service",
			"version": "1.0.0",
		},
	}

	logger, err := New(config)
	require.NoError(t, err)
	logger.SetOutput(&buf)

	// Log with various field types
	logger.WithFields(logrus.Fields{
		"string_field":  "test_value",
		"number_field":  42,
		"boolean_field": true,
		"time_field":    time.Now(),
	}).Info("Structured log test")

	// Parse logged JSON
	var logData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &logData)
	require.NoError(t, err)

	// Verify structure
	assert.Equal(t, "info", logData["level"])
	assert.Equal(t, "Structured log test", logData["message"])
	assert.Equal(t, "test-service", logData["service"])
	assert.Equal(t, "1.0.0", logData["version"])
	assert.Equal(t, "test_value", logData["string_field"])
	assert.Equal(t, float64(42), logData["number_field"])
	assert.Equal(t, true, logData["boolean_field"])
	assert.NotEmpty(t, logData["timestamp"])
}

func TestTextLogging(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:  "info",
		Format: "text",
		Output: "stdout",
	}

	logger, err := New(config)
	require.NoError(t, err)
	logger.SetOutput(&buf)

	logger.Info("Text log test")

	output := buf.String()
	assert.Contains(t, output, "Text log test")
	assert.Contains(t, output, "level=info")
}

func TestContextFunctions(t *testing.T) {
	ctx := context.Background()

	// Test ContextWithUserID
	ctx = ContextWithUserID(ctx, "user123")
	assert.Equal(t, "user123", ctx.Value(UserIDKey))

	// Test ContextWithComponent
	ctx = ContextWithComponent(ctx, "auth")
	assert.Equal(t, "auth", ctx.Value(ComponentKey))

	// Test ContextWithOperation
	ctx = ContextWithOperation(ctx, "login")
	assert.Equal(t, "login", ctx.Value(OperationKey))

	// Test ContextWithFields
	fields := map[string]interface{}{
		"session_id": "sess456",
		"ip_address": "192.168.1.1",
	}
	ctx = ContextWithFields(ctx, fields)
	assert.Equal(t, "sess456", ctx.Value(ContextKey("session_id")))
	assert.Equal(t, "192.168.1.1", ctx.Value(ContextKey("ip_address")))
}

// Benchmark tests
func BenchmarkLoggerWithFields(b *testing.B) {
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger, _ := New(config)
	logger.SetOutput(io.Discard)

	fields := logrus.Fields{
		"user_id":    "user123",
		"request_id": "req456",
		"operation":  "test_operation",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithFields(fields).Info("Benchmark test message")
	}
}

func BenchmarkContextLogging(b *testing.B) {
	config := &Config{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	}

	logger, _ := New(config)
	logger.SetOutput(io.Discard)

	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIDKey, "req123")
	ctx = context.WithValue(ctx, UserIDKey, "user456")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithContext(ctx).Info("Benchmark context test")
	}
} 