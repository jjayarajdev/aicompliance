package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigManager_LoadConfig(t *testing.T) {
	// Create temporary config directory
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test config file
	configContent := `
environment: test
log_level: debug
server:
  port: 9999
  host: "test.host"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "test-key"
    base_url: "https://test.openai.com"
    timeout: 60s
  anthropic:
    api_key: "test-anthropic-key"
    base_url: "https://api.anthropic.com"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "test-jwt-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Test loading configuration
	manager := NewConfigManager("test", tempDir)
	config, err := manager.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify loaded configuration
	if config.Environment != "test" {
		t.Errorf("Expected environment 'test', got '%s'", config.Environment)
	}

	if config.Server.Port != 9999 {
		t.Errorf("Expected port 9999, got %d", config.Server.Port)
	}

	if config.Server.Host != "test.host" {
		t.Errorf("Expected host 'test.host', got '%s'", config.Server.Host)
	}
}

func TestConfigManager_EnvironmentOverrides(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create base config
	baseConfig := `
environment: development
server:
  port: 8080
  host: "0.0.0.0"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "base-api-key"
    timeout: 60s
  anthropic:
    api_key: "base-api-key"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "base-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	baseConfigPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(baseConfigPath, []byte(baseConfig), 0644); err != nil {
		t.Fatalf("Failed to write base config: %v", err)
	}

	// Create environment-specific config
	envConfig := `
server:
  port: 9090
  host: "env.host"
`
	envConfigPath := filepath.Join(tempDir, "config.test.yaml")
	if err := os.WriteFile(envConfigPath, []byte(envConfig), 0644); err != nil {
		t.Fatalf("Failed to write env config: %v", err)
	}

	// Test loading with environment override
	manager := NewConfigManager("test", tempDir)
	config, err := manager.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify environment overrides took effect
	if config.Server.Port != 9090 {
		t.Errorf("Expected port 9090 from env override, got %d", config.Server.Port)
	}

	if config.Server.Host != "env.host" {
		t.Errorf("Expected host 'env.host' from env override, got '%s'", config.Server.Host)
	}

	// Verify base config values are still present
	if config.Environment != "development" {
		t.Errorf("Expected environment 'development' from base, got '%s'", config.Environment)
	}
}

func TestConfigManager_Validation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create invalid config (invalid port)
	invalidConfig := `
environment: test
server:
  port: 70000  # Invalid port
  host: ""     # Invalid empty host
security:
  jwt_secret: "short"  # Too short
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	manager := NewConfigManager("test", tempDir)
	_, err = manager.LoadConfig()
	if err == nil {
		t.Error("Expected validation error, but got none")
	}

	// Verify it's a validation error
	if validationErr, ok := err.(*ValidationErrors); !ok {
		t.Errorf("Expected ValidationErrors, got %T", err)
	} else {
		if len(validationErr.Errors) == 0 {
			t.Error("Expected validation errors, but got none")
		}
	}
}

func TestConfigManager_SecretResolution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Set environment variables for testing
	os.Setenv("TEST_API_KEY", "secret-api-key")
	os.Setenv("TEST_JWT_SECRET", "secret-jwt-key-12345678901234567890")
	defer func() {
		os.Unsetenv("TEST_API_KEY")
		os.Unsetenv("TEST_JWT_SECRET")
	}()

	// Create config with secret references
	configWithSecrets := `
environment: test
server:
  port: 8080
  host: "localhost"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "${TEST_API_KEY}"
    timeout: 60s
  anthropic:
    api_key: "${TEST_API_KEY}"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "${TEST_JWT_SECRET}"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configWithSecrets), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	manager := NewConfigManager("test", tempDir)
	config, err := manager.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify secrets were resolved
	if config.Providers.OpenAI.APIKey != "secret-api-key" {
		t.Errorf("Expected resolved API key, got '%s'", config.Providers.OpenAI.APIKey)
	}

	if config.Security.JWTSecret != "secret-jwt-key-12345678901234567890" {
		t.Errorf("Expected resolved JWT secret, got '%s'", config.Security.JWTSecret)
	}
}

func TestConfigManager_Watcher(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create initial config
	initialConfig := `
environment: test
log_level: info
server:
  port: 8080
  host: "localhost"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "test-api-key"
    timeout: 60s
  anthropic:
    api_key: "test-api-key"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "test-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	manager := NewConfigManager("test", tempDir)
	_, err = manager.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load initial config: %v", err)
	}

	// Add watcher
	watcherCalled := make(chan bool, 1)
	manager.AddWatcher(ConfigWatcherFunc(func(oldConfig, newConfig *Config) error {
		if oldConfig.LogLevel != newConfig.LogLevel {
			watcherCalled <- true
		}
		return nil
	}))

	// Start watching
	if err := manager.StartWatching(); err != nil {
		t.Fatalf("Failed to start watching: %v", err)
	}
	defer manager.StopWatching()

	// Update config file
	updatedConfig := `
environment: test
log_level: debug  # Changed from info to debug
server:
  port: 8080
  host: "localhost"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "test-api-key"
    timeout: 60s
  anthropic:
    api_key: "test-api-key"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "test-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Wait for watcher to be called
	select {
	case <-watcherCalled:
		// Success - watcher was called
	case <-time.After(2 * time.Second):
		t.Error("Config watcher was not called within timeout")
	}
}

func TestConfigManager_ValidateConfigFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewConfigManager("test", tempDir)

	// Test valid config
	validConfig := `
environment: test
server:
  port: 8080
  host: "localhost"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "test-api-key"
    timeout: 60s
  anthropic:
    api_key: "test-api-key"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "valid-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	validConfigPath := filepath.Join(tempDir, "valid.yaml")
	if err := os.WriteFile(validConfigPath, []byte(validConfig), 0644); err != nil {
		t.Fatalf("Failed to write valid config: %v", err)
	}

	if err := manager.ValidateConfigFile(validConfigPath); err != nil {
		t.Errorf("Valid config failed validation: %v", err)
	}

	// Test invalid config
	invalidConfig := `
environment: invalid_env
server:
  port: -1
  host: ""
`
	invalidConfigPath := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidConfigPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}

	if err := manager.ValidateConfigFile(invalidConfigPath); err == nil {
		t.Error("Invalid config passed validation")
	}
}

func TestConfigManager_ExportConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create and load config
	configContent := `
environment: test
server:
  port: 8080
  host: "localhost"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "test-api-key"
    timeout: 60s
  anthropic:
    api_key: "test-api-key"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "test-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	manager := NewConfigManager("test", tempDir)
	_, err = manager.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Export config
	exportPath := filepath.Join(tempDir, "exported.yaml")
	if err := manager.ExportConfig(exportPath); err != nil {
		t.Fatalf("Failed to export config: %v", err)
	}

	// Verify exported file exists
	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Error("Exported config file does not exist")
	}
}

func TestGetConfigDiff(t *testing.T) {
	oldConfig := &Config{
		Environment: "test",
		LogLevel:    "info",
		Server: ServerConfig{
			Port: 8080,
			Host: "localhost",
		},
	}

	newConfig := &Config{
		Environment: "production",
		LogLevel:    "warn",
		Server: ServerConfig{
			Port: 8443,
			Host: "localhost",
		},
	}

	diffs := GetConfigDiff(oldConfig, newConfig)
	
	if len(diffs) == 0 {
		t.Error("Expected configuration differences, but got none")
	}

	// Check that environment and log level changes are detected
	foundEnvDiff := false
	foundLogDiff := false
	foundPortDiff := false

	for _, diff := range diffs {
		if diff == "Environment: test -> production" {
			foundEnvDiff = true
		}
		if diff == "LogLevel: info -> warn" {
			foundLogDiff = true
		}
		if diff == "Server.Port: 8080 -> 8443" {
			foundPortDiff = true
		}
	}

	if !foundEnvDiff {
		t.Error("Environment difference not detected")
	}
	if !foundLogDiff {
		t.Error("LogLevel difference not detected")
	}
	if !foundPortDiff {
		t.Error("Server.Port difference not detected")
	}
}

func TestConfigManager_ThreadSafety(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `
environment: test
server:
  port: 8080
  host: "localhost"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
providers:
  openai:
    api_key: "test-api-key"
    timeout: 60s
  anthropic:
    api_key: "test-api-key"
    timeout: 60s
proxy:
  enabled: false
security:
  jwt_secret: "test-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
timeouts:
  default_request_timeout: "30s"
  chat_completion_timeout: "60s"
  streaming_timeout: "300s"
  health_check_timeout: "10s"
  provider_connect_timeout: "10s"
  provider_read_timeout: "45s"
  provider_write_timeout: "10s"
  database_query_timeout: "5s"
  database_connection_timeout: "15s"
  cache_operation_timeout: "2s"
  shutdown_timeout: "30s"
router:
  strategy: "round_robin"
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	manager := NewConfigManager("test", tempDir)
	_, err = manager.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test concurrent access
	done := make(chan bool)
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer func() { done <- true }()
			
			// Concurrent reads
			for j := 0; j < 100; j++ {
				config := manager.GetConfig()
				if config == nil {
					t.Error("Got nil config")
				}
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
} 