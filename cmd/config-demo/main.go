package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"ai-gateway-poc/internal/config"
)

func main() {
	fmt.Println("🔧 AI Gateway Configuration Management Demo")
	fmt.Println("============================================")

	// Demo 1: Basic Configuration Loading
	fmt.Println("\n📋 Demo 1: Basic Configuration Loading")
	demoBasicConfigLoading()

	// Demo 2: Environment-Specific Configuration
	fmt.Println("\n📋 Demo 2: Environment-Specific Configuration")
	demoEnvironmentConfigs()

	// Demo 3: Configuration Validation
	fmt.Println("\n📋 Demo 3: Configuration Validation")
	demoConfigValidation()

	// Demo 4: Secret Resolution
	fmt.Println("\n📋 Demo 4: Secret Resolution")
	demoSecretResolution()

	// Demo 5: Configuration Watching
	fmt.Println("\n📋 Demo 5: Configuration Watching and Hot Reload")
	demoConfigWatching()

	// Demo 6: Configuration Export
	fmt.Println("\n📋 Demo 6: Configuration Export")
	demoConfigExport()

	fmt.Println("\n✅ Configuration management demo completed successfully!")
}

func demoBasicConfigLoading() {
	// Create configuration manager
	manager := config.NewConfigManager("development", "./configs")

	// Load configuration
	cfg, err := manager.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	fmt.Printf("✅ Loaded configuration for environment: %s\n", cfg.Environment)
	fmt.Printf("📊 Server config: %s:%d\n", cfg.Server.Host, cfg.Server.Port)
	fmt.Printf("🔗 Database: %s@%s:%d/%s\n", 
		cfg.Database.Username, cfg.Database.Host, cfg.Database.Port, cfg.Database.Database)
	fmt.Printf("🛡️  Security: CORS=%t, TLS=%s\n", 
		cfg.Security.CorsEnabled, cfg.Security.TLSMinVersion)

	// Show current config
	currentConfig := manager.GetConfig()
	if currentConfig != nil {
		fmt.Printf("📋 Current config environment: %s\n", currentConfig.Environment)
	}
}

func demoEnvironmentConfigs() {
	environments := []string{"development", "staging", "production"}

	for _, env := range environments {
		fmt.Printf("\n🌍 Loading %s environment...\n", env)
		
		manager := config.NewConfigManager(env, "./configs")
		cfg, err := manager.LoadConfig()
		if err != nil {
			fmt.Printf("❌ Failed to load %s config: %v\n", env, err)
			continue
		}

		fmt.Printf("  📊 Server port: %d\n", cfg.Server.Port)
		fmt.Printf("  📝 Log level: %s\n", cfg.LogLevel)
		fmt.Printf("  🔄 Router strategy: %s\n", cfg.Router.Strategy)
		fmt.Printf("  ⏱️  Chat timeout: %v\n", cfg.Timeouts.ChatCompletionTimeout)
		fmt.Printf("  🔐 Circuit breaker: %t\n", cfg.Router.CircuitBreakerEnabled)
	}
}

func demoConfigValidation() {
	// Create a temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "config_demo")
	if err != nil {
		fmt.Printf("❌ Failed to create temp dir: %v\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	manager := config.NewConfigManager("test", tempDir)

	// Test 1: Valid configuration
	fmt.Println("\n🧪 Testing valid configuration...")
	validConfig := `
environment: test
server:
  port: 8080
  host: "localhost"
  read_timeout: 30
  write_timeout: 30
providers:
  openai:
    api_key: "test-key"
    base_url: "https://api.openai.com/v1"
    timeout: 60s
  anthropic:
    api_key: "test-key"
    base_url: "https://api.anthropic.com"
    timeout: 60s
security:
  jwt_secret: "valid-jwt-secret-12345678901234567890"
  jwt_expiry: 24h
  tls_min_version: "1.2"
database:
  host: "localhost"
  port: 5432
  database: "test_db"
  ssl_mode: "disable"
redis:
  host: "localhost"
  port: 6379
  database: 0
`
	validPath := filepath.Join(tempDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validConfig), 0644); err != nil {
		fmt.Printf("❌ Failed to write valid config: %v\n", err)
		return
	}

	if err := manager.ValidateConfigFile(validPath); err != nil {
		fmt.Printf("❌ Valid config failed validation: %v\n", err)
	} else {
		fmt.Printf("✅ Valid configuration passed validation\n")
	}

	// Test 2: Invalid configuration
	fmt.Println("\n🧪 Testing invalid configuration...")
	invalidConfig := `
environment: invalid_environment
server:
  port: 70000  # Invalid port
  host: ""     # Empty host
  read_timeout: -1  # Negative timeout
providers:
  openai:
    api_key: ""  # Empty API key
    base_url: "not-a-url"  # Invalid URL
    timeout: 0s  # Zero timeout
security:
  jwt_secret: "short"  # Too short
  tls_min_version: "0.9"  # Invalid TLS version
database:
  host: ""  # Empty host
  port: 0   # Invalid port
  ssl_mode: "invalid"  # Invalid SSL mode
redis:
  host: ""  # Empty host
  port: 70000  # Invalid port
  database: 16  # Invalid Redis DB number
`
	invalidPath := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidConfig), 0644); err != nil {
		fmt.Printf("❌ Failed to write invalid config: %v\n", err)
		return
	}

	if err := manager.ValidateConfigFile(invalidPath); err != nil {
		fmt.Printf("✅ Invalid configuration correctly failed validation:\n")
		if validationErr, ok := err.(*config.ValidationErrors); ok {
			for i, ve := range validationErr.Errors {
				if i < 5 { // Show first 5 errors
					fmt.Printf("  • %s: %s\n", ve.Field, ve.Message)
				}
			}
			if len(validationErr.Errors) > 5 {
				fmt.Printf("  • ... and %d more errors\n", len(validationErr.Errors)-5)
			}
		}
	} else {
		fmt.Printf("❌ Invalid config unexpectedly passed validation\n")
	}
}

func demoSecretResolution() {
	// Set demo environment variables
	os.Setenv("DEMO_API_KEY", "secret-api-key-from-env")
	os.Setenv("DEMO_JWT_SECRET", "super-secret-jwt-key-12345678901234567890")
	defer func() {
		os.Unsetenv("DEMO_API_KEY")
		os.Unsetenv("DEMO_JWT_SECRET")
	}()

	// Create temp config with secret references
	tempDir, err := os.MkdirTemp("", "secret_demo")
	if err != nil {
		fmt.Printf("❌ Failed to create temp dir: %v\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	configWithSecrets := `
environment: test
providers:
  openai:
    api_key: "${DEMO_API_KEY}"
  anthropic:
    api_key: "${DEMO_API_KEY}"
security:
  jwt_secret: "${DEMO_JWT_SECRET}"
  cors_origins:
    - "${CORS_ORIGIN:-http://localhost:3000}"  # With default value
database:
  password: "${DB_PASSWORD:-default_password}"  # With default value
server:
  host: "localhost"
  port: 8080
redis:
  host: "localhost"
  port: 6379
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configWithSecrets), 0644); err != nil {
		fmt.Printf("❌ Failed to write config: %v\n", err)
		return
	}

	manager := config.NewConfigManager("test", tempDir)
	cfg, err := manager.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config with secrets: %v\n", err)
		return
	}

	fmt.Printf("✅ Secret resolution completed:\n")
	fmt.Printf("  🔑 OpenAI API Key: %s\n", maskSecret(cfg.Providers.OpenAI.APIKey))
	fmt.Printf("  🔑 Anthropic API Key: %s\n", maskSecret(cfg.Providers.Anthropic.APIKey))
	fmt.Printf("  🔐 JWT Secret: %s\n", maskSecret(cfg.Security.JWTSecret))
	fmt.Printf("  🌐 CORS Origins: %v\n", cfg.Security.CorsOrigins)
	fmt.Printf("  🗃️  DB Password: %s\n", maskSecret(cfg.Database.Password))
}

func demoConfigWatching() {
	// Create temporary config
	tempDir, err := os.MkdirTemp("", "watch_demo")
	if err != nil {
		fmt.Printf("❌ Failed to create temp dir: %v\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	initialConfig := `
environment: test
log_level: info
server:
  port: 8080
security:
  jwt_secret: "demo-secret-12345678901234567890"
database:
  host: "localhost"
  port: 5432
redis:
  host: "localhost"
  port: 6379
`
	configPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		fmt.Printf("❌ Failed to write initial config: %v\n", err)
		return
	}

	manager := config.NewConfigManager("test", tempDir)
	cfg, err := manager.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load initial config: %v\n", err)
		return
	}

	fmt.Printf("✅ Initial config loaded - Log level: %s\n", cfg.LogLevel)

	// Add a watcher
	changeDetected := make(chan string, 1)
	manager.AddWatcher(config.ConfigWatcherFunc(func(oldConfig, newConfig *config.Config) error {
		if oldConfig != nil && newConfig != nil {
			diffs := config.GetConfigDiff(oldConfig, newConfig)
			if len(diffs) > 0 {
				changeDetected <- fmt.Sprintf("Config changed: %v", diffs)
			}
		}
		return nil
	}))

	// Start watching
	if err := manager.StartWatching(); err != nil {
		fmt.Printf("❌ Failed to start watching: %v\n", err)
		return
	}
	defer manager.StopWatching()

	fmt.Printf("🔍 Started config watching...\n")

	// Simulate config change
	go func() {
		time.Sleep(100 * time.Millisecond) // Give watcher time to start
		
		updatedConfig := `
environment: test
log_level: debug  # Changed!
server:
  port: 9090      # Changed!
security:
  jwt_secret: "demo-secret-12345678901234567890"
database:
  host: "localhost"
  port: 5432
redis:
  host: "localhost"
  port: 6379
`
		if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
			log.Printf("Failed to update config: %v", err)
		}
	}()

	// Wait for change detection
	select {
	case change := <-changeDetected:
		fmt.Printf("✅ %s\n", change)
	case <-time.After(3 * time.Second):
		fmt.Printf("⏰ No config change detected within timeout\n")
	}
}

func demoConfigExport() {
	// Load existing configuration
	manager := config.NewConfigManager("development", "./configs")
	_, err := manager.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config for export: %v\n", err)
		return
	}

	// Create temp directory for export
	tempDir, err := os.MkdirTemp("", "export_demo")
	if err != nil {
		fmt.Printf("❌ Failed to create temp dir: %v\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	// Export configuration
	exportPath := filepath.Join(tempDir, "exported_config.yaml")
	if err := manager.ExportConfig(exportPath); err != nil {
		fmt.Printf("❌ Failed to export config: %v\n", err)
		return
	}

	fmt.Printf("✅ Configuration exported to: %s\n", exportPath)

	// Read and show first few lines of exported config
	content, err := os.ReadFile(exportPath)
	if err != nil {
		fmt.Printf("❌ Failed to read exported config: %v\n", err)
		return
	}

	fmt.Printf("📄 Exported config preview:\n")
	lines := string(content)
	if len(lines) > 500 {
		lines = lines[:500] + "...\n"
	}
	fmt.Printf("%s", lines)
}

// Helper function to mask secrets for display
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
} 