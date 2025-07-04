package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// ConfigManager handles configuration loading, validation, and hot reloading
type ConfigManager struct {
	config      *Config
	mu          sync.RWMutex
	watchers    []ConfigWatcher
	validator   *ConfigValidator
	environment string
	configPath  string
	viper       *viper.Viper
	ctx         context.Context
	cancel      context.CancelFunc
}

// ConfigWatcher defines the interface for configuration change callbacks
type ConfigWatcher interface {
	OnConfigChange(oldConfig, newConfig *Config) error
}

// ConfigWatcherFunc is a function type that implements ConfigWatcher
type ConfigWatcherFunc func(oldConfig, newConfig *Config) error

func (f ConfigWatcherFunc) OnConfigChange(oldConfig, newConfig *Config) error {
	return f(oldConfig, newConfig)
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(environment string, configPath string) *ConfigManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	v := viper.New()
	
	return &ConfigManager{
		environment: environment,
		configPath:  configPath,
		viper:       v,
		validator:   NewConfigValidator(),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// LoadConfig loads configuration with environment-specific overrides
func (cm *ConfigManager) LoadConfig() (*Config, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Set up Viper configuration
	cm.setupViper()
	
	// Load base configuration
	if err := cm.loadBaseConfig(); err != nil {
		return nil, fmt.Errorf("failed to load base config: %w", err)
	}
	
	// Load environment-specific overrides
	if err := cm.loadEnvironmentConfig(); err != nil {
		return nil, fmt.Errorf("failed to load environment config: %w", err)
	}
	
	// Unmarshal configuration
	var config Config
	if err := cm.viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Set environment if not specified
	if config.Environment == "" {
		config.Environment = cm.environment
	}
	
	// Validate configuration
	if err := cm.validator.Validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	
	// Resolve secrets
	if err := cm.resolveSecrets(&config); err != nil {
		return nil, fmt.Errorf("failed to resolve secrets: %w", err)
	}
	
	cm.config = &config
	return &config, nil
}

// GetConfig returns the current configuration (thread-safe)
func (cm *ConfigManager) GetConfig() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.config == nil {
		return nil
	}
	
	// Return a copy to prevent external modification
	configCopy := *cm.config
	return &configCopy
}

// AddWatcher adds a configuration change watcher
func (cm *ConfigManager) AddWatcher(watcher ConfigWatcher) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.watchers = append(cm.watchers, watcher)
}

// StartWatching starts watching for configuration file changes
func (cm *ConfigManager) StartWatching() error {
	cm.viper.WatchConfig()
	cm.viper.OnConfigChange(func(e fsnotify.Event) {
		log.Printf("Config file changed: %s", e.Name)
		
		if err := cm.reloadConfig(); err != nil {
			log.Printf("Failed to reload config: %v", err)
			return
		}
		
		log.Println("Configuration reloaded successfully")
	})
	
	return nil
}

// StopWatching stops the configuration watcher
func (cm *ConfigManager) StopWatching() {
	if cm.cancel != nil {
		cm.cancel()
	}
}

// ReloadConfig manually reloads the configuration
func (cm *ConfigManager) ReloadConfig() error {
	return cm.reloadConfig()
}

// setupViper configures the Viper instance
func (cm *ConfigManager) setupViper() {
	// Set configuration paths
	if cm.configPath != "" {
		cm.viper.AddConfigPath(cm.configPath)
	}
	cm.viper.AddConfigPath("./configs")
	cm.viper.AddConfigPath(".")
	cm.viper.AddConfigPath("/etc/ai-gateway")
	
	// Set configuration type
	cm.viper.SetConfigType("yaml")
	
	// Environment variable configuration
	cm.viper.SetEnvPrefix("GATEWAY")
	cm.viper.AutomaticEnv()
	
	// Set defaults
	setViperDefaults(cm.viper)
}

// loadBaseConfig loads the base configuration file
func (cm *ConfigManager) loadBaseConfig() error {
	cm.viper.SetConfigName("config")
	
	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("No base config file found, using defaults")
		} else {
			return fmt.Errorf("error reading base config: %w", err)
		}
	} else {
		log.Printf("Using base config file: %s", cm.viper.ConfigFileUsed())
	}
	
	return nil
}

// loadEnvironmentConfig loads environment-specific configuration
func (cm *ConfigManager) loadEnvironmentConfig() error {
	if cm.environment == "" {
		return nil
	}
	
	envConfigName := fmt.Sprintf("config.%s", cm.environment)
	
	// Create a separate viper instance for environment config
	envViper := viper.New()
	envViper.SetConfigName(envConfigName)
	envViper.SetConfigType("yaml")
	
	// Add the same config paths
	if cm.configPath != "" {
		envViper.AddConfigPath(cm.configPath)
	}
	envViper.AddConfigPath("./configs")
	envViper.AddConfigPath(".")
	envViper.AddConfigPath("/etc/ai-gateway")
	
	if err := envViper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("No environment config file found for %s", cm.environment)
			return nil
		}
		return fmt.Errorf("error reading environment config: %w", err)
	}
	
	log.Printf("Using environment config file: %s", envViper.ConfigFileUsed())
	
	// Merge environment config into main viper
	for _, key := range envViper.AllKeys() {
		cm.viper.Set(key, envViper.Get(key))
	}
	
	return nil
}

// reloadConfig reloads the configuration and notifies watchers
func (cm *ConfigManager) reloadConfig() error {
	oldConfig := cm.GetConfig()
	
	// Load new configuration
	newConfig, err := cm.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}
	
	// Notify watchers
	cm.notifyWatchers(oldConfig, newConfig)
	
	return nil
}

// notifyWatchers notifies all registered watchers of configuration changes
func (cm *ConfigManager) notifyWatchers(oldConfig, newConfig *Config) {
	cm.mu.RLock()
	watchers := make([]ConfigWatcher, len(cm.watchers))
	copy(watchers, cm.watchers)
	cm.mu.RUnlock()
	
	for _, watcher := range watchers {
		if err := watcher.OnConfigChange(oldConfig, newConfig); err != nil {
			log.Printf("Config watcher error: %v", err)
		}
	}
}

// resolveSecrets resolves secret references in configuration
func (cm *ConfigManager) resolveSecrets(config *Config) error {
	secretResolver := NewSecretResolver()
	
	// Resolve provider secrets
	if err := secretResolver.ResolveString(&config.Providers.OpenAI.APIKey); err != nil {
		return fmt.Errorf("failed to resolve OpenAI API key: %w", err)
	}
	
	if err := secretResolver.ResolveString(&config.Providers.Anthropic.APIKey); err != nil {
		return fmt.Errorf("failed to resolve Anthropic API key: %w", err)
	}
	
	// Resolve database secrets
	if err := secretResolver.ResolveString(&config.Database.Password); err != nil {
		return fmt.Errorf("failed to resolve database password: %w", err)
	}
	
	if err := secretResolver.ResolveString(&config.Redis.Password); err != nil {
		return fmt.Errorf("failed to resolve Redis password: %w", err)
	}
	
	// Resolve security secrets
	if err := secretResolver.ResolveString(&config.Security.JWTSecret); err != nil {
		return fmt.Errorf("failed to resolve JWT secret: %w", err)
	}
	
	return nil
}

// setViperDefaults sets default configuration values for a Viper instance
func setViperDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("environment", "development")
	v.SetDefault("log_level", "info")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.read_timeout", 30)
	v.SetDefault("server.write_timeout", 30)
	v.SetDefault("server.idle_timeout", 60)

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.database", "ai_gateway")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.conn_max_life", "1h")

	// Redis defaults
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.database", 0)
	v.SetDefault("redis.pool_size", 10)

	// Provider defaults
	v.SetDefault("providers.openai.base_url", "https://api.openai.com/v1")
	v.SetDefault("providers.openai.timeout", "60s")
	v.SetDefault("providers.openai.max_retries", 3)
	v.SetDefault("providers.anthropic.base_url", "https://api.anthropic.com")
	v.SetDefault("providers.anthropic.timeout", "60s")
	v.SetDefault("providers.anthropic.max_retries", 3)

	// Proxy defaults
	v.SetDefault("proxy.enabled", true)
	v.SetDefault("proxy.port", 8443)
	v.SetDefault("proxy.ssl_bump", true)
	v.SetDefault("proxy.target_hosts", []string{"api.openai.com", "api.anthropic.com"})

	// Security defaults
	v.SetDefault("security.jwt_expiry", "24h")
	v.SetDefault("security.api_key_header", "X-API-Key")
	v.SetDefault("security.cors_enabled", true)
	v.SetDefault("security.cors_origins", []string{"*"})
	v.SetDefault("security.tls_min_version", "1.2")

	// Cache defaults
	v.SetDefault("cache.enabled", true)
	v.SetDefault("cache.default_ttl", "1h")
	v.SetDefault("cache.max_size", "100MB")
	v.SetDefault("cache.prefix", "gateway:")

	// Rate limit defaults
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.requests_per_min", 60)
	v.SetDefault("rate_limit.burst_size", 100)
	v.SetDefault("rate_limit.cleanup_interval", "5m")

	// Monitoring defaults
	v.SetDefault("monitoring.enabled", true)
	v.SetDefault("monitoring.metrics_port", 9090)
	v.SetDefault("monitoring.metrics_path", "/metrics")
	v.SetDefault("monitoring.health_path", "/health")

	// Timeout defaults
	v.SetDefault("timeouts.default_request_timeout", "30s")
	v.SetDefault("timeouts.chat_completion_timeout", "60s")
	v.SetDefault("timeouts.streaming_timeout", "300s")
	v.SetDefault("timeouts.health_check_timeout", "10s")
	v.SetDefault("timeouts.provider_connect_timeout", "10s")
	v.SetDefault("timeouts.provider_read_timeout", "45s")
	v.SetDefault("timeouts.provider_write_timeout", "10s")
	v.SetDefault("timeouts.database_query_timeout", "5s")
	v.SetDefault("timeouts.database_connection_timeout", "15s")
	v.SetDefault("timeouts.cache_operation_timeout", "2s")
	v.SetDefault("timeouts.shutdown_timeout", "30s")

	// Router defaults
	v.SetDefault("router.strategy", "round_robin")
	v.SetDefault("router.enable_failover", true)
	v.SetDefault("router.max_retries", 3)
	v.SetDefault("router.failover_timeout", "30s")
	v.SetDefault("router.health_check_interval", "5m")
	v.SetDefault("router.circuit_breaker_enabled", true)
	v.SetDefault("router.circuit_breaker_threshold", 5)
	v.SetDefault("router.circuit_breaker_window", "5m")
}

// GetEnvironment returns the current environment
func (cm *ConfigManager) GetEnvironment() string {
	return cm.environment
}

// GetConfigPath returns the configuration path
func (cm *ConfigManager) GetConfigPath() string {
	return cm.configPath
}

// IsWatching returns true if configuration watching is active
func (cm *ConfigManager) IsWatching() bool {
	select {
	case <-cm.ctx.Done():
		return false
	default:
		return true
	}
}

// ValidateConfigFile validates a configuration file without loading it
func (cm *ConfigManager) ValidateConfigFile(filePath string) error {
	// Create a temporary viper instance
	tempViper := viper.New()
	tempViper.SetConfigFile(filePath)
	
	if err := tempViper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config Config
	if err := tempViper.Unmarshal(&config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	return cm.validator.Validate(&config)
}

// ExportConfig exports the current configuration to a file
func (cm *ConfigManager) ExportConfig(filePath string) error {
	config := cm.GetConfig()
	if config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	
	// Create a new viper instance for export
	exportViper := viper.New()
	
	// Set all configuration values
	exportViper.Set("environment", config.Environment)
	exportViper.Set("log_level", config.LogLevel)
	exportViper.Set("server", config.Server)
	exportViper.Set("database", config.Database)
	exportViper.Set("redis", config.Redis)
	exportViper.Set("providers", config.Providers)
	exportViper.Set("proxy", config.Proxy)
	exportViper.Set("security", config.Security)
	exportViper.Set("cache", config.Cache)
	exportViper.Set("rate_limit", config.RateLimit)
	exportViper.Set("monitoring", config.Monitoring)
	exportViper.Set("router", config.Router)
	exportViper.Set("timeouts", config.Timeouts)
	
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Write configuration file
	if err := exportViper.WriteConfigAs(filePath); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// GetConfigDiff returns the differences between two configurations
func GetConfigDiff(old, new *Config) []string {
	var diffs []string
	
	if old == nil && new == nil {
		return diffs
	}
	
	if old == nil {
		diffs = append(diffs, "Configuration loaded for the first time")
		return diffs
	}
	
	if new == nil {
		diffs = append(diffs, "Configuration unloaded")
		return diffs
	}
	
	// Compare key fields (simplified diff)
	if old.Environment != new.Environment {
		diffs = append(diffs, fmt.Sprintf("Environment: %s -> %s", old.Environment, new.Environment))
	}
	
	if old.LogLevel != new.LogLevel {
		diffs = append(diffs, fmt.Sprintf("LogLevel: %s -> %s", old.LogLevel, new.LogLevel))
	}
	
	if old.Server.Port != new.Server.Port {
		diffs = append(diffs, fmt.Sprintf("Server.Port: %d -> %d", old.Server.Port, new.Server.Port))
	}
	
	// Add more field comparisons as needed...
	
	return diffs
} 