package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	// Test loading configuration with defaults
	t.Run("load with defaults", func(t *testing.T) {
		// Set required environment variable for JWT secret
		os.Setenv("GATEWAY_SECURITY_JWT_SECRET", "test-jwt-secret")
		defer os.Unsetenv("GATEWAY_SECURITY_JWT_SECRET")

		cfg, err := Load()
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify default values
		assert.Equal(t, "development", cfg.Environment)
		assert.Equal(t, "info", cfg.LogLevel)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, "ai_gateway", cfg.Database.Database)
		assert.Equal(t, "localhost", cfg.Database.Host)
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "test-jwt-secret", cfg.Security.JWTSecret)
	})

	t.Run("environment variable override", func(t *testing.T) {
		// Set environment variables
		os.Setenv("GATEWAY_ENVIRONMENT", "production")
		os.Setenv("GATEWAY_LOG_LEVEL", "error")
		os.Setenv("GATEWAY_SERVER_PORT", "9000")
		os.Setenv("GATEWAY_SECURITY_JWT_SECRET", "production-jwt-secret")
		defer func() {
			os.Unsetenv("GATEWAY_ENVIRONMENT")
			os.Unsetenv("GATEWAY_LOG_LEVEL")
			os.Unsetenv("GATEWAY_SERVER_PORT")
			os.Unsetenv("GATEWAY_SECURITY_JWT_SECRET")
		}()

		cfg, err := Load()
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify environment variables took effect
		assert.Equal(t, "production", cfg.Environment)
		assert.Equal(t, "error", cfg.LogLevel)
		assert.Equal(t, 9000, cfg.Server.Port)
		assert.Equal(t, "production-jwt-secret", cfg.Security.JWTSecret)
	})

	t.Run("validation failure", func(t *testing.T) {
		// Test with invalid port
		os.Setenv("GATEWAY_SERVER_PORT", "99999")
		os.Setenv("GATEWAY_SECURITY_JWT_SECRET", "test-jwt-secret")
		defer func() {
			os.Unsetenv("GATEWAY_SERVER_PORT")
			os.Unsetenv("GATEWAY_SECURITY_JWT_SECRET")
		}()

		cfg, err := Load()
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "invalid server port")
	})

	t.Run("missing JWT secret", func(t *testing.T) {
		// Ensure JWT secret is not set
		os.Unsetenv("GATEWAY_SECURITY_JWT_SECRET")

		cfg, err := Load()
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "JWT secret is required")
	})
}

func TestDatabaseConfig_GetDSN(t *testing.T) {
	dbConfig := DatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		Username: "testuser",
		Password: "testpass",
		Database: "testdb",
		SSLMode:  "disable",
	}

	expectedDSN := "host=localhost port=5432 user=testuser password=testpass dbname=testdb sslmode=disable"
	actualDSN := dbConfig.GetDSN()

	assert.Equal(t, expectedDSN, actualDSN)
}

func TestRedisConfig_GetRedisAddr(t *testing.T) {
	redisConfig := RedisConfig{
		Host: "localhost",
		Port: 6379,
	}

	expectedAddr := "localhost:6379"
	actualAddr := redisConfig.GetRedisAddr()

	assert.Equal(t, expectedAddr, actualAddr)
}

func TestConfigDefaults(t *testing.T) {
	// Set minimum required environment variables
	os.Setenv("GATEWAY_SECURITY_JWT_SECRET", "test-jwt-secret")
	defer os.Unsetenv("GATEWAY_SECURITY_JWT_SECRET")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Test server defaults
	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 30, cfg.Server.ReadTimeout)
	assert.Equal(t, 30, cfg.Server.WriteTimeout)
	assert.Equal(t, 60, cfg.Server.IdleTimeout)

	// Test database defaults
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "ai_gateway", cfg.Database.Database)
	assert.Equal(t, "disable", cfg.Database.SSLMode)
	assert.Equal(t, 25, cfg.Database.MaxOpenConns)
	assert.Equal(t, 10, cfg.Database.MaxIdleConns)

	// Test cache defaults
	assert.True(t, cfg.Cache.Enabled)
	assert.Equal(t, time.Hour, cfg.Cache.DefaultTTL)
	assert.Equal(t, "100MB", cfg.Cache.MaxSize)
	assert.Equal(t, "gateway:", cfg.Cache.Prefix)

	// Test rate limiting defaults
	assert.True(t, cfg.RateLimit.Enabled)
	assert.Equal(t, 60, cfg.RateLimit.RequestsPerMin)
	assert.Equal(t, 100, cfg.RateLimit.BurstSize)

	// Test monitoring defaults
	assert.True(t, cfg.Monitoring.Enabled)
	assert.Equal(t, 9090, cfg.Monitoring.MetricsPort)
	assert.Equal(t, "/metrics", cfg.Monitoring.MetricsPath)
	assert.Equal(t, "/health", cfg.Monitoring.HealthPath)

	// Test provider defaults
	assert.Equal(t, "https://api.openai.com/v1", cfg.Providers.OpenAI.BaseURL)
	assert.Equal(t, 60*time.Second, cfg.Providers.OpenAI.Timeout)
	assert.Equal(t, 3, cfg.Providers.OpenAI.MaxRetries)
	assert.Equal(t, "https://api.anthropic.com", cfg.Providers.Anthropic.BaseURL)
	assert.Equal(t, 60*time.Second, cfg.Providers.Anthropic.Timeout)
	assert.Equal(t, 3, cfg.Providers.Anthropic.MaxRetries)
} 