package database

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
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
				PostgreSQL: PostgreSQLConfig{},
				Redis:      RedisConfig{},
			},
			expectError: false,
		},
		{
			name: "config with custom values",
			config: &Config{
				PostgreSQL: PostgreSQLConfig{
					Host:     "custom-host",
					Port:     5433,
					Username: "custom-user",
					Database: "custom-db",
				},
				Redis: RedisConfig{
					Host:     "redis-host",
					Port:     6380,
					Database: 1,
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel) // Reduce test noise

			manager, err := NewManager(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
				assert.Equal(t, tt.config, manager.config)
				assert.Equal(t, logger, manager.logger)
			}
		})
	}
}

func TestManager_ConfigDefaults(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis:      RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	// Test PostgreSQL defaults
	assert.Equal(t, "localhost", manager.config.PostgreSQL.Host)
	assert.Equal(t, 5432, manager.config.PostgreSQL.Port)
	assert.Equal(t, "prefer", manager.config.PostgreSQL.SSLMode)
	assert.Equal(t, 25, manager.config.PostgreSQL.MaxOpenConns)
	assert.Equal(t, 5, manager.config.PostgreSQL.MaxIdleConns)
	assert.Equal(t, 5*time.Minute, manager.config.PostgreSQL.ConnMaxLifetime)
	assert.Equal(t, 5*time.Minute, manager.config.PostgreSQL.ConnMaxIdleTime)
	assert.Equal(t, 10*time.Second, manager.config.PostgreSQL.ConnectTimeout)

	// Test Redis defaults
	assert.Equal(t, "localhost", manager.config.Redis.Host)
	assert.Equal(t, 6379, manager.config.Redis.Port)
	assert.Equal(t, 10, manager.config.Redis.PoolSize)
	assert.Equal(t, 2, manager.config.Redis.MinIdleConns)
	assert.Equal(t, 30*time.Minute, manager.config.Redis.MaxConnAge)
	assert.Equal(t, 5*time.Second, manager.config.Redis.PoolTimeout)
	assert.Equal(t, 5*time.Minute, manager.config.Redis.IdleTimeout)
	assert.Equal(t, 1*time.Minute, manager.config.Redis.IdleCheckFrequency)
	assert.Equal(t, 5*time.Second, manager.config.Redis.DialTimeout)
	assert.Equal(t, 3*time.Second, manager.config.Redis.ReadTimeout)
	assert.Equal(t, 3*time.Second, manager.config.Redis.WriteTimeout)
}

func TestManager_IsConnected(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis:      RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	// Initially not connected
	assert.False(t, manager.IsConnected())

	// Simulate connections (without actually connecting to real databases)
	// This is a unit test, so we don't want external dependencies
	assert.Nil(t, manager.GetPostgreSQL())
	assert.Nil(t, manager.GetRedis())
}

func TestManager_GetStats_NoConnections(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis:      RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	stats, err := manager.GetStats()
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Should have empty stats when no connections
	assert.NotContains(t, stats, "postgresql")
	assert.NotContains(t, stats, "redis")
}

func TestManager_Disconnect_NoConnections(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis:      RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	// Should not error when disconnecting with no connections
	err = manager.Disconnect()
	assert.NoError(t, err)
}

func TestManager_HealthCheck_NoConnections(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis:      RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Should fail when no connections
	err = manager.HealthCheck(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PostgreSQL health check failed")
}

func TestManager_ConnectPostgreSQL_InvalidConfig(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{
			Host:     "nonexistent-host",
			Port:     5432,
			Username: "invalid-user",
			Password: "invalid-password",
			Database: "invalid-db",
		},
		Redis: RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Should fail to connect to invalid PostgreSQL
	err = manager.connectPostgreSQL(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to PostgreSQL")
}

func TestManager_ConnectRedis_InvalidConfig(t *testing.T) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis: RedisConfig{
			Host: "nonexistent-redis-host",
			Port: 6379,
		},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Should fail to connect to invalid Redis
	err = manager.connectRedis(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to ping Redis")
}

func TestPostgreSQLConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config PostgreSQLConfig
		valid  bool
	}{
		{
			name: "valid config",
			config: PostgreSQLConfig{
				Host:     "localhost",
				Port:     5432,
				Username: "user",
				Password: "password",
				Database: "testdb",
			},
			valid: true,
		},
		{
			name: "missing required fields",
			config: PostgreSQLConfig{
				Host: "localhost",
				Port: 5432,
				// Missing username, password, database
			},
			valid: false,
		},
		{
			name: "invalid port",
			config: PostgreSQLConfig{
				Host:     "localhost",
				Port:     0,
				Username: "user",
				Password: "password",
				Database: "testdb",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that config values are preserved
			config := &Config{
				PostgreSQL: tt.config,
				Redis:      RedisConfig{},
			}

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			manager, err := NewManager(config, logger)
			require.NoError(t, err)

			if tt.valid {
				// Valid configs should have values preserved (with defaults filled)
				if tt.config.Host != "" {
					assert.Equal(t, tt.config.Host, manager.config.PostgreSQL.Host)
				}
				if tt.config.Port != 0 {
					assert.Equal(t, tt.config.Port, manager.config.PostgreSQL.Port)
				}
			}
		})
	}
}

func TestRedisConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config RedisConfig
		valid  bool
	}{
		{
			name: "valid config",
			config: RedisConfig{
				Host:     "localhost",
				Port:     6379,
				Database: 0,
			},
			valid: true,
		},
		{
			name: "custom database",
			config: RedisConfig{
				Host:     "localhost",
				Port:     6379,
				Database: 5,
			},
			valid: true,
		},
		{
			name: "with password",
			config: RedisConfig{
				Host:     "localhost",
				Port:     6379,
				Password: "secret",
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				PostgreSQL: PostgreSQLConfig{},
				Redis:      tt.config,
			}

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			manager, err := NewManager(config, logger)
			require.NoError(t, err)

			if tt.valid {
				// Valid configs should have values preserved (with defaults filled)
				if tt.config.Host != "" {
					assert.Equal(t, tt.config.Host, manager.config.Redis.Host)
				}
				if tt.config.Port != 0 {
					assert.Equal(t, tt.config.Port, manager.config.Redis.Port)
				}
				assert.Equal(t, tt.config.Database, manager.config.Redis.Database)
			}
		})
	}
}

// Benchmark tests
func BenchmarkNewManager(b *testing.B) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{
			Host:     "localhost",
			Port:     5432,
			Username: "user",
			Password: "password",
			Database: "testdb",
		},
		Redis: RedisConfig{
			Host: "localhost",
			Port: 6379,
		},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewManager(config, logger)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkManager_GetStats(b *testing.B) {
	config := &Config{
		PostgreSQL: PostgreSQLConfig{},
		Redis:      RedisConfig{},
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	manager, err := NewManager(config, logger)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.GetStats()
		if err != nil {
			b.Fatal(err)
		}
	}
} 