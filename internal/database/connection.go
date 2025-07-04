package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/sirupsen/logrus"
)

// Manager handles database connections for PostgreSQL and Redis
type Manager struct {
	config *Config
	logger *logrus.Logger
	
	// Database connections
	PostgreSQL *sqlx.DB
	Redis      *redis.Client
}

// Config holds database configuration
type Config struct {
	// PostgreSQL configuration
	PostgreSQL PostgreSQLConfig `yaml:"postgresql" mapstructure:"postgresql"`
	
	// Redis configuration
	Redis RedisConfig `yaml:"redis" mapstructure:"redis"`
}

// PostgreSQLConfig holds PostgreSQL-specific configuration
type PostgreSQLConfig struct {
	Host            string        `yaml:"host" mapstructure:"host"`
	Port            int           `yaml:"port" mapstructure:"port"`
	Username        string        `yaml:"username" mapstructure:"username"`
	Password        string        `yaml:"password" mapstructure:"password"`
	Database        string        `yaml:"database" mapstructure:"database"`
	SSLMode         string        `yaml:"ssl_mode" mapstructure:"ssl_mode"`
	MaxOpenConns    int           `yaml:"max_open_conns" mapstructure:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" mapstructure:"conn_max_idle_time"`
	ConnectTimeout  time.Duration `yaml:"connect_timeout" mapstructure:"connect_timeout"`
}

// RedisConfig holds Redis-specific configuration
type RedisConfig struct {
	Host               string        `yaml:"host" mapstructure:"host"`
	Port               int           `yaml:"port" mapstructure:"port"`
	Password           string        `yaml:"password" mapstructure:"password"`
	Database           int           `yaml:"database" mapstructure:"database"`
	PoolSize           int           `yaml:"pool_size" mapstructure:"pool_size"`
	MinIdleConns       int           `yaml:"min_idle_conns" mapstructure:"min_idle_conns"`
	MaxConnAge         time.Duration `yaml:"max_conn_age" mapstructure:"max_conn_age"`
	PoolTimeout        time.Duration `yaml:"pool_timeout" mapstructure:"pool_timeout"`
	IdleTimeout        time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout"`
	IdleCheckFrequency time.Duration `yaml:"idle_check_frequency" mapstructure:"idle_check_frequency"`
	DialTimeout        time.Duration `yaml:"dial_timeout" mapstructure:"dial_timeout"`
	ReadTimeout        time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout       time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`
}

// NewManager creates a new database manager
func NewManager(config *Config, logger *logrus.Logger) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("database config cannot be nil")
	}
	
	if logger == nil {
		logger = logrus.New()
	}

	// Set default values for PostgreSQL
	if config.PostgreSQL.Host == "" {
		config.PostgreSQL.Host = "localhost"
	}
	if config.PostgreSQL.Port == 0 {
		config.PostgreSQL.Port = 5432
	}
	if config.PostgreSQL.SSLMode == "" {
		config.PostgreSQL.SSLMode = "prefer"
	}
	if config.PostgreSQL.MaxOpenConns == 0 {
		config.PostgreSQL.MaxOpenConns = 25
	}
	if config.PostgreSQL.MaxIdleConns == 0 {
		config.PostgreSQL.MaxIdleConns = 5
	}
	if config.PostgreSQL.ConnMaxLifetime == 0 {
		config.PostgreSQL.ConnMaxLifetime = 5 * time.Minute
	}
	if config.PostgreSQL.ConnMaxIdleTime == 0 {
		config.PostgreSQL.ConnMaxIdleTime = 5 * time.Minute
	}
	if config.PostgreSQL.ConnectTimeout == 0 {
		config.PostgreSQL.ConnectTimeout = 10 * time.Second
	}

	// Set default values for Redis
	if config.Redis.Host == "" {
		config.Redis.Host = "localhost"
	}
	if config.Redis.Port == 0 {
		config.Redis.Port = 6379
	}
	if config.Redis.PoolSize == 0 {
		config.Redis.PoolSize = 10
	}
	if config.Redis.MinIdleConns == 0 {
		config.Redis.MinIdleConns = 2
	}
	if config.Redis.MaxConnAge == 0 {
		config.Redis.MaxConnAge = 30 * time.Minute
	}
	if config.Redis.PoolTimeout == 0 {
		config.Redis.PoolTimeout = 5 * time.Second
	}
	if config.Redis.IdleTimeout == 0 {
		config.Redis.IdleTimeout = 5 * time.Minute
	}
	if config.Redis.IdleCheckFrequency == 0 {
		config.Redis.IdleCheckFrequency = 1 * time.Minute
	}
	if config.Redis.DialTimeout == 0 {
		config.Redis.DialTimeout = 5 * time.Second
	}
	if config.Redis.ReadTimeout == 0 {
		config.Redis.ReadTimeout = 3 * time.Second
	}
	if config.Redis.WriteTimeout == 0 {
		config.Redis.WriteTimeout = 3 * time.Second
	}

	manager := &Manager{
		config: config,
		logger: logger,
	}

	return manager, nil
}

// Connect establishes connections to both PostgreSQL and Redis
func (m *Manager) Connect(ctx context.Context) error {
	// Connect to PostgreSQL
	if err := m.connectPostgreSQL(ctx); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Connect to Redis
	if err := m.connectRedis(ctx); err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	m.logger.Info("Successfully connected to all databases")
	return nil
}

// connectPostgreSQL establishes PostgreSQL connection
func (m *Manager) connectPostgreSQL(ctx context.Context) error {
	m.logger.WithFields(logrus.Fields{
		"host":     m.config.PostgreSQL.Host,
		"port":     m.config.PostgreSQL.Port,
		"database": m.config.PostgreSQL.Database,
		"user":     m.config.PostgreSQL.Username,
	}).Info("Connecting to PostgreSQL")

	// Build connection string
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		m.config.PostgreSQL.Host,
		m.config.PostgreSQL.Port,
		m.config.PostgreSQL.Username,
		m.config.PostgreSQL.Password,
		m.config.PostgreSQL.Database,
		m.config.PostgreSQL.SSLMode,
		int(m.config.PostgreSQL.ConnectTimeout.Seconds()),
	)

	// Open database connection
	db, err := sqlx.ConnectContext(ctx, "postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(m.config.PostgreSQL.MaxOpenConns)
	db.SetMaxIdleConns(m.config.PostgreSQL.MaxIdleConns)
	db.SetConnMaxLifetime(m.config.PostgreSQL.ConnMaxLifetime)
	db.SetConnMaxIdleTime(m.config.PostgreSQL.ConnMaxIdleTime)

	// Test connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	m.PostgreSQL = db
	m.logger.Info("PostgreSQL connection established successfully")
	return nil
}

// connectRedis establishes Redis connection
func (m *Manager) connectRedis(ctx context.Context) error {
	m.logger.WithFields(logrus.Fields{
		"host":     m.config.Redis.Host,
		"port":     m.config.Redis.Port,
		"database": m.config.Redis.Database,
	}).Info("Connecting to Redis")

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", m.config.Redis.Host, m.config.Redis.Port),
		Password:     m.config.Redis.Password,
		DB:           m.config.Redis.Database,
		PoolSize:     m.config.Redis.PoolSize,
		MinIdleConns: m.config.Redis.MinIdleConns,
		PoolTimeout:  m.config.Redis.PoolTimeout,
		DialTimeout:  m.config.Redis.DialTimeout,
		ReadTimeout:  m.config.Redis.ReadTimeout,
		WriteTimeout: m.config.Redis.WriteTimeout,
	})

	// Test connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		rdb.Close()
		return fmt.Errorf("failed to ping Redis: %w", err)
	}

	m.Redis = rdb
	m.logger.Info("Redis connection established successfully")
	return nil
}

// Disconnect closes all database connections
func (m *Manager) Disconnect() error {
	var errors []error

	// Close PostgreSQL connection
	if m.PostgreSQL != nil {
		if err := m.PostgreSQL.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close PostgreSQL: %w", err))
		} else {
			m.logger.Info("PostgreSQL connection closed")
		}
		m.PostgreSQL = nil
	}

	// Close Redis connection
	if m.Redis != nil {
		if err := m.Redis.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close Redis: %w", err))
		} else {
			m.logger.Info("Redis connection closed")
		}
		m.Redis = nil
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during disconnect: %v", errors)
	}

	m.logger.Info("All database connections closed successfully")
	return nil
}

// HealthCheck performs health checks on all database connections
func (m *Manager) HealthCheck(ctx context.Context) error {
	// Check PostgreSQL
	if err := m.healthCheckPostgreSQL(ctx); err != nil {
		return fmt.Errorf("PostgreSQL health check failed: %w", err)
	}

	// Check Redis
	if err := m.healthCheckRedis(ctx); err != nil {
		return fmt.Errorf("Redis health check failed: %w", err)
	}

	return nil
}

// healthCheckPostgreSQL performs PostgreSQL health check
func (m *Manager) healthCheckPostgreSQL(ctx context.Context) error {
	if m.PostgreSQL == nil {
		return fmt.Errorf("PostgreSQL connection is nil")
	}

	// Create a context with timeout for health check
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := m.PostgreSQL.PingContext(healthCtx); err != nil {
		return fmt.Errorf("PostgreSQL ping failed: %w", err)
	}

	// Test a simple query
	var result int
	if err := m.PostgreSQL.GetContext(healthCtx, &result, "SELECT 1"); err != nil {
		return fmt.Errorf("PostgreSQL query test failed: %w", err)
	}

	return nil
}

// healthCheckRedis performs Redis health check
func (m *Manager) healthCheckRedis(ctx context.Context) error {
	if m.Redis == nil {
		return fmt.Errorf("Redis connection is nil")
	}

	// Create a context with timeout for health check
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := m.Redis.Ping(healthCtx).Err(); err != nil {
		return fmt.Errorf("Redis ping failed: %w", err)
	}

	// Test a simple operation
	testKey := "health_check_test"
	if err := m.Redis.Set(healthCtx, testKey, "ok", 1*time.Second).Err(); err != nil {
		return fmt.Errorf("Redis SET test failed: %w", err)
	}

	if err := m.Redis.Del(healthCtx, testKey).Err(); err != nil {
		return fmt.Errorf("Redis DEL test failed: %w", err)
	}

	return nil
}

// GetStats returns connection statistics
func (m *Manager) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// PostgreSQL stats
	if m.PostgreSQL != nil {
		pgStats := m.PostgreSQL.Stats()
		stats["postgresql"] = map[string]interface{}{
			"max_open_connections":     pgStats.MaxOpenConnections,
			"open_connections":         pgStats.OpenConnections,
			"in_use":                  pgStats.InUse,
			"idle":                    pgStats.Idle,
			"wait_count":              pgStats.WaitCount,
			"wait_duration":           pgStats.WaitDuration.String(),
			"max_idle_closed":         pgStats.MaxIdleClosed,
			"max_idle_time_closed":    pgStats.MaxIdleTimeClosed,
			"max_lifetime_closed":     pgStats.MaxLifetimeClosed,
		}
	}

	// Redis stats
	if m.Redis != nil {
		redisStats := m.Redis.PoolStats()
		stats["redis"] = map[string]interface{}{
			"hits":          redisStats.Hits,
			"misses":        redisStats.Misses,
			"timeouts":      redisStats.Timeouts,
			"total_conns":   redisStats.TotalConns,
			"idle_conns":    redisStats.IdleConns,
			"stale_conns":   redisStats.StaleConns,
		}
	}

	return stats, nil
}

// IsConnected checks if both databases are connected
func (m *Manager) IsConnected() bool {
	return m.PostgreSQL != nil && m.Redis != nil
}

// GetPostgreSQL returns the PostgreSQL connection
func (m *Manager) GetPostgreSQL() *sqlx.DB {
	return m.PostgreSQL
}

// GetRedis returns the Redis client
func (m *Manager) GetRedis() *redis.Client {
	return m.Redis
} 