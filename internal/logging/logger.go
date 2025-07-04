package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger represents the application logger with enhanced functionality
type Logger struct {
	*logrus.Logger
	config *Config
	fields logrus.Fields
}

// Config holds logging configuration
type Config struct {
	Level           string            `mapstructure:"level"`
	Format          string            `mapstructure:"format"`
	Output          string            `mapstructure:"output"`
	File            FileConfig        `mapstructure:"file"`
	Fields          map[string]string `mapstructure:"fields"`
	RequestLogging  RequestLogging    `mapstructure:"request_logging"`
	ComponentLevels map[string]string `mapstructure:"component_levels"`
}

// FileConfig holds file logging configuration
type FileConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Path       string `mapstructure:"path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// RequestLogging holds HTTP request logging configuration
type RequestLogging struct {
	Enabled       bool     `mapstructure:"enabled"`
	Headers       bool     `mapstructure:"headers"`
	Body          bool     `mapstructure:"body"`
	QueryParams   bool     `mapstructure:"query_params"`
	ResponseBody  bool     `mapstructure:"response_body"`
	ExcludePaths  []string `mapstructure:"exclude_paths"`
	MaxBodySize   int      `mapstructure:"max_body_size"`
}

// ContextKey represents keys for logger context values
type ContextKey string

const (
	// RequestIDKey is the context key for request ID
	RequestIDKey ContextKey = "request_id"
	// UserIDKey is the context key for user ID
	UserIDKey ContextKey = "user_id"
	// ComponentKey is the context key for component name
	ComponentKey ContextKey = "component"
	// OperationKey is the context key for operation name
	OperationKey ContextKey = "operation"
)

// Global logger instance
var globalLogger *Logger

// New creates a new logger instance with the given configuration
func New(config *Config) (*Logger, error) {
	if config == nil {
		return nil, fmt.Errorf("logging config cannot be nil")
	}

	// Create base logrus logger
	baseLogger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %s: %w", config.Level, err)
	}
	baseLogger.SetLevel(level)

	// Set formatter
	switch strings.ToLower(config.Format) {
	case "json":
		baseLogger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
		})
	case "text":
		baseLogger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
		})
	default:
		return nil, fmt.Errorf("unsupported log format: %s", config.Format)
	}

	// Set output
	output, err := getLogOutput(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure log output: %w", err)
	}
	baseLogger.SetOutput(output)

	// Prepare base fields
	fields := make(logrus.Fields)
	for key, value := range config.Fields {
		fields[key] = value
	}

	logger := &Logger{
		Logger: baseLogger,
		config: config,
		fields: fields,
	}

	return logger, nil
}

// getLogOutput configures the log output based on configuration
func getLogOutput(config *Config) (io.Writer, error) {
	switch strings.ToLower(config.Output) {
	case "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	case "file":
		if !config.File.Enabled {
			return os.Stdout, nil
		}
		return getFileWriter(config.File), nil
	case "both":
		outputs := []io.Writer{os.Stdout}
		if config.File.Enabled {
			outputs = append(outputs, getFileWriter(config.File))
		}
		return io.MultiWriter(outputs...), nil
	default:
		return nil, fmt.Errorf("unsupported output type: %s", config.Output)
	}
}

// getFileWriter creates a file writer with rotation support
func getFileWriter(config FileConfig) io.Writer {
	// Ensure directory exists
	dir := filepath.Dir(config.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		// Fallback to stdout if directory creation fails
		return os.Stdout
	}

	return &lumberjack.Logger{
		Filename:   config.Path,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}
}

// WithComponent creates a logger with component information
func (l *Logger) WithComponent(component string) *Logger {
	fields := make(logrus.Fields)
	for k, v := range l.fields {
		fields[k] = v
	}
	fields["component"] = component

	// Check for component-specific log level
	if level, exists := l.config.ComponentLevels[component]; exists {
		if logLevel, err := logrus.ParseLevel(level); err == nil {
			// Create a new logger instance with component-specific level
			newLogger := &Logger{
				Logger: logrus.New(),
				config: l.config,
				fields: fields,
			}
			
			// Copy configuration from original logger
			newLogger.SetLevel(logLevel)
			newLogger.SetFormatter(l.Formatter)
			newLogger.SetOutput(l.Out)
			
			return newLogger
		}
	}

	return &Logger{
		Logger: l.Logger,
		config: l.config,
		fields: fields,
	}
}

// WithContext creates a logger with context information
func (l *Logger) WithContext(ctx context.Context) *logrus.Entry {
	fields := make(logrus.Fields)
	for k, v := range l.fields {
		fields[k] = v
	}

	// Extract context values
	if requestID := ctx.Value(RequestIDKey); requestID != nil {
		fields["request_id"] = requestID
	}
	if userID := ctx.Value(UserIDKey); userID != nil {
		fields["user_id"] = userID
	}
	if component := ctx.Value(ComponentKey); component != nil {
		fields["component"] = component
	}
	if operation := ctx.Value(OperationKey); operation != nil {
		fields["operation"] = operation
	}

	return l.WithFields(fields)
}

// WithFields creates a logger entry with additional fields
func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	combinedFields := make(logrus.Fields)
	for k, v := range l.fields {
		combinedFields[k] = v
	}
	for k, v := range fields {
		combinedFields[k] = v
	}
	return l.Logger.WithFields(combinedFields)
}

// WithError creates a logger entry with error information
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.WithFields(logrus.Fields{"error": err.Error()})
}

// WithOperation creates a logger entry with operation information
func (l *Logger) WithOperation(operation string) *logrus.Entry {
	return l.WithFields(logrus.Fields{"operation": operation})
}

// Performance creates a logger entry for performance tracking
func (l *Logger) Performance(operation string, duration time.Duration) *logrus.Entry {
	return l.WithFields(logrus.Fields{
		"operation":        operation,
		"duration_ms":      duration.Milliseconds(),
		"duration_ns":      duration.Nanoseconds(),
		"performance_log":  true,
	})
}

// Security creates a logger entry for security events
func (l *Logger) Security(event string) *logrus.Entry {
	return l.WithFields(logrus.Fields{
		"security_event": event,
		"security_log":   true,
	})
}

// Audit creates a logger entry for audit events
func (l *Logger) Audit(action string) *logrus.Entry {
	return l.WithFields(logrus.Fields{
		"audit_action": action,
		"audit_log":    true,
	})
}

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Create a default logger if none exists
		config := &Config{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		}
		logger, _ := New(config)
		return logger
	}
	return globalLogger
}

// Global convenience functions
func Debug(args ...interface{}) {
	GetGlobalLogger().Debug(args...)
}

func Info(args ...interface{}) {
	GetGlobalLogger().Info(args...)
}

func Warn(args ...interface{}) {
	GetGlobalLogger().Warn(args...)
}

func Error(args ...interface{}) {
	GetGlobalLogger().Error(args...)
}

func Fatal(args ...interface{}) {
	GetGlobalLogger().Fatal(args...)
}

func WithComponent(component string) *Logger {
	return GetGlobalLogger().WithComponent(component)
}

func WithContext(ctx context.Context) *logrus.Entry {
	return GetGlobalLogger().WithContext(ctx)
}

func WithFields(fields logrus.Fields) *logrus.Entry {
	return GetGlobalLogger().WithFields(fields)
}

func WithError(err error) *logrus.Entry {
	return GetGlobalLogger().WithError(err)
} 