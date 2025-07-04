package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/logging"
	"github.com/sirupsen/logrus"
)

func main() {
	fmt.Println("🚀 AI Gateway - Structured Logging Infrastructure Demo")
	fmt.Println("===============================================")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	// Create logging configuration
	logConfig := &logging.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		Output: cfg.Logging.Output,
		File: logging.FileConfig{
			Enabled:    cfg.Logging.File.Enabled,
			Path:       cfg.Logging.File.Path,
			MaxSize:    cfg.Logging.File.MaxSize,
			MaxBackups: cfg.Logging.File.MaxBackups,
			MaxAge:     cfg.Logging.File.MaxAge,
			Compress:   cfg.Logging.File.Compress,
		},
		Fields:          cfg.Logging.Fields,
		ComponentLevels: cfg.Logging.ComponentLevels,
	}

	// Create main logger
	logger, err := logging.New(logConfig)
	if err != nil {
		fmt.Printf("❌ Failed to create logger: %v\n", err)
		return
	}

	// Set as global logger
	logging.SetGlobalLogger(logger)

	fmt.Println("✅ Logging system initialized successfully")
	fmt.Println()

	// Demo 1: Basic structured logging
	fmt.Println("📝 Demo 1: Basic Structured Logging")
	fmt.Println("-----------------------------------")
	
	logger.Info("Basic info message")
	logger.Warn("Basic warning message")
	logger.Error("Basic error message")
	
	// Structured logging with fields
	logger.WithFields(logrus.Fields{
		"user_id":    "user-123",
		"request_id": "req-456",
		"operation":  "demo",
	}).Info("Structured log with multiple fields")

	fmt.Println("✅ Basic logging demo completed")
	fmt.Println()

	// Demo 2: Component-specific logging
	fmt.Println("📝 Demo 2: Component-Specific Logging")
	fmt.Println("-------------------------------------")

	serverLogger := logger.WithComponent("server")
	dbLogger := logger.WithComponent("database")
	providerLogger := logger.WithComponent("providers")

	serverLogger.Info("Server component message")
	dbLogger.Info("Database component message (should be warn level)")
	providerLogger.Info("Providers component message")

	fmt.Println("✅ Component logging demo completed")
	fmt.Println()

	// Demo 3: Context-aware logging
	fmt.Println("📝 Demo 3: Context-Aware Logging")
	fmt.Println("--------------------------------")

	ctx := context.Background()
	ctx = logging.ContextWithUserID(ctx, "user-789")
	ctx = logging.ContextWithComponent(ctx, "auth")
	ctx = logging.ContextWithOperation(ctx, "login")
	ctx = context.WithValue(ctx, logging.RequestIDKey, "req-context-123")

	logger.WithContext(ctx).Info("Context-aware log message")

	fmt.Println("✅ Context logging demo completed")
	fmt.Println()

	// Demo 4: Specialized logging types
	fmt.Println("📝 Demo 4: Specialized Logging Types")
	fmt.Println("------------------------------------")

	// Performance logging
	start := time.Now()
	time.Sleep(50 * time.Millisecond) // Simulate work
	duration := time.Since(start)
	logger.Performance("demo_operation", duration).Info("Performance measurement")

	// Security logging
	logger.Security("suspicious_activity").Warn("Potential security threat detected")

	// Audit logging
	logger.Audit("policy_change").Info("System policy updated")

	// Error logging
	demoError := errors.New("demonstration error")
	logger.WithError(demoError).Error("Error occurred during demo")

	fmt.Println("✅ Specialized logging demo completed")
	fmt.Println()

	// Demo 5: Global convenience functions
	fmt.Println("📝 Demo 5: Global Convenience Functions")
	fmt.Println("--------------------------------------")

	logging.Info("Using global Info function")
	logging.Warn("Using global Warn function")
	logging.Error("Using global Error function")

	// Global functions with context
	logging.WithFields(logrus.Fields{
		"demo_type": "global_functions",
		"feature":   "convenience",
	}).Info("Global function with fields")

	// Global component logging
	globalServerLogger := logging.WithComponent("global_server")
	globalServerLogger.Info("Global component logger")

	fmt.Println("✅ Global functions demo completed")
	fmt.Println()

	// Demo 6: Log levels demonstration
	fmt.Println("📝 Demo 6: Log Levels Demonstration")
	fmt.Println("-----------------------------------")

	logger.Debug("Debug level message (may not appear depending on config)")
	logger.Info("Info level message")
	logger.Warn("Warning level message")
	logger.Error("Error level message")

	fmt.Println("✅ Log levels demo completed")
	fmt.Println()

	// Demo 7: Complex structured data
	fmt.Println("📝 Demo 7: Complex Structured Data")
	fmt.Println("----------------------------------")

	complexData := map[string]interface{}{
		"user": map[string]interface{}{
			"id":    "user-complex-123",
			"name":  "Demo User",
			"roles": []string{"admin", "user"},
		},
		"request": map[string]interface{}{
			"method":    "POST",
			"path":      "/api/v1/demo",
			"timestamp": time.Now(),
			"headers": map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "Demo-Client/1.0",
			},
		},
		"metadata": map[string]interface{}{
			"processing_time": 123.45,
			"cache_hit":       true,
			"retry_count":     0,
		},
	}

	logger.WithFields(logrus.Fields{
		"complex_data": complexData,
		"data_type":    "nested_structure",
	}).Info("Complex structured data logging")

	fmt.Println("✅ Complex data demo completed")
	fmt.Println()

	// Demo 8: File logging (if enabled)
	if logConfig.File.Enabled {
		fmt.Println("📝 Demo 8: File Logging")
		fmt.Println("-----------------------")

		fileLogger, err := logging.New(&logging.Config{
			Level:  "info",
			Format: "json",
			Output: "file",
			File: logging.FileConfig{
				Enabled:    true,
				Path:       "logs/demo.log",
				MaxSize:    1,
				MaxBackups: 2,
				MaxAge:     7,
				Compress:   true,
			},
			Fields: map[string]string{
				"demo": "file_logging",
			},
		})

		if err != nil {
			fmt.Printf("❌ Failed to create file logger: %v\n", err)
		} else {
			fileLogger.Info("This message is written to file")
			fileLogger.WithFields(logrus.Fields{
				"file_demo": true,
				"timestamp": time.Now(),
			}).Info("File logging with structured data")
			fmt.Println("✅ File logging demo completed (check logs/demo.log)")
		}
		fmt.Println()
	}

	// Demo 9: Performance benchmarking
	fmt.Println("📝 Demo 9: Performance Benchmarking")
	fmt.Println("-----------------------------------")

	// Simple logging performance
	start = time.Now()
	for i := 0; i < 1000; i++ {
		logger.WithFields(logrus.Fields{
			"iteration": i,
			"benchmark": true,
		}).Debug("Benchmark message") // Debug level so it might not be processed
	}
	duration = time.Since(start)
	logger.Performance("logging_benchmark", duration).Info(fmt.Sprintf("Processed 1000 log messages in %v", duration))

	fmt.Println("✅ Performance benchmarking demo completed")
	fmt.Println()

	// Final summary
	fmt.Println("🎉 All Logging Demos Completed Successfully!")
	fmt.Println("============================================")
	fmt.Println()
	fmt.Printf("📊 Configuration Summary:\n")
	fmt.Printf("  - Log Level: %s\n", logConfig.Level)
	fmt.Printf("  - Log Format: %s\n", logConfig.Format)
	fmt.Printf("  - Log Output: %s\n", logConfig.Output)
	fmt.Printf("  - File Logging: %t\n", logConfig.File.Enabled)
	if logConfig.File.Enabled {
		fmt.Printf("  - File Path: %s\n", logConfig.File.Path)
	}
	fmt.Printf("  - Component Levels: %d configured\n", len(logConfig.ComponentLevels))
	fmt.Printf("  - Base Fields: %d configured\n", len(logConfig.Fields))
	fmt.Println()

	logger.WithFields(logrus.Fields{
		"demo_status":    "completed",
		"total_duration": time.Since(time.Now().Add(-5*time.Second)), // Approximate
		"demos_run":      9,
	}).Info("Logging infrastructure demonstration completed successfully")
} 