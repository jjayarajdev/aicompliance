package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/logging"
	"ai-gateway-poc/internal/server"
)

// @title AI Gateway PoC API
// @version 1.0
// @description AI Gateway Proof of Concept - Forward Proxy Edge AI Control Plane
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.ai-gateway.com/support
// @contact.email support@ai-gateway.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /api/v1
// @schemes http https

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

// @securityDefinitions.apikey JWTAuth
// @in header
// @name Authorization
// @description Enter JWT token with 'Bearer ' prefix

func main() {
	// Initialize configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Setup structured logging
	logger, err := setupLogging(cfg)
	if err != nil {
		fmt.Printf("Failed to setup logging: %v\n", err)
		os.Exit(1)
	}

	// Set as global logger
	logging.SetGlobalLogger(logger)

	logger.Info("Starting AI Gateway PoC...")
	logger.WithFields(map[string]interface{}{
		"version":     getVersion(),
		"environment": cfg.Environment,
		"log_level":   cfg.Logging.Level,
		"log_format":  cfg.Logging.Format,
	}).Info("Application configuration loaded")

	// Create server instance
	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create server")
	}

	// Start HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      srv.Handler(),
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		serverLogger := logger.WithComponent("server")
		serverLogger.WithFields(map[string]interface{}{
			"port":          cfg.Server.Port,
			"read_timeout":  cfg.Server.ReadTimeout,
			"write_timeout": cfg.Server.WriteTimeout,
			"idle_timeout":  cfg.Server.IdleTimeout,
		}).Info("HTTP server starting")

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverLogger.WithError(err).Fatal("HTTP server failed to start")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down AI Gateway...")

	// Gracefully shutdown with timeout
	shutdownTimeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	start := time.Now()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.WithFields(map[string]interface{}{
			"shutdown_duration": time.Since(start),
		}).Info("Server shutdown completed gracefully")
	}

	// Cleanup resources
	if err := srv.Close(); err != nil {
		logger.WithError(err).Error("Error closing server resources")
	}

	logger.Info("AI Gateway PoC stopped")
}

func setupLogging(cfg *config.Config) (*logging.Logger, error) {
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
		RequestLogging: logging.RequestLogging{
			Enabled:       cfg.Logging.RequestLogging.Enabled,
			Headers:       cfg.Logging.RequestLogging.Headers,
			Body:          cfg.Logging.RequestLogging.Body,
			QueryParams:   cfg.Logging.RequestLogging.QueryParams,
			ResponseBody:  cfg.Logging.RequestLogging.ResponseBody,
			ExcludePaths:  cfg.Logging.RequestLogging.ExcludePaths,
			MaxBodySize:   cfg.Logging.RequestLogging.MaxBodySize,
		},
	}

	logger, err := logging.New(logConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return logger, nil
}

func getVersion() string {
	if version := os.Getenv("APP_VERSION"); version != "" {
		return version
	}
	return "development"
} 