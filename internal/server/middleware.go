package server

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"ai-gateway-poc/internal/logging"
	"github.com/sirupsen/logrus"
)

// setupMiddleware configures HTTP middleware
func (s *Server) setupMiddleware() {
	// Request ID middleware (always first)
	s.router.Use(logging.RequestIDMiddleware())

	// Request logging middleware
	if s.config.Logging.RequestLogging.Enabled {
		s.router.Use(logging.RequestLoggingMiddleware(s.logger, logging.RequestLogging{
			Enabled:       s.config.Logging.RequestLogging.Enabled,
			Headers:       s.config.Logging.RequestLogging.Headers,
			Body:          s.config.Logging.RequestLogging.Body,
			QueryParams:   s.config.Logging.RequestLogging.QueryParams,
			ResponseBody:  s.config.Logging.RequestLogging.ResponseBody,
			ExcludePaths:  s.config.Logging.RequestLogging.ExcludePaths,
			MaxBodySize:   s.config.Logging.RequestLogging.MaxBodySize,
		}))
	}

	// Recovery middleware (for panic handling)
	s.router.Use(s.recoveryMiddleware)

	// CORS middleware
	if s.config.Security.CorsEnabled {
		s.router.Use(s.corsMiddleware)
	}

	s.logger.Info("HTTP middleware configured")
}

// corsMiddleware handles Cross-Origin Resource Sharing
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range s.config.Security.CorsOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-API-Key, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "3600")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// recoveryMiddleware handles panics and returns 500 error
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				requestID := r.Header.Get("X-Request-ID")
				
				s.logger.WithFields(logrus.Fields{
					"error":      err,
					"request_id": requestID,
					"path":       r.URL.Path,
					"method":     r.Method,
					"stack":      string(debug.Stack()),
					"panic":      true,
				}).Error("Panic recovered")

				// Return 500 error
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				
				errorResponse := fmt.Sprintf(`{
					"error": "internal_server_error",
					"message": "An internal server error occurred",
					"request_id": "%s"
				}`, requestID)
				
				w.Write([]byte(errorResponse))
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the real client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fallback to RemoteAddr
	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 {
		return ip[0]
	}

	return r.RemoteAddr
} 