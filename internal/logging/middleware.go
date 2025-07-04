package logging

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RequestLoggingMiddleware creates HTTP middleware for request logging
func RequestLoggingMiddleware(logger *Logger, config RequestLogging) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip logging for excluded paths
			if shouldExcludePath(r.URL.Path, config.ExcludePaths) {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Generate or extract request ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Add request ID to context and response headers
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			r = r.WithContext(ctx)
			w.Header().Set("X-Request-ID", requestID)

			// Capture request body if enabled
			var requestBody []byte
			if config.Body && r.Body != nil {
				requestBody, _ = captureBody(r.Body, config.MaxBodySize)
				r.Body = io.NopCloser(bytes.NewReader(requestBody))
			}

			// Wrap response writer to capture response data
			wrapped := &responseCapture{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				body:          bytes.NewBuffer(nil),
				captureBody:   config.ResponseBody,
				maxBodySize:   config.MaxBodySize,
			}

			// Process request
			next.ServeHTTP(wrapped, r)

			// Calculate duration
			duration := time.Since(start)

			// Prepare log fields
			fields := logrus.Fields{
				"request_id":    requestID,
				"method":        r.Method,
				"path":          r.URL.Path,
				"status":        wrapped.statusCode,
				"duration_ms":   duration.Milliseconds(),
				"duration_ns":   duration.Nanoseconds(),
				"user_agent":    r.Header.Get("User-Agent"),
				"remote_ip":     getClientIP(r),
				"content_length": getContentLength(r),
				"protocol":      r.Proto,
				"host":          r.Host,
			}

			// Add query parameters if enabled
			if config.QueryParams && r.URL.RawQuery != "" {
				fields["query_params"] = r.URL.RawQuery
			}

			// Add headers if enabled
			if config.Headers {
				fields["request_headers"] = sanitizeHeaders(r.Header)
				fields["response_headers"] = sanitizeHeaders(w.Header())
			}

			// Add request body if enabled and captured
			if config.Body && len(requestBody) > 0 {
				fields["request_body"] = string(requestBody)
			}

			// Add response body if enabled and captured
			if config.ResponseBody && wrapped.body.Len() > 0 {
				fields["response_body"] = wrapped.body.String()
			}

			// Log with appropriate level based on status code
			entry := logger.WithFields(fields)
			switch {
			case wrapped.statusCode >= 500:
				entry.Error("HTTP request completed with server error")
			case wrapped.statusCode >= 400:
				entry.Warn("HTTP request completed with client error")
			case wrapped.statusCode >= 300:
				entry.Info("HTTP request completed with redirect")
			default:
				entry.Info("HTTP request completed successfully")
			}
		})
	}
}

// RequestIDMiddleware adds request ID to context
func RequestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request ID already exists
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Add to response headers
			w.Header().Set("X-Request-ID", requestID)

			// Add to context
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// shouldExcludePath checks if a path should be excluded from logging
func shouldExcludePath(path string, excludePaths []string) bool {
	for _, excludePath := range excludePaths {
		if strings.HasPrefix(path, excludePath) {
			return true
		}
	}
	return false
}

// captureBody captures request/response body up to maxSize bytes
func captureBody(body io.ReadCloser, maxSize int) ([]byte, error) {
	if maxSize <= 0 {
		maxSize = 1024 // Default limit
	}

	buffer := make([]byte, maxSize)
	n, err := body.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return buffer[:n], nil
}

// responseCapture wraps http.ResponseWriter to capture response data
type responseCapture struct {
	http.ResponseWriter
	statusCode  int
	body        *bytes.Buffer
	captureBody bool
	maxBodySize int
}

func (rc *responseCapture) WriteHeader(statusCode int) {
	rc.statusCode = statusCode
	rc.ResponseWriter.WriteHeader(statusCode)
}

func (rc *responseCapture) Write(data []byte) (int, error) {
	// Capture response body if enabled
	if rc.captureBody && rc.body.Len() < rc.maxBodySize {
		remaining := rc.maxBodySize - rc.body.Len()
		if remaining > 0 {
			if len(data) <= remaining {
				rc.body.Write(data)
			} else {
				rc.body.Write(data[:remaining])
			}
		}
	}

	return rc.ResponseWriter.Write(data)
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

// getContentLength safely gets content length
func getContentLength(r *http.Request) int64 {
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	if length := r.Header.Get("Content-Length"); length != "" {
		if size, err := strconv.ParseInt(length, 10, 64); err == nil {
			return size
		}
	}
	return 0
}

// sanitizeHeaders removes sensitive headers for logging
func sanitizeHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header)
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"x-api-key":     true,
		"x-auth-token":  true,
	}

	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if sensitiveHeaders[lowerKey] {
			sanitized[key] = []string{"[REDACTED]"}
		} else {
			sanitized[key] = values
		}
	}

	return sanitized
}

// ContextWithFields adds logging fields to context
func ContextWithFields(ctx context.Context, fields map[string]interface{}) context.Context {
	for key, value := range fields {
		ctx = context.WithValue(ctx, ContextKey(key), value)
	}
	return ctx
}

// ContextWithUserID adds user ID to context
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// ContextWithComponent adds component name to context
func ContextWithComponent(ctx context.Context, component string) context.Context {
	return context.WithValue(ctx, ComponentKey, component)
}

// ContextWithOperation adds operation name to context
func ContextWithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, OperationKey, operation)
} 