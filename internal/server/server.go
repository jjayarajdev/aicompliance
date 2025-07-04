package server

import (
	"net/http"

	"ai-gateway-poc/internal/config"
	"ai-gateway-poc/internal/logging"
	"github.com/gorilla/mux"
)

// Server represents the HTTP server
type Server struct {
	config *config.Config
	router *mux.Router
	logger *logging.Logger
}

// New creates a new server instance
func New(cfg *config.Config, logger *logging.Logger) (*Server, error) {
	if logger == nil {
		// Create default logger if none provided
		defaultLogger, err := logging.New(&logging.Config{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		})
		if err != nil {
			return nil, err
		}
		logger = defaultLogger
	}

	srv := &Server{
		config: cfg,
		router: mux.NewRouter(),
		logger: logger.WithComponent("server"),
	}

	// Setup routes and middleware
	srv.setupRoutes()
	srv.setupMiddleware()

	return srv, nil
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// Close gracefully shuts down the server and closes resources
func (s *Server) Close() error {
	s.logger.Info("Cleaning up server resources...")
	// TODO: Close database connections, Redis connections, etc.
	return nil
}

// setupRoutes configures the API routes
func (s *Server) setupRoutes() {
	// API v1 routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	
	// Health check endpoints
	api.HandleFunc("/health", s.healthCheckHandler).Methods("GET")
	api.HandleFunc("/ready", s.readyCheckHandler).Methods("GET")
	api.HandleFunc("/version", s.versionHandler).Methods("GET")

	// Dashboard API routes
	dashboard := api.PathPrefix("/dashboard").Subrouter()
	dashboard.HandleFunc("/stats", s.getDashboardStatsHandler).Methods("GET")
	dashboard.HandleFunc("/overview", s.getSystemOverviewHandler).Methods("GET")
	dashboard.HandleFunc("/activity", s.getRecentActivityHandler).Methods("GET")
	dashboard.HandleFunc("/metrics", s.getMetricsHandler).Methods("GET")

	// Policy management API routes
	policies := api.PathPrefix("/policies").Subrouter()
	policies.HandleFunc("", s.getPoliciesHandler).Methods("GET")
	policies.HandleFunc("", s.createPolicyHandler).Methods("POST")
	policies.HandleFunc("/{id}", s.updatePolicyHandler).Methods("PUT")
	policies.HandleFunc("/{id}", s.deletePolicyHandler).Methods("DELETE")

	// Monitoring API routes
	monitoring := api.PathPrefix("/monitoring").Subrouter()
	monitoring.HandleFunc("/system", s.getSystemMetricsHandler).Methods("GET")
	monitoring.HandleFunc("/alerts", s.getAlertsHandler).Methods("GET")
	monitoring.HandleFunc("/performance", s.getPerformanceMetricsHandler).Methods("GET")
	monitoring.HandleFunc("/providers", s.getProviderHealthHandler).Methods("GET")

	// Analytics API routes
	analytics := api.PathPrefix("/analytics").Subrouter()
	analytics.HandleFunc("", s.getAnalyticsHandler).Methods("POST")

	// Settings API routes
	settings := api.PathPrefix("/settings").Subrouter()
	settings.HandleFunc("/system", s.getSystemSettingsHandler).Methods("GET")
	settings.HandleFunc("/system", s.updateSystemSettingsHandler).Methods("PUT")

	// Root level health endpoint (without /api/v1 prefix for simple health checks)
	s.router.HandleFunc("/health", s.healthCheckHandler).Methods("GET")

	s.logger.Info("API routes configured")
}

// setupMiddleware configures HTTP middleware  
func (s *Server) setupMiddleware() {
	// CORS middleware (if enabled)
	if s.config.Security.CorsEnabled {
		s.router.Use(s.corsMiddleware)
	}

	// Recovery middleware
	s.router.Use(s.recoveryMiddleware)

	s.logger.Info("HTTP middleware configured")
}

// Health check handlers
func (s *Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"ai-gateway-poc"}`))
}

func (s *Server) readyCheckHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Add database and Redis connectivity checks
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready","service":"ai-gateway-poc"}`))
}

func (s *Server) versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"version":"1.0.0","service":"ai-gateway-poc","environment":"` + s.config.Environment + `"}`))
} 