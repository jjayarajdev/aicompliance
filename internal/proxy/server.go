package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ProxyServer represents the main proxy server instance
type ProxyServer struct {
	config     *Config
	httpServer *http.Server
	listener   net.Listener
	tlsConfig  *tls.Config
	logger     *logrus.Logger
	mu         sync.RWMutex
	started    bool
}

// Config holds the proxy server configuration
type Config struct {
	// Server configuration
	ListenAddr      string `yaml:"listen_addr" mapstructure:"listen_addr"`
	Port            int    `yaml:"port" mapstructure:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" mapstructure:"idle_timeout"`
	
	// SSL/TLS configuration
	EnableTLS       bool   `yaml:"enable_tls" mapstructure:"enable_tls"`
	CertFile        string `yaml:"cert_file" mapstructure:"cert_file"`
	KeyFile         string `yaml:"key_file" mapstructure:"key_file"`
	
	// Proxy configuration
	ConnectTimeout  time.Duration `yaml:"connect_timeout" mapstructure:"connect_timeout"`
	
	// AI Provider endpoints
	OpenAIEndpoint     string `yaml:"openai_endpoint" mapstructure:"openai_endpoint"`
	AnthropicEndpoint  string `yaml:"anthropic_endpoint" mapstructure:"anthropic_endpoint"`
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config *Config, logger *logrus.Logger) (*ProxyServer, error) {
	if config == nil {
		return nil, fmt.Errorf("proxy config cannot be nil")
	}
	
	if logger == nil {
		logger = logrus.New()
	}

	// Set default values
	if config.ListenAddr == "" {
		config.ListenAddr = "0.0.0.0"
	}
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 120 * time.Second
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 10 * time.Second
	}

	server := &ProxyServer{
		config: config,
		logger: logger,
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleHTTP)
	
	server.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.ListenAddr, config.Port),
		Handler:      mux,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  config.IdleTimeout,
	}

	// Setup TLS if enabled
	if config.EnableTLS {
		tlsConfig, err := server.setupTLS()
		if err != nil {
			return nil, fmt.Errorf("failed to setup TLS: %w", err)
		}
		server.tlsConfig = tlsConfig
		server.httpServer.TLSConfig = tlsConfig
	}

	return server, nil
}

// Start starts the proxy server
func (p *ProxyServer) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started {
		return fmt.Errorf("proxy server already started")
	}

	p.logger.WithFields(logrus.Fields{
		"address": p.httpServer.Addr,
		"tls":     p.config.EnableTLS,
	}).Info("Starting proxy server")

	listener, err := net.Listen("tcp", p.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	p.listener = listener

	p.started = true

	// Start server in goroutine
	go func() {
		var err error
		if p.config.EnableTLS {
			err = p.httpServer.ServeTLS(listener, p.config.CertFile, p.config.KeyFile)
		} else {
			err = p.httpServer.Serve(listener)
		}
		
		if err != nil && err != http.ErrServerClosed {
			p.logger.WithError(err).Error("Proxy server stopped with error")
		}
	}()

	// Wait for context cancellation
	go func() {
		<-ctx.Done()
		p.Stop()
	}()

	p.logger.Info("Proxy server started successfully")
	return nil
}

// Stop stops the proxy server gracefully
func (p *ProxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started {
		return nil
	}

	p.logger.Info("Stopping proxy server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := p.httpServer.Shutdown(ctx); err != nil {
		p.logger.WithError(err).Error("Error during server shutdown")
		return err
	}

	p.started = false
	p.logger.Info("Proxy server stopped")
	return nil
}

// handleHTTP handles HTTP requests and CONNECT methods for HTTPS
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Log the request
	p.logger.WithFields(logrus.Fields{
		"method":     r.Method,
		"url":        r.URL.String(),
		"host":       r.Host,
		"remote_addr": r.RemoteAddr,
		"user_agent": r.Header.Get("User-Agent"),
	}).Info("Proxy request received")

	switch r.Method {
	case http.MethodConnect:
		// Handle HTTPS CONNECT method
		p.handleConnect(w, r)
	default:
		// Handle HTTP requests
		p.handleHTTPRequest(w, r)
	}
}

// handleConnect handles HTTPS CONNECT method for SSL tunneling
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Parse the target host and port
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		p.logger.WithError(err).WithField("host", r.Host).Error("Invalid host in CONNECT request")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Check if this is a request to an AI provider
	targetHost := p.getTargetHost(host)
	if targetHost == "" {
		p.logger.WithField("host", host).Warn("CONNECT request to non-AI provider host")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Establish connection to target server
	destConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, port), p.config.ConnectTimeout)
	if err != nil {
		p.logger.WithError(err).WithField("target", targetHost).Error("Failed to connect to target server")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("ResponseWriter does not support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.WithError(err).Error("Failed to hijack connection")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Send 200 Connection established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		p.logger.WithError(err).Error("Failed to write connection established response")
		return
	}

	// Start bidirectional copying
	p.logger.WithField("target", targetHost).Info("Starting SSL tunnel")
	
	// Copy data between client and destination
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(destConn, clientConn)
	}()

	io.Copy(clientConn, destConn)
	
	p.logger.WithField("target", targetHost).Info("SSL tunnel closed")
}

// handleHTTPRequest handles regular HTTP requests
func (p *ProxyServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Create a new request to the target
	targetURL := p.buildTargetURL(r)
	if targetURL == nil {
		p.logger.WithField("host", r.Host).Warn("HTTP request to non-AI provider host")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Create new request
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to create target request")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Update Host header
	req.Host = targetURL.Host
	req.Header.Set("Host", targetURL.Host)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: p.config.ConnectTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: p.config.ConnectTimeout,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		p.logger.WithError(err).WithField("target", targetURL.String()).Error("Failed to make target request")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to copy response body")
		return
	}

	p.logger.WithFields(logrus.Fields{
		"target":     targetURL.String(),
		"status":     resp.StatusCode,
		"method":     r.Method,
	}).Info("HTTP request proxied successfully")
}

// getTargetHost returns the appropriate target host for AI providers
func (p *ProxyServer) getTargetHost(host string) string {
	// Normalize host (remove port if present)
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	switch {
	case strings.Contains(host, "openai.com") || strings.Contains(host, "api.openai.com"):
		if p.config.OpenAIEndpoint != "" {
			if u, err := url.Parse(p.config.OpenAIEndpoint); err == nil {
				return u.Host
			}
		}
		return "api.openai.com"
	case strings.Contains(host, "anthropic.com") || strings.Contains(host, "api.anthropic.com"):
		if p.config.AnthropicEndpoint != "" {
			if u, err := url.Parse(p.config.AnthropicEndpoint); err == nil {
				return u.Host
			}
		}
		return "api.anthropic.com"
	default:
		return "" // Not an AI provider
	}
}

// buildTargetURL builds the target URL for HTTP requests
func (p *ProxyServer) buildTargetURL(r *http.Request) *url.URL {
	targetHost := p.getTargetHost(r.Host)
	if targetHost == "" {
		return nil
	}

	scheme := "https"
	if !p.config.EnableTLS {
		scheme = "http"
	}

	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     targetHost,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	return targetURL
}

// setupTLS configures TLS settings for the proxy server
func (p *ProxyServer) setupTLS() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	return tlsConfig, nil
}

// GetAddr returns the server's listening address
func (p *ProxyServer) GetAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return p.httpServer.Addr
}

// IsStarted returns whether the server is currently running
func (p *ProxyServer) IsStarted() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.started
} 