package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SSLHandler manages SSL/TLS certificates and configuration
type SSLHandler struct {
	config     *SSLConfig
	logger     *logrus.Logger
	certCache  sync.Map // Cache for dynamically generated certificates
	rootCA     *x509.Certificate
	rootCAKey  *rsa.PrivateKey
	mu         sync.RWMutex
}

// SSLConfig holds SSL/TLS configuration
type SSLConfig struct {
	// Certificate files
	CertFile    string `yaml:"cert_file" mapstructure:"cert_file"`
	KeyFile     string `yaml:"key_file" mapstructure:"key_file"`
	CAFile      string `yaml:"ca_file" mapstructure:"ca_file"`
	
	// Auto-generation settings
	AutoGenerate     bool   `yaml:"auto_generate" mapstructure:"auto_generate"`
	CertDir          string `yaml:"cert_dir" mapstructure:"cert_dir"`
	
	// Certificate settings
	Organization     string        `yaml:"organization" mapstructure:"organization"`
	Country          string        `yaml:"country" mapstructure:"country"`
	Province         string        `yaml:"province" mapstructure:"province"`
	Locality         string        `yaml:"locality" mapstructure:"locality"`
	ValidityDuration time.Duration `yaml:"validity_duration" mapstructure:"validity_duration"`
	
	// TLS settings
	MinVersion       uint16   `yaml:"min_version" mapstructure:"min_version"`
	MaxVersion       uint16   `yaml:"max_version" mapstructure:"max_version"`
	CipherSuites     []uint16 `yaml:"cipher_suites" mapstructure:"cipher_suites"`
	
	// Dynamic certificate generation
	EnableDynamicCerts bool `yaml:"enable_dynamic_certs" mapstructure:"enable_dynamic_certs"`
}

// NewSSLHandler creates a new SSL handler instance
func NewSSLHandler(config *SSLConfig, logger *logrus.Logger) (*SSLHandler, error) {
	if config == nil {
		return nil, fmt.Errorf("SSL config cannot be nil")
	}
	
	if logger == nil {
		logger = logrus.New()
	}

	// Set default values
	if config.CertDir == "" {
		config.CertDir = "./certs"
	}
	if config.Organization == "" {
		config.Organization = "AI Gateway"
	}
	if config.Country == "" {
		config.Country = "US"
	}
	if config.ValidityDuration == 0 {
		config.ValidityDuration = 365 * 24 * time.Hour // 1 year
	}
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}
	if config.MaxVersion == 0 {
		config.MaxVersion = tls.VersionTLS13
	}

	handler := &SSLHandler{
		config: config,
		logger: logger,
	}

	// Create cert directory if it doesn't exist
	if err := os.MkdirAll(config.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Initialize root CA if dynamic certificates are enabled
	if config.EnableDynamicCerts {
		if err := handler.initRootCA(); err != nil {
			return nil, fmt.Errorf("failed to initialize root CA: %w", err)
		}
	}

	return handler, nil
}

// GetTLSConfig returns a TLS configuration with appropriate settings
func (s *SSLHandler) GetTLSConfig() (*tls.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tlsConfig := &tls.Config{
		MinVersion:               s.config.MinVersion,
		MaxVersion:               s.config.MaxVersion,
		PreferServerCipherSuites: true,
	}

	// Set cipher suites if specified
	if len(s.config.CipherSuites) > 0 {
		tlsConfig.CipherSuites = s.config.CipherSuites
	} else {
		// Default secure cipher suites
		tlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		}
	}

	// If dynamic certificates are enabled, set up certificate retrieval
	if s.config.EnableDynamicCerts {
		tlsConfig.GetCertificate = s.getCertificate
	}

	return tlsConfig, nil
}

// LoadCertificate loads SSL certificate and key from files
func (s *SSLHandler) LoadCertificate() (tls.Certificate, error) {
	if s.config.CertFile == "" || s.config.KeyFile == "" {
		return tls.Certificate{}, fmt.Errorf("certificate and key files must be specified")
	}

	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load certificate: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"cert_file": s.config.CertFile,
		"key_file":  s.config.KeyFile,
	}).Info("SSL certificate loaded successfully")

	return cert, nil
}

// GenerateSelfSignedCertificate generates a self-signed certificate for testing
func (s *SSLHandler) GenerateSelfSignedCertificate(hosts []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Generating self-signed certificate")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{s.config.Organization},
			Country:       []string{s.config.Country},
			Province:      []string{s.config.Province},
			Locality:      []string{s.config.Locality},
			StreetAddress: []string{},
			PostalCode:    []string{},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(s.config.ValidityDuration),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Add hosts to certificate
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	// Add localhost and common names
	template.DNSNames = append(template.DNSNames, "localhost", "ai-gateway")
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Save certificate
	certPath := filepath.Join(s.config.CertDir, "server.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyPath := filepath.Join(s.config.CertDir, "server.key")
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Update config with generated files
	s.config.CertFile = certPath
	s.config.KeyFile = keyPath

	s.logger.WithFields(logrus.Fields{
		"cert_file": certPath,
		"key_file":  keyPath,
		"hosts":     hosts,
	}).Info("Self-signed certificate generated successfully")

	return nil
}

// initRootCA initializes or loads the root CA for dynamic certificate generation
func (s *SSLHandler) initRootCA() error {
	caCertPath := filepath.Join(s.config.CertDir, "ca.crt")
	caKeyPath := filepath.Join(s.config.CertDir, "ca.key")

	// Check if CA files exist
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return s.generateRootCA(caCertPath, caKeyPath)
	}

	// Load existing CA
	return s.loadRootCA(caCertPath, caKeyPath)
}

// generateRootCA generates a new root CA
func (s *SSLHandler) generateRootCA(certPath, keyPath string) error {
	s.logger.Info("Generating root CA certificate")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{s.config.Organization + " Root CA"},
			Country:       []string{s.config.Country},
			Province:      []string{s.config.Province},
			Locality:      []string{s.config.Locality},
			StreetAddress: []string{},
			PostalCode:    []string{},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(s.config.ValidityDuration * 10), // CA valid for 10x longer
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Save certificate
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create CA cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Save private key
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	s.rootCA = cert
	s.rootCAKey = privateKey

	s.logger.WithFields(logrus.Fields{
		"cert_file": certPath,
		"key_file":  keyPath,
	}).Info("Root CA generated successfully")

	return nil
}

// loadRootCA loads existing root CA
func (s *SSLHandler) loadRootCA(certPath, keyPath string) error {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA private key is not RSA")
	}

	s.rootCA = cert
	s.rootCAKey = rsaKey

	s.logger.WithFields(logrus.Fields{
		"cert_file": certPath,
		"key_file":  keyPath,
	}).Info("Root CA loaded successfully")

	return nil
}

// getCertificate dynamically generates or retrieves certificates for SNI
func (s *SSLHandler) getCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if info.ServerName == "" {
		return nil, fmt.Errorf("no server name provided")
	}

	// Check cache first
	if cachedCert, ok := s.certCache.Load(info.ServerName); ok {
		return cachedCert.(*tls.Certificate), nil
	}

	// Generate new certificate for the hostname
	cert, err := s.generateDynamicCertificate(info.ServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to generate dynamic certificate: %w", err)
	}

	// Cache the certificate
	s.certCache.Store(info.ServerName, cert)

	s.logger.WithField("hostname", info.ServerName).Info("Generated dynamic certificate")

	return cert, nil
}

// generateDynamicCertificate generates a certificate for a specific hostname
func (s *SSLHandler) generateDynamicCertificate(hostname string) (*tls.Certificate, error) {
	if s.rootCA == nil || s.rootCAKey == nil {
		return nil, fmt.Errorf("root CA not initialized")
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{s.config.Organization},
			CommonName:   hostname,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(s.config.ValidityDuration),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Add hostname to certificate
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	// Generate certificate signed by root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.rootCA, &privateKey.PublicKey, s.rootCAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER, s.rootCA.Raw},
		PrivateKey:  privateKey,
	}

	return &cert, nil
}

// ValidateCertificate validates that the certificate files are valid
func (s *SSLHandler) ValidateCertificate() error {
	if s.config.CertFile == "" || s.config.KeyFile == "" {
		return fmt.Errorf("certificate and key files must be specified")
	}

	_, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		return fmt.Errorf("invalid certificate or key: %w", err)
	}

	return nil
}

// GetRootCA returns the root CA certificate for client configuration
func (s *SSLHandler) GetRootCA() *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rootCA
} 