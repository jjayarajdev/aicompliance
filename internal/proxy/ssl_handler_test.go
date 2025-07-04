package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSSLHandler(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name        string
		config      *SSLConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "valid config with defaults",
			config: &SSLConfig{
				CertDir: tempDir,
			},
			expectError: false,
		},
		{
			name: "config with dynamic certs disabled",
			config: &SSLConfig{
				CertDir:            tempDir,
				EnableDynamicCerts: false,
			},
			expectError: false,
		},
		{
			name: "config with dynamic certs enabled",
			config: &SSLConfig{
				CertDir:            tempDir,
				EnableDynamicCerts: true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel) // Reduce test noise

			handler, err := NewSSLHandler(tt.config, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, handler)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, handler)
			}
		})
	}
}

func TestSSLHandler_ConfigDefaults(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir: tempDir,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	assert.Equal(t, tempDir, handler.config.CertDir)
	assert.Equal(t, "AI Gateway", handler.config.Organization)
	assert.Equal(t, "US", handler.config.Country)
	assert.Equal(t, 365*24*time.Hour, handler.config.ValidityDuration)
	assert.Equal(t, uint16(tls.VersionTLS12), handler.config.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), handler.config.MaxVersion)
}

func TestSSLHandler_GetTLSConfig(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name   string
		config *SSLConfig
	}{
		{
			name: "basic config",
			config: &SSLConfig{
				CertDir:    tempDir,
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
			},
		},
		{
			name: "config with custom cipher suites",
			config: &SSLConfig{
				CertDir: tempDir,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
		},
		{
			name: "config with dynamic certs",
			config: &SSLConfig{
				CertDir:            tempDir,
				EnableDynamicCerts: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)

			handler, err := NewSSLHandler(tt.config, logger)
			require.NoError(t, err)

			tlsConfig, err := handler.GetTLSConfig()
			assert.NoError(t, err)
			assert.NotNil(t, tlsConfig)

			assert.Equal(t, tt.config.MinVersion, tlsConfig.MinVersion)
			assert.Equal(t, tt.config.MaxVersion, tlsConfig.MaxVersion)
			assert.True(t, tlsConfig.PreferServerCipherSuites)

			if len(tt.config.CipherSuites) > 0 {
				assert.Equal(t, tt.config.CipherSuites, tlsConfig.CipherSuites)
			} else {
				// Should have default cipher suites
				assert.NotEmpty(t, tlsConfig.CipherSuites)
			}

			if tt.config.EnableDynamicCerts {
				assert.NotNil(t, tlsConfig.GetCertificate)
			}
		})
	}
}

func TestSSLHandler_GenerateSelfSignedCertificate(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:          tempDir,
		Organization:     "Test Org",
		Country:          "US",
		ValidityDuration: 24 * time.Hour,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	hosts := []string{"localhost", "127.0.0.1", "test.example.com"}

	err = handler.GenerateSelfSignedCertificate(hosts)
	assert.NoError(t, err)

	// Check that certificate files were created
	certPath := filepath.Join(tempDir, "server.crt")
	keyPath := filepath.Join(tempDir, "server.key")

	assert.FileExists(t, certPath)
	assert.FileExists(t, keyPath)

	// Verify certificate can be loaded
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Parse the certificate to verify content
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	assert.Equal(t, "Test Org", x509Cert.Subject.Organization[0])
	assert.Contains(t, x509Cert.DNSNames, "localhost")
	assert.Contains(t, x509Cert.DNSNames, "test.example.com")

	// Verify IP addresses
	foundIPv4 := false
	for _, ip := range x509Cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIPv4 = true
			break
		}
	}
	assert.True(t, foundIPv4, "Should contain 127.0.0.1 IP address")
}

func TestSSLHandler_LoadCertificate(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir: tempDir,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	// Test loading without cert files
	_, err = handler.LoadCertificate()
	assert.Error(t, err)

	// Generate certificate first
	err = handler.GenerateSelfSignedCertificate([]string{"localhost"})
	require.NoError(t, err)

	// Test loading existing certificate
	cert, err := handler.LoadCertificate()
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestSSLHandler_ValidateCertificate(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir: tempDir,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	// Test validation without cert files
	err = handler.ValidateCertificate()
	assert.Error(t, err)

	// Generate certificate first
	err = handler.GenerateSelfSignedCertificate([]string{"localhost"})
	require.NoError(t, err)

	// Test validation with valid certificate
	err = handler.ValidateCertificate()
	assert.NoError(t, err)

	// Test validation with invalid certificate (corrupt the cert file)
	certPath := filepath.Join(tempDir, "server.crt")
	err = os.WriteFile(certPath, []byte("invalid cert data"), 0644)
	require.NoError(t, err)

	err = handler.ValidateCertificate()
	assert.Error(t, err)
}

func TestSSLHandler_RootCAGeneration(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		Organization:       "Test CA",
		Country:            "US",
		ValidityDuration:   24 * time.Hour,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	// Check that CA files were created
	caCertPath := filepath.Join(tempDir, "ca.crt")
	caKeyPath := filepath.Join(tempDir, "ca.key")

	assert.FileExists(t, caCertPath)
	assert.FileExists(t, caKeyPath)

	// Verify CA certificate
	rootCA := handler.GetRootCA()
	assert.NotNil(t, rootCA)
	assert.True(t, rootCA.IsCA)
	assert.Equal(t, "Test CA Root CA", rootCA.Subject.Organization[0])
}

func TestSSLHandler_DynamicCertificateGeneration(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		Organization:       "Test Org",
		ValidityDuration:   24 * time.Hour,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	// Test dynamic certificate generation
	hostname := "test.example.com"
	cert, err := handler.generateDynamicCertificate(hostname)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)
	assert.Contains(t, x509Cert.DNSNames, hostname)
	assert.Equal(t, "Test Org", x509Cert.Subject.Organization[0])
	assert.Equal(t, hostname, x509Cert.Subject.CommonName)

	// Test caching by generating the same certificate again
	clientHello := &tls.ClientHelloInfo{
		ServerName: hostname,
	}

	cert1, err := handler.getCertificate(clientHello)
	assert.NoError(t, err)

	cert2, err := handler.getCertificate(clientHello)
	assert.NoError(t, err)

	// Should be the same cached certificate
	assert.Equal(t, cert1, cert2)
}

func TestSSLHandler_DynamicCertificateWithIP(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		ValidityDuration:   24 * time.Hour,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	// Test dynamic certificate generation with IP address
	ipAddress := "192.168.1.100"
	cert, err := handler.generateDynamicCertificate(ipAddress)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify the certificate contains the IP address
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	assert.NoError(t, err)

	foundIP := false
	for _, ip := range x509Cert.IPAddresses {
		if ip.String() == ipAddress {
			foundIP = true
			break
		}
	}
	assert.True(t, foundIP, "Certificate should contain the IP address")
}

func TestSSLHandler_GetCertificateErrors(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(t, err)

	// Test with empty server name
	clientHello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	cert, err := handler.getCertificate(clientHello)
	assert.Error(t, err)
	assert.Nil(t, cert)
}

func TestSSLHandler_LoadExistingRootCA(t *testing.T) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// First, create a handler to generate the CA
	config1 := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		Organization:       "Original CA",
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler1, err := NewSSLHandler(config1, logger)
	require.NoError(t, err)

	originalCA := handler1.GetRootCA()
	require.NotNil(t, originalCA)

	// Now create a second handler that should load the existing CA
	config2 := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		Organization:       "Different CA", // This should be ignored
	}

	handler2, err := NewSSLHandler(config2, logger)
	require.NoError(t, err)

	loadedCA := handler2.GetRootCA()
	require.NotNil(t, loadedCA)

	// Should have loaded the original CA, not generated a new one
	assert.Equal(t, originalCA.SerialNumber, loadedCA.SerialNumber)
	assert.Equal(t, "Original CA Root CA", loadedCA.Subject.Organization[0])
}

// Benchmark tests
func BenchmarkSSLHandler_GenerateDynamicCertificate(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		ValidityDuration:   24 * time.Hour,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(b, err)

	hostnames := []string{
		"test1.example.com",
		"test2.example.com",
		"test3.example.com",
		"192.168.1.1",
		"api.service.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname := hostnames[i%len(hostnames)]
		_, err := handler.generateDynamicCertificate(hostname)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSSLHandler_GetCertificate(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "ssl_handler_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	config := &SSLConfig{
		CertDir:            tempDir,
		EnableDynamicCerts: true,
		ValidityDuration:   24 * time.Hour,
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler, err := NewSSLHandler(config, logger)
	require.NoError(b, err)

	// Pre-populate cache with a certificate
	clientHello := &tls.ClientHelloInfo{
		ServerName: "cached.example.com",
	}
	_, err = handler.getCertificate(clientHello)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This should hit the cache
		_, err := handler.getCertificate(clientHello)
		if err != nil {
			b.Fatal(err)
		}
	}
} 