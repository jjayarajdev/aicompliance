package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// SecretResolver handles resolving secret references in configuration
type SecretResolver struct {
	envVarRegex *regexp.Regexp
}

// NewSecretResolver creates a new secret resolver
func NewSecretResolver() *SecretResolver {
	return &SecretResolver{
		envVarRegex: regexp.MustCompile(`\$\{([^}]+)\}`),
	}
}

// ResolveString resolves environment variable references in a string
func (sr *SecretResolver) ResolveString(value *string) error {
	if value == nil || *value == "" {
		return nil
	}
	
	resolved := sr.envVarRegex.ReplaceAllStringFunc(*value, func(match string) string {
		// Extract the variable name from ${VAR_NAME} or ${VAR_NAME:-default}
		envVar := strings.TrimPrefix(strings.TrimSuffix(match, "}"), "${")
		
		// Handle default values
		var varName, defaultValue string
		if strings.Contains(envVar, ":-") {
			parts := strings.SplitN(envVar, ":-", 2)
			varName = parts[0]
			defaultValue = parts[1]
		} else {
			varName = envVar
		}
		
		// Get environment variable
		if envValue, exists := os.LookupEnv(varName); exists {
			return envValue
		}
		
		// Return default value if provided
		if defaultValue != "" {
			return defaultValue
		}
		
		// Return original if no default and env var not found
		return match
	})
	
	*value = resolved
	return nil
}

// ValidateSecrets validates that required secrets are available
func (sr *SecretResolver) ValidateSecrets(config *Config) error {
	var missing []string
	
	// Check required API keys
	if config.Providers.OpenAI.APIKey == "" || strings.Contains(config.Providers.OpenAI.APIKey, "${") {
		missing = append(missing, "OpenAI API key")
	}
	
	if config.Providers.Anthropic.APIKey == "" || strings.Contains(config.Providers.Anthropic.APIKey, "${") {
		missing = append(missing, "Anthropic API key")
	}
	
	// Check JWT secret in production
	if config.Environment == "production" {
		if config.Security.JWTSecret == "" || strings.Contains(config.Security.JWTSecret, "${") {
			missing = append(missing, "JWT secret")
		}
	}
	
	if len(missing) > 0 {
		return fmt.Errorf("missing required secrets: %s", strings.Join(missing, ", "))
	}
	
	return nil
} 