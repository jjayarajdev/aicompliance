package policy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// TenantManager provides comprehensive tenant management and isolation
type TenantManager struct {
	tenants                 map[string]*Tenant
	tenantEngines          map[string]TenantPolicyEngineInterface
	tenantCaches           map[string]TenantCacheInterface
	tenantMetrics          map[string]TenantMetricsInterface
	tenantLoggers          map[string]TenantLoggerInterface
	isolationManager       TenantIsolationManager
	auditLogger           TenantLoggerInterface
	metrics               TenantMetricsInterface
	configuration         *TenantManagerConfig
	mu                    sync.RWMutex
	shutdownCh            chan struct{}
	backgroundTasks       sync.WaitGroup
}

// TenantManagerConfig contains configuration for the tenant manager
type TenantManagerConfig struct {
	DefaultIsolationLevel    IsolationLevel         `json:"default_isolation_level"`
	DefaultConfiguration     *TenantConfiguration   `json:"default_configuration"`
	DefaultResourceLimits    *TenantResourceLimits  `json:"default_resource_limits"`
	DefaultSecuritySettings  *TenantSecuritySettings `json:"default_security_settings"`
	
	// Manager settings
	EnableAutoCleanup        bool                   `json:"enable_auto_cleanup"`
	CleanupInterval          time.Duration          `json:"cleanup_interval"`
	EnableHealthMonitoring   bool                   `json:"enable_health_monitoring"`
	HealthCheckInterval      time.Duration          `json:"health_check_interval"`
	EnableUsageTracking      bool                   `json:"enable_usage_tracking"`
	UsageTrackingInterval    time.Duration          `json:"usage_tracking_interval"`
	
	// Resource management
	GlobalResourceLimits     *TenantResourceLimits  `json:"global_resource_limits"`
	EnableResourceEnforcement bool                  `json:"enable_resource_enforcement"`
	ResourceCheckInterval    time.Duration          `json:"resource_check_interval"`
	
	// Audit and compliance
	EnableAuditLogging       bool                   `json:"enable_audit_logging"`
	AuditRetentionDays       int                    `json:"audit_retention_days"`
	ComplianceMode           string                 `json:"compliance_mode"`
	
	// Performance
	EnablePerformanceOptimizations bool             `json:"enable_performance_optimizations"`
	CacheWarmupEnabled       bool                   `json:"cache_warmup_enabled"`
	BackgroundTaskWorkers    int                    `json:"background_task_workers"`
}

// NewTenantManager creates a new tenant manager instance
func NewTenantManager(config *TenantManagerConfig) *TenantManager {
	if config == nil {
		config = getDefaultTenantManagerConfig()
	}
	
	tm := &TenantManager{
		tenants:         make(map[string]*Tenant),
		tenantEngines:   make(map[string]TenantPolicyEngineInterface),
		tenantCaches:    make(map[string]TenantCacheInterface),
		tenantMetrics:   make(map[string]TenantMetricsInterface),
		tenantLoggers:   make(map[string]TenantLoggerInterface),
		configuration:   config,
		shutdownCh:      make(chan struct{}),
	}
	
	// Initialize isolation manager
	tm.isolationManager = NewTenantIsolationManagerImpl(config)
	
	// Start background tasks if enabled
	if config.EnableAutoCleanup {
		tm.backgroundTasks.Add(1)
		go tm.cleanupWorker()
	}
	
	if config.EnableHealthMonitoring {
		tm.backgroundTasks.Add(1)
		go tm.healthMonitorWorker()
	}
	
	if config.EnableUsageTracking {
		tm.backgroundTasks.Add(1)
		go tm.usageTrackingWorker()
	}
	
	return tm
}

// ===== TENANT LIFECYCLE MANAGEMENT =====

// CreateTenant creates a new tenant with complete isolation
func (tm *TenantManager) CreateTenant(request *CreateTenantRequest) (*Tenant, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	// Validate request
	if err := tm.validateCreateTenantRequest(request); err != nil {
		return nil, fmt.Errorf("invalid create tenant request: %w", err)
	}
	
	// Check if tenant already exists
	if _, exists := tm.tenants[request.Name]; exists {
		return nil, fmt.Errorf("tenant with name '%s' already exists", request.Name)
	}
	
	// Generate tenant ID and namespace
	tenantID := tm.generateTenantID()
	namespace := tm.generateNamespace(request.Name, tenantID)
	
	// Create tenant object
	tenant := &Tenant{
		ID:              tenantID,
		Name:            request.Name,
		DisplayName:     request.DisplayName,
		Description:     request.Description,
		Type:            request.Type,
		Status:          TenantStatusPending,
		Plan:            request.Plan,
		Tier:            request.Tier,
		Organization:    request.Organization,
		ContactEmail:    request.ContactEmail,
		ContactName:     request.ContactName,
		Domain:          request.Domain,
		Namespace:       namespace,
		IsolationLevel:  request.IsolationLevel,
		CreatedBy:       request.CreatedBy,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		FeatureFlags:    make(map[string]bool),
		Tags:            []string{},
		Metadata:        make(map[string]interface{}),
		CustomFields:    request.CustomFields,
	}
	
	// Set configuration
	if request.InitialConfiguration != nil {
		tenant.Configuration = request.InitialConfiguration
	} else {
		tenant.Configuration = tm.configuration.DefaultConfiguration
	}
	
	// Set resource limits
	tenant.ResourceLimits = tm.getResourceLimitsForTenant(request.Plan, request.Tier)
	
	// Set security settings
	tenant.SecuritySettings = tm.getSecuritySettingsForTenant(request.Type, request.Plan)
	
	// Set billing info
	if request.BillingInfo != nil {
		tenant.BillingInfo = request.BillingInfo
	}
	
	// Initialize usage metrics
	tenant.UsageMetrics = &TenantUsageMetrics{
		FirstRequest: nil,
		LastRequest:  nil,
		LastUpdated:  time.Now(),
	}
	
	// Create tenant isolation resources
	if err := tm.createTenantIsolationResources(tenant); err != nil {
		return nil, fmt.Errorf("failed to create tenant isolation resources: %w", err)
	}
	
	// Store tenant
	tm.tenants[tenantID] = tenant
	
	// Add initial users if provided
	if len(request.InitialUsers) > 0 {
		for _, user := range request.InitialUsers {
			user.TenantID = tenantID
			if err := tm.addTenantUserInternal(tenant, &user); err != nil {
				// Log error but don't fail tenant creation
				tm.logAuditEvent(tenantID, &TenantAuditEvent{
					Action:      "add_initial_user",
					Actor:       request.CreatedBy,
					ActorType:   "system",
					Resource:    "user",
					ResourceID:  user.UserID,
					Result:      "failure",
					ErrorMessage: err.Error(),
					Severity:    "medium",
				})
			}
		}
	}
	
	// Activate tenant
	tenant.Status = TenantStatusActive
	tenant.UpdatedAt = time.Now()
	
	// Log creation
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "create_tenant",
		Actor:      request.CreatedBy,
		ActorType:  "user",
		Resource:   "tenant",
		ResourceID: tenantID,
		Result:     "success",
		Details: map[string]interface{}{
			"tenant_name":  request.Name,
			"tenant_type":  request.Type,
			"tenant_plan":  request.Plan,
			"tenant_tier":  request.Tier,
			"isolation_level": request.IsolationLevel,
		},
		Severity: "high",
	})
	
	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (tm *TenantManager) GetTenant(tenantID string) (*Tenant, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Return a copy to prevent external modification
	return tm.copyTenant(tenant), nil
}

// GetTenantByName retrieves a tenant by name
func (tm *TenantManager) GetTenantByName(name string) (*Tenant, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	for _, tenant := range tm.tenants {
		if tenant.Name == name {
			return tm.copyTenant(tenant), nil
		}
	}
	
	return nil, fmt.Errorf("tenant not found with name: %s", name)
}

// GetTenantByDomain retrieves a tenant by domain
func (tm *TenantManager) GetTenantByDomain(domain string) (*Tenant, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	for _, tenant := range tm.tenants {
		if tenant.Domain == domain {
			return tm.copyTenant(tenant), nil
		}
	}
	
	return nil, fmt.Errorf("tenant not found with domain: %s", domain)
}

// UpdateTenant updates an existing tenant
func (tm *TenantManager) UpdateTenant(tenantID string, updates *TenantUpdateRequest) (*Tenant, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Apply updates
	originalTenant := tm.copyTenant(tenant)
	
	if updates.Name != nil && *updates.Name != tenant.Name {
		// Check for name conflicts
		if tm.tenantNameExists(*updates.Name, tenantID) {
			return nil, fmt.Errorf("tenant name '%s' already exists", *updates.Name)
		}
		tenant.Name = *updates.Name
	}
	
	if updates.DisplayName != nil {
		tenant.DisplayName = *updates.DisplayName
	}
	
	if updates.Description != nil {
		tenant.Description = *updates.Description
	}
	
	if updates.ContactEmail != nil {
		tenant.ContactEmail = *updates.ContactEmail
	}
	
	if updates.ContactName != nil {
		tenant.ContactName = *updates.ContactName
	}
	
	if updates.Domain != nil {
		tenant.Domain = *updates.Domain
	}
	
	if updates.Plan != nil {
		tenant.Plan = *updates.Plan
		// Update resource limits based on new plan
		tenant.ResourceLimits = tm.getResourceLimitsForTenant(*updates.Plan, tenant.Tier)
	}
	
	if updates.Tier != nil {
		tenant.Tier = *updates.Tier
		// Update resource limits based on new tier
		tenant.ResourceLimits = tm.getResourceLimitsForTenant(tenant.Plan, *updates.Tier)
	}
	
	if updates.Status != nil {
		tenant.Status = *updates.Status
	}
	
	if updates.FeatureFlags != nil {
		for key, value := range updates.FeatureFlags {
			tenant.FeatureFlags[key] = value
		}
	}
	
	if updates.Tags != nil {
		tenant.Tags = updates.Tags
	}
	
	if updates.CustomFields != nil {
		if tenant.CustomFields == nil {
			tenant.CustomFields = make(map[string]interface{})
		}
		for key, value := range updates.CustomFields {
			tenant.CustomFields[key] = value
		}
	}
	
	tenant.UpdatedAt = time.Now()
	
	// Log update
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "update_tenant",
		Actor:      updates.UpdatedBy,
		ActorType:  "user",
		Resource:   "tenant",
		ResourceID: tenantID,
		Result:     "success",
		Details: map[string]interface{}{
			"changes": tm.calculateTenantChanges(originalTenant, tenant),
		},
		Severity: "medium",
	})
	
	return tm.copyTenant(tenant), nil
}

// DeleteTenant removes a tenant and all its resources
func (tm *TenantManager) DeleteTenant(tenantID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Prevent deletion of active tenants
	if tenant.Status == TenantStatusActive {
		return fmt.Errorf("cannot delete active tenant: %s. Suspend or terminate first", tenantID)
	}
	
	// Clean up tenant isolation resources
	if err := tm.cleanupTenantIsolationResources(tenantID); err != nil {
		return fmt.Errorf("failed to cleanup tenant isolation resources: %w", err)
	}
	
	// Remove tenant
	delete(tm.tenants, tenantID)
	
	// Log deletion
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "delete_tenant",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "tenant",
		ResourceID: tenantID,
		Result:     "success",
		Details: map[string]interface{}{
			"tenant_name": tenant.Name,
		},
		Severity: "high",
	})
	
	return nil
}

// ListTenants returns a filtered list of tenants
func (tm *TenantManager) ListTenants(filters *TenantListFilters) ([]*Tenant, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	var result []*Tenant
	
	for _, tenant := range tm.tenants {
		if tm.matchesTenantFilters(tenant, filters) {
			result = append(result, tm.copyTenant(tenant))
		}
	}
	
	// Apply sorting
	if filters != nil && filters.SortBy != "" {
		tm.sortTenants(result, filters.SortBy, filters.SortOrder)
	}
	
	// Apply pagination
	if filters != nil && (filters.Limit > 0 || filters.Offset > 0) {
		result = tm.paginateTenants(result, filters.Limit, filters.Offset)
	}
	
	return result, nil
}

// ===== TENANT STATUS MANAGEMENT =====

// ActivateTenant activates a tenant
func (tm *TenantManager) ActivateTenant(tenantID string, activatedBy string) error {
	return tm.updateTenantStatus(tenantID, TenantStatusActive, "activate_tenant", activatedBy)
}

// SuspendTenant suspends a tenant
func (tm *TenantManager) SuspendTenant(tenantID string, reason string, suspendedBy string) error {
	return tm.updateTenantStatusWithReason(tenantID, TenantStatusSuspended, "suspend_tenant", suspendedBy, reason)
}

// ReactivateTenant reactivates a suspended tenant
func (tm *TenantManager) ReactivateTenant(tenantID string, reactivatedBy string) error {
	return tm.updateTenantStatus(tenantID, TenantStatusActive, "reactivate_tenant", reactivatedBy)
}

// TerminateTenant terminates a tenant
func (tm *TenantManager) TerminateTenant(tenantID string, reason string, terminatedBy string) error {
	return tm.updateTenantStatusWithReason(tenantID, TenantStatusTerminated, "terminate_tenant", terminatedBy, reason)
}

// ===== CONFIGURATION MANAGEMENT =====

// UpdateTenantConfiguration updates tenant configuration
func (tm *TenantManager) UpdateTenantConfiguration(tenantID string, config *TenantConfiguration) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	oldConfig := tenant.Configuration
	tenant.Configuration = config
	tenant.UpdatedAt = time.Now()
	
	// Update tenant engine configuration if it exists
	if engine, exists := tm.tenantEngines[tenantID]; exists {
		if err := engine.UpdateTenantConfiguration(config); err != nil {
			// Rollback on failure
			tenant.Configuration = oldConfig
			return fmt.Errorf("failed to update engine configuration: %w", err)
		}
	}
	
	// Log configuration update
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "update_configuration",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "configuration",
		ResourceID: tenantID,
		Result:     "success",
		Severity:   "medium",
	})
	
	return nil
}

// GetTenantConfiguration retrieves tenant configuration
func (tm *TenantManager) GetTenantConfiguration(tenantID string) (*TenantConfiguration, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	return tenant.Configuration, nil
}

// ResetTenantConfiguration resets tenant configuration to defaults
func (tm *TenantManager) ResetTenantConfiguration(tenantID string) error {
	return tm.UpdateTenantConfiguration(tenantID, tm.configuration.DefaultConfiguration)
}

// ===== RESOURCE MANAGEMENT =====

// UpdateResourceLimits updates tenant resource limits
func (tm *TenantManager) UpdateResourceLimits(tenantID string, limits *TenantResourceLimits) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	tenant.ResourceLimits = limits
	tenant.UpdatedAt = time.Now()
	
	// Update isolation manager with new limits
	if tm.isolationManager != nil {
		if err := tm.isolationManager.EnforceIsolation(tenantID); err != nil {
			return fmt.Errorf("failed to enforce new resource limits: %w", err)
		}
	}
	
	// Log resource limit update
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "update_resource_limits",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "resource_limits",
		ResourceID: tenantID,
		Result:     "success",
		Severity:   "medium",
	})
	
	return nil
}

// GetResourceUsage retrieves current resource usage for a tenant
func (tm *TenantManager) GetResourceUsage(tenantID string) (*TenantUsageMetrics, error) {
	tm.mu.RLock()
	tenant, exists := tm.tenants[tenantID]
	tm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Refresh usage metrics
	if err := tm.refreshTenantUsageMetrics(tenantID); err != nil {
		return nil, fmt.Errorf("failed to refresh usage metrics: %w", err)
	}
	
	return tenant.UsageMetrics, nil
}

// CheckResourceQuota checks if a tenant can consume a specific amount of a resource
func (tm *TenantManager) CheckResourceQuota(tenantID string, resource string, amount int64) (bool, error) {
	tm.mu.RLock()
	tenant, exists := tm.tenants[tenantID]
	tm.mu.RUnlock()
	
	if !exists {
		return false, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	if tenant.ResourceLimits == nil {
		return true, nil // No limits configured
	}
	
	// Check specific resource limits
	switch resource {
	case "requests_per_second":
		return tm.checkRateLimit(tenantID, "requests_per_second", amount, int64(tenant.ResourceLimits.MaxRequestsPerSecond))
	case "requests_per_minute":
		return tm.checkRateLimit(tenantID, "requests_per_minute", amount, int64(tenant.ResourceLimits.MaxRequestsPerMinute))
	case "requests_per_hour":
		return tm.checkRateLimit(tenantID, "requests_per_hour", amount, int64(tenant.ResourceLimits.MaxRequestsPerHour))
	case "requests_per_day":
		return tm.checkRateLimit(tenantID, "requests_per_day", amount, int64(tenant.ResourceLimits.MaxRequestsPerDay))
	case "memory":
		currentUsage := tenant.UsageMetrics.StorageUsed // This would track memory in a real implementation
		return currentUsage+amount <= tenant.ResourceLimits.MaxMemoryUsage, nil
	case "storage":
		currentUsage := tenant.UsageMetrics.StorageUsed
		return currentUsage+amount <= tenant.ResourceLimits.MaxStorageUsage, nil
	default:
		return true, nil // Unknown resource, allow by default
	}
}

// ===== HELPER METHODS =====

// generateTenantID generates a unique tenant ID
func (tm *TenantManager) generateTenantID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return "tenant_" + hex.EncodeToString(bytes)
}

// generateNamespace generates a unique namespace for a tenant
func (tm *TenantManager) generateNamespace(tenantName, tenantID string) string {
	// Create a safe namespace name
	safeName := strings.ToLower(strings.ReplaceAll(tenantName, " ", "_"))
	safeName = strings.ReplaceAll(safeName, "-", "_")
	
	// Add tenant ID suffix for uniqueness
	return fmt.Sprintf("tenant_%s_%s", safeName, tenantID[7:15]) // Use part of tenant ID
}

// validateCreateTenantRequest validates a create tenant request
func (tm *TenantManager) validateCreateTenantRequest(request *CreateTenantRequest) error {
	if request.Name == "" {
		return fmt.Errorf("tenant name is required")
	}
	
	if request.ContactEmail == "" {
		return fmt.Errorf("contact email is required")
	}
	
	if request.Organization == "" {
		return fmt.Errorf("organization is required")
	}
	
	if request.CreatedBy == "" {
		return fmt.Errorf("created_by is required")
	}
	
	// Validate enum values
	validTypes := []TenantType{TenantTypeEnterprise, TenantTypeStandard, TenantTypeStartup, TenantTypeTrial, TenantTypeInternal, TenantTypePartner, TenantTypeDeveloper}
	if !tm.contains(validTypes, request.Type) {
		return fmt.Errorf("invalid tenant type: %s", request.Type)
	}
	
	validPlans := []TenantPlan{TenantPlanFree, TenantPlanBasic, TenantPlanProfessional, TenantPlanEnterprise, TenantPlanCustom}
	if !tm.contains(validPlans, request.Plan) {
		return fmt.Errorf("invalid tenant plan: %s", request.Plan)
	}
	
	validTiers := []TenantTier{TenantTierShared, TenantTierDedicated, TenantTierIsolated, TenantTierPremium}
	if !tm.contains(validTiers, request.Tier) {
		return fmt.Errorf("invalid tenant tier: %s", request.Tier)
	}
	
	validIsolationLevels := []IsolationLevel{IsolationLevelStrict, IsolationLevelStandard, IsolationLevelBasic, IsolationLevelShared}
	if !tm.contains(validIsolationLevels, request.IsolationLevel) {
		return fmt.Errorf("invalid isolation level: %s", request.IsolationLevel)
	}
	
	return nil
}

// createTenantIsolationResources creates isolation resources for a tenant
func (tm *TenantManager) createTenantIsolationResources(tenant *Tenant) error {
	// Create tenant cache
	cache, err := tm.isolationManager.CreateTenantCache(tenant.ID)
	if err != nil {
		return fmt.Errorf("failed to create tenant cache: %w", err)
	}
	tm.tenantCaches[tenant.ID] = cache
	
	// Create tenant metrics
	metrics, err := tm.isolationManager.CreateTenantMetrics(tenant.ID)
	if err != nil {
		return fmt.Errorf("failed to create tenant metrics: %w", err)
	}
	tm.tenantMetrics[tenant.ID] = metrics
	
	// Create tenant logger
	logger, err := tm.isolationManager.CreateTenantLogger(tenant.ID)
	if err != nil {
		return fmt.Errorf("failed to create tenant logger: %w", err)
	}
	tm.tenantLoggers[tenant.ID] = logger
	
	// Create tenant policy engine
	engine, err := tm.isolationManager.CreateTenantPolicyEngine(tenant.ID, tenant.Configuration)
	if err != nil {
		return fmt.Errorf("failed to create tenant policy engine: %w", err)
	}
	tm.tenantEngines[tenant.ID] = engine
	
	return nil
}

// cleanupTenantIsolationResources cleans up isolation resources for a tenant
func (tm *TenantManager) cleanupTenantIsolationResources(tenantID string) error {
	var errors []string
	
	// Delete tenant policy engine
	if err := tm.isolationManager.DeleteTenantPolicyEngine(tenantID); err != nil {
		errors = append(errors, fmt.Sprintf("policy engine: %v", err))
	}
	delete(tm.tenantEngines, tenantID)
	
	// Delete tenant logger
	if err := tm.isolationManager.DeleteTenantLogger(tenantID); err != nil {
		errors = append(errors, fmt.Sprintf("logger: %v", err))
	}
	delete(tm.tenantLoggers, tenantID)
	
	// Delete tenant metrics
	if err := tm.isolationManager.DeleteTenantMetrics(tenantID); err != nil {
		errors = append(errors, fmt.Sprintf("metrics: %v", err))
	}
	delete(tm.tenantMetrics, tenantID)
	
	// Delete tenant cache
	if err := tm.isolationManager.DeleteTenantCache(tenantID); err != nil {
		errors = append(errors, fmt.Sprintf("cache: %v", err))
	}
	delete(tm.tenantCaches, tenantID)
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to cleanup resources: %s", strings.Join(errors, ", "))
	}
	
	return nil
}

// getDefaultTenantManagerConfig returns default configuration
func getDefaultTenantManagerConfig() *TenantManagerConfig {
	return &TenantManagerConfig{
		DefaultIsolationLevel:     IsolationLevelStandard,
		EnableAutoCleanup:         true,
		CleanupInterval:           24 * time.Hour,
		EnableHealthMonitoring:    true,
		HealthCheckInterval:       5 * time.Minute,
		EnableUsageTracking:       true,
		UsageTrackingInterval:     1 * time.Minute,
		EnableResourceEnforcement: true,
		ResourceCheckInterval:     30 * time.Second,
		EnableAuditLogging:        true,
		AuditRetentionDays:        90,
		EnablePerformanceOptimizations: true,
		CacheWarmupEnabled:        true,
		BackgroundTaskWorkers:     4,
	}
}

// Additional implementation continues... 

// ===== SECURITY AND ACCESS CONTROL =====

// UpdateSecuritySettings updates tenant security settings
func (tm *TenantManager) UpdateSecuritySettings(tenantID string, settings *TenantSecuritySettings) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	tenant.SecuritySettings = settings
	tenant.UpdatedAt = time.Now()
	
	// Log security settings update
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "update_security_settings",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "security_settings",
		ResourceID: tenantID,
		Result:     "success",
		Severity:   "high",
	})
	
	return nil
}

// ValidateTenantAccess validates if a user has access to perform an action on a tenant
func (tm *TenantManager) ValidateTenantAccess(tenantID string, userID string, action string) (bool, error) {
	tm.mu.RLock()
	tenant, exists := tm.tenants[tenantID]
	tm.mu.RUnlock()
	
	if !exists {
		return false, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Check tenant status
	if tenant.Status != TenantStatusActive {
		return false, fmt.Errorf("tenant is not active: %s", tenant.Status)
	}
	
	// Get tenant users and check permissions
	users, err := tm.GetTenantUsers(tenantID)
	if err != nil {
		return false, fmt.Errorf("failed to get tenant users: %w", err)
	}
	
	for _, user := range users {
		if user.UserID == userID {
			if user.Status != UserStatusActive {
				return false, fmt.Errorf("user is not active: %s", user.Status)
			}
			
			// Check if user has permission for the action
			return tm.userHasPermission(user, action), nil
		}
	}
	
	return false, fmt.Errorf("user not found in tenant: %s", userID)
}

// GetTenantUsers retrieves all users for a tenant
func (tm *TenantManager) GetTenantUsers(tenantID string) ([]TenantUser, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	_, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// In a real implementation, this would query a database
	// For now, return empty slice
	return []TenantUser{}, nil
}

// AddTenantUser adds a user to a tenant
func (tm *TenantManager) AddTenantUser(tenantID string, user *TenantUser) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	return tm.addTenantUserInternal(tenant, user)
}

// RemoveTenantUser removes a user from a tenant
func (tm *TenantManager) RemoveTenantUser(tenantID string, userID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	_, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Log user removal
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "remove_tenant_user",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "user",
		ResourceID: userID,
		Result:     "success",
		Severity:   "medium",
	})
	
	return nil
}

// ===== NAMESPACE AND ISOLATION =====

// GetTenantNamespace retrieves the namespace for a tenant
func (tm *TenantManager) GetTenantNamespace(tenantID string) (string, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return "", fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	return tenant.Namespace, nil
}

// EnsureNamespaceIsolation ensures proper namespace isolation for a tenant
func (tm *TenantManager) EnsureNamespaceIsolation(tenantID string) error {
	if tm.isolationManager == nil {
		return fmt.Errorf("isolation manager not available")
	}
	
	return tm.isolationManager.EnforceIsolation(tenantID)
}

// ValidateNamespaceAccess validates if a tenant has access to a namespace
func (tm *TenantManager) ValidateNamespaceAccess(tenantID string, namespace string) (bool, error) {
	tenantNamespace, err := tm.GetTenantNamespace(tenantID)
	if err != nil {
		return false, err
	}
	
	return tenantNamespace == namespace, nil
}

// ===== BILLING AND USAGE =====

// GetBillingInfo retrieves billing information for a tenant
func (tm *TenantManager) GetBillingInfo(tenantID string) (*TenantBillingInfo, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	return tenant.BillingInfo, nil
}

// UpdateBillingInfo updates billing information for a tenant
func (tm *TenantManager) UpdateBillingInfo(tenantID string, billing *TenantBillingInfo) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	tenant.BillingInfo = billing
	tenant.UpdatedAt = time.Now()
	
	// Log billing info update
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "update_billing_info",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "billing_info",
		ResourceID: tenantID,
		Result:     "success",
		Severity:   "medium",
	})
	
	return nil
}

// RecordUsage records usage for billing purposes
func (tm *TenantManager) RecordUsage(tenantID string, usage *UsageRecord) error {
	tm.mu.RLock()
	tenant, exists := tm.tenants[tenantID]
	tm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Update usage metrics
	if tenant.UsageMetrics != nil {
		switch usage.Resource {
		case "requests":
			tenant.UsageMetrics.TotalRequests += usage.Amount
			tenant.UsageMetrics.RequestsToday += usage.Amount
		case "storage":
			tenant.UsageMetrics.StorageUsed += usage.Amount
		case "bandwidth":
			tenant.UsageMetrics.BandwidthUsed += usage.Amount
		}
		
		tenant.UsageMetrics.LastRequest = &usage.Timestamp
		if tenant.UsageMetrics.FirstRequest == nil {
			tenant.UsageMetrics.FirstRequest = &usage.Timestamp
		}
		tenant.UsageMetrics.LastUpdated = time.Now()
	}
	
	return nil
}

// GetUsageReport generates a usage report for a tenant
func (tm *TenantManager) GetUsageReport(tenantID string, period *ReportPeriod) (*UsageReport, error) {
	tm.mu.RLock()
	tenant, exists := tm.tenants[tenantID]
	tm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	report := &UsageReport{
		TenantID:    tenantID,
		Period:      period,
		TotalUsage:  make(map[string]int64),
		UsageByDay:  []DailyUsage{},
		Costs:       make(map[string]float64),
		Currency:    "USD",
		GeneratedAt: time.Now(),
	}
	
	if tenant.UsageMetrics != nil {
		report.TotalUsage["requests"] = tenant.UsageMetrics.TotalRequests
		report.TotalUsage["storage"] = tenant.UsageMetrics.StorageUsed
		report.TotalUsage["bandwidth"] = tenant.UsageMetrics.BandwidthUsed
	}
	
	return report, nil
}

// ===== AUDIT AND COMPLIANCE =====

// GetTenantAuditLog retrieves audit log entries for a tenant
func (tm *TenantManager) GetTenantAuditLog(tenantID string, filters *AuditLogFilters) ([]TenantAuditEntry, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	_, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// In a real implementation, this would query a database
	return []TenantAuditEntry{}, nil
}

// RecordAuditEvent records an audit event for a tenant
func (tm *TenantManager) RecordAuditEvent(tenantID string, event *TenantAuditEvent) error {
	return tm.logAuditEvent(tenantID, event)
}

// ===== HEALTH AND MONITORING =====

// GetTenantHealth retrieves health status for a tenant
func (tm *TenantManager) GetTenantHealth(tenantID string) (*TenantHealthStatus, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	_, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	health := &TenantHealthStatus{
		TenantID:      tenantID,
		OverallStatus: HealthStatusHealthy,
		Components:    make(map[string]ComponentHealth),
		LastChecked:   time.Now(),
		Issues:        []HealthIssue{},
		Recommendations: []string{},
	}
	
	// Check component health
	health.Components["policy_engine"] = tm.checkPolicyEngineHealth(tenantID)
	health.Components["cache"] = tm.checkCacheHealth(tenantID)
	health.Components["metrics"] = tm.checkMetricsHealth(tenantID)
	health.Components["logging"] = tm.checkLoggingHealth(tenantID)
	
	// Determine overall health
	health.OverallStatus = tm.calculateOverallHealth(health.Components)
	
	return health, nil
}

// GetTenantMetrics retrieves metrics for a tenant
func (tm *TenantManager) GetTenantMetrics(tenantID string, period *ReportPeriod) (*TenantMetricsReport, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	_, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	report := &TenantMetricsReport{
		TenantID:    tenantID,
		Period:      period,
		GeneratedAt: time.Now(),
	}
	
	// Get metrics from tenant-specific metrics collector
	if metrics, exists := tm.tenantMetrics[tenantID]; exists {
		// Populate report with metrics data
		report.RequestMetrics = tm.buildRequestMetrics(metrics)
		report.PerformanceMetrics = tm.buildPerformanceMetrics(metrics)
		report.ResourceMetrics = tm.buildResourceMetrics(metrics)
		report.ErrorMetrics = tm.buildErrorMetrics(metrics)
		report.BusinessMetrics = tm.buildBusinessMetrics(metrics)
	}
	
	return report, nil
}

// AlertOnTenantIssues sends alerts for tenant issues
func (tm *TenantManager) AlertOnTenantIssues(tenantID string, alertType string, details map[string]interface{}) error {
	tm.mu.RLock()
	_, exists := tm.tenants[tenantID]
	tm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	// Log alert event
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     "tenant_alert",
		Actor:      "system",
		ActorType:  "system",
		Resource:   "alert",
		ResourceID: tenantID,
		Result:     "success",
		Details:    details,
		Severity:   "high",
	})
	
	// In a real implementation, this would send notifications
	// based on tenant notification configuration
	
	return nil
}

// ===== BACKGROUND WORKERS =====

// cleanupWorker performs periodic cleanup tasks
func (tm *TenantManager) cleanupWorker() {
	defer tm.backgroundTasks.Done()
	
	ticker := time.NewTicker(tm.configuration.CleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tm.performCleanupTasks()
		case <-tm.shutdownCh:
			return
		}
	}
}

// healthMonitorWorker performs periodic health checks
func (tm *TenantManager) healthMonitorWorker() {
	defer tm.backgroundTasks.Done()
	
	ticker := time.NewTicker(tm.configuration.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tm.performHealthChecks()
		case <-tm.shutdownCh:
			return
		}
	}
}

// usageTrackingWorker performs periodic usage tracking
func (tm *TenantManager) usageTrackingWorker() {
	defer tm.backgroundTasks.Done()
	
	ticker := time.NewTicker(tm.configuration.UsageTrackingInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			tm.updateUsageMetrics()
		case <-tm.shutdownCh:
			return
		}
	}
}

// ===== UTILITY METHODS =====

// copyTenant creates a deep copy of a tenant to prevent external modification
func (tm *TenantManager) copyTenant(tenant *Tenant) *Tenant {
	if tenant == nil {
		return nil
	}
	
	copied := *tenant
	
	// Deep copy maps and slices
	if tenant.FeatureFlags != nil {
		copied.FeatureFlags = make(map[string]bool)
		for k, v := range tenant.FeatureFlags {
			copied.FeatureFlags[k] = v
		}
	}
	
	if tenant.Tags != nil {
		copied.Tags = make([]string, len(tenant.Tags))
		copy(copied.Tags, tenant.Tags)
	}
	
	if tenant.Metadata != nil {
		copied.Metadata = make(map[string]interface{})
		for k, v := range tenant.Metadata {
			copied.Metadata[k] = v
		}
	}
	
	if tenant.CustomFields != nil {
		copied.CustomFields = make(map[string]interface{})
		for k, v := range tenant.CustomFields {
			copied.CustomFields[k] = v
		}
	}
	
	return &copied
}

// contains checks if a slice contains a value
func (tm *TenantManager) contains(slice interface{}, item interface{}) bool {
	switch s := slice.(type) {
	case []TenantType:
		for _, v := range s {
			if v == item {
				return true
			}
		}
	case []TenantPlan:
		for _, v := range s {
			if v == item {
				return true
			}
		}
	case []TenantTier:
		for _, v := range s {
			if v == item {
				return true
			}
		}
	case []IsolationLevel:
		for _, v := range s {
			if v == item {
				return true
			}
		}
	}
	return false
}

// tenantNameExists checks if a tenant name already exists
func (tm *TenantManager) tenantNameExists(name string, excludeTenantID string) bool {
	for id, tenant := range tm.tenants {
		if id != excludeTenantID && tenant.Name == name {
			return true
		}
	}
	return false
}

// updateTenantStatus updates tenant status with audit logging
func (tm *TenantManager) updateTenantStatus(tenantID string, status TenantStatus, action string, actor string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	oldStatus := tenant.Status
	tenant.Status = status
	tenant.UpdatedAt = time.Now()
	
	// Log status change
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     action,
		Actor:      actor,
		ActorType:  "user",
		Resource:   "tenant",
		ResourceID: tenantID,
		Result:     "success",
		Details: map[string]interface{}{
			"old_status": oldStatus,
			"new_status": status,
		},
		Severity: "high",
	})
	
	return nil
}

// updateTenantStatusWithReason updates tenant status with reason and audit logging
func (tm *TenantManager) updateTenantStatusWithReason(tenantID string, status TenantStatus, action string, actor string, reason string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}
	
	oldStatus := tenant.Status
	tenant.Status = status
	tenant.UpdatedAt = time.Now()
	
	// Log status change with reason
	tm.logAuditEvent(tenantID, &TenantAuditEvent{
		Action:     action,
		Actor:      actor,
		ActorType:  "user",
		Resource:   "tenant",
		ResourceID: tenantID,
		Result:     "success",
		Details: map[string]interface{}{
			"old_status": oldStatus,
			"new_status": status,
			"reason":     reason,
		},
		Severity: "high",
	})
	
	return nil
}

// logAuditEvent logs an audit event
func (tm *TenantManager) logAuditEvent(tenantID string, event *TenantAuditEvent) error {
	if !tm.configuration.EnableAuditLogging {
		return nil
	}
	
	if logger, exists := tm.tenantLoggers[tenantID]; exists {
		return logger.LogTenantEvent(event)
	}
	
	// Fallback to global audit logger if available
	if tm.auditLogger != nil {
		return tm.auditLogger.LogTenantEvent(event)
	}
	
	return nil
}

// calculateTenantChanges calculates changes between two tenant states
func (tm *TenantManager) calculateTenantChanges(original, updated *Tenant) map[string]interface{} {
	changes := make(map[string]interface{})
	
	if original.Name != updated.Name {
		changes["name"] = map[string]interface{}{
			"old": original.Name,
			"new": updated.Name,
		}
	}
	
	if original.DisplayName != updated.DisplayName {
		changes["display_name"] = map[string]interface{}{
			"old": original.DisplayName,
			"new": updated.DisplayName,
		}
	}
	
	if original.Plan != updated.Plan {
		changes["plan"] = map[string]interface{}{
			"old": original.Plan,
			"new": updated.Plan,
		}
	}
	
	if original.Tier != updated.Tier {
		changes["tier"] = map[string]interface{}{
			"old": original.Tier,
			"new": updated.Tier,
		}
	}
	
	if original.Status != updated.Status {
		changes["status"] = map[string]interface{}{
			"old": original.Status,
			"new": updated.Status,
		}
	}
	
	return changes
}

// Shutdown gracefully shuts down the tenant manager
func (tm *TenantManager) Shutdown(ctx context.Context) error {
	// Signal shutdown to background workers
	close(tm.shutdownCh)
	
	// Wait for background tasks to complete with timeout
	done := make(chan struct{})
	go func() {
		tm.backgroundTasks.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ===== MISSING HELPER METHODS =====

// getResourceLimitsForTenant returns appropriate resource limits based on plan and tier
func (tm *TenantManager) getResourceLimitsForTenant(plan TenantPlan, tier TenantTier) *TenantResourceLimits {
	limits := &TenantResourceLimits{}
	
	// Set base limits based on plan
	switch plan {
	case TenantPlanFree:
		limits.MaxRequestsPerSecond = 10
		limits.MaxRequestsPerMinute = 100
		limits.MaxRequestsPerHour = 1000
		limits.MaxRequestsPerDay = 10000
		limits.MaxPolicies = 5
		limits.MaxActiveRules = 20
		limits.MaxMemoryUsage = 50 * 1024 * 1024 // 50MB
		limits.MaxStorageUsage = 100 * 1024 * 1024 // 100MB
	case TenantPlanBasic:
		limits.MaxRequestsPerSecond = 50
		limits.MaxRequestsPerMinute = 1000
		limits.MaxRequestsPerHour = 10000
		limits.MaxRequestsPerDay = 100000
		limits.MaxPolicies = 25
		limits.MaxActiveRules = 100
		limits.MaxMemoryUsage = 200 * 1024 * 1024 // 200MB
		limits.MaxStorageUsage = 1024 * 1024 * 1024 // 1GB
	case TenantPlanProfessional:
		limits.MaxRequestsPerSecond = 200
		limits.MaxRequestsPerMinute = 5000
		limits.MaxRequestsPerHour = 50000
		limits.MaxRequestsPerDay = 1000000
		limits.MaxPolicies = 100
		limits.MaxActiveRules = 500
		limits.MaxMemoryUsage = 1024 * 1024 * 1024 // 1GB
		limits.MaxStorageUsage = 10 * 1024 * 1024 * 1024 // 10GB
	case TenantPlanEnterprise:
		limits.MaxRequestsPerSecond = 1000
		limits.MaxRequestsPerMinute = 30000
		limits.MaxRequestsPerHour = 500000
		limits.MaxRequestsPerDay = 10000000
		limits.MaxPolicies = 500
		limits.MaxActiveRules = 2500
		limits.MaxMemoryUsage = 4 * 1024 * 1024 * 1024 // 4GB
		limits.MaxStorageUsage = 100 * 1024 * 1024 * 1024 // 100GB
	default: // Custom
		limits.MaxRequestsPerSecond = 100
		limits.MaxRequestsPerMinute = 2000
		limits.MaxRequestsPerHour = 20000
		limits.MaxRequestsPerDay = 500000
		limits.MaxPolicies = 50
		limits.MaxActiveRules = 200
		limits.MaxMemoryUsage = 500 * 1024 * 1024 // 500MB
		limits.MaxStorageUsage = 5 * 1024 * 1024 * 1024 // 5GB
	}
	
	// Apply tier multipliers
	switch tier {
	case TenantTierShared:
		// No multiplier (base limits)
	case TenantTierDedicated:
		// 2x multiplier
		limits.MaxRequestsPerSecond *= 2
		limits.MaxRequestsPerMinute *= 2
		limits.MaxRequestsPerHour *= 2
		limits.MaxRequestsPerDay *= 2
		limits.MaxMemoryUsage *= 2
		limits.MaxStorageUsage *= 2
	case TenantTierIsolated:
		// 3x multiplier
		limits.MaxRequestsPerSecond *= 3
		limits.MaxRequestsPerMinute *= 3
		limits.MaxRequestsPerHour *= 3
		limits.MaxRequestsPerDay *= 3
		limits.MaxMemoryUsage *= 3
		limits.MaxStorageUsage *= 3
	case TenantTierPremium:
		// 5x multiplier
		limits.MaxRequestsPerSecond *= 5
		limits.MaxRequestsPerMinute *= 5
		limits.MaxRequestsPerHour *= 5
		limits.MaxRequestsPerDay *= 5
		limits.MaxMemoryUsage *= 5
		limits.MaxStorageUsage *= 5
	}
	
	// Set common limits
	limits.MaxContentSize = 10 * 1024 * 1024 // 10MB
	limits.MaxBatchSize = 100
	limits.MaxConcurrentEvaluations = 50
	limits.MaxCPUUsage = 80.0 // 80%
	limits.MaxEvaluationTime = 30 * time.Second
	limits.MaxProcessingTime = 60 * time.Second
	limits.MaxWebhooks = 10
	limits.MaxIntegrations = 5
	limits.MaxUsers = 100
	limits.MaxAdmins = 10
	
	return limits
}

// getSecuritySettingsForTenant returns appropriate security settings based on type and plan
func (tm *TenantManager) getSecuritySettingsForTenant(tenantType TenantType, plan TenantPlan) *TenantSecuritySettings {
	settings := &TenantSecuritySettings{
		RequireAuth:           true,
		AllowedAuthMethods:    []string{"jwt", "api_key"},
		MFARequired:           false,
		SessionTimeout:        24 * time.Hour,
		RequireHTTPS:          true,
		EncryptionRequired:    false,
		DataRetentionDays:     90,
		PIIRedactionEnabled:   false,
		AuditLoggingEnabled:   true,
		RequireDataAgreement:  true,
	}
	
	// Enhanced security for enterprise
	if tenantType == TenantTypeEnterprise || plan == TenantPlanEnterprise {
		settings.MFARequired = true
		settings.EncryptionRequired = true
		settings.PIIRedactionEnabled = true
		settings.SessionTimeout = 8 * time.Hour
		settings.DataRetentionDays = 365
		settings.ComplianceMode = "SOX"
	}
	
	// Basic security for trial/developer
	if tenantType == TenantTypeTrial || tenantType == TenantTypeDeveloper {
		settings.MFARequired = false
		settings.SessionTimeout = 7 * 24 * time.Hour
		settings.DataRetentionDays = 30
		settings.RequireDataAgreement = false
	}
	
	settings.PasswordPolicy = &PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   false,
		MaxAge:           90 * 24 * time.Hour,
		PreventReuse:     5,
	}
	
	settings.RBAC = &RBACSettings{
		Enabled:            true,
		InheritanceEnabled: true,
		Roles: []TenantRole{
			{
				ID:          "admin",
				Name:        "Administrator",
				Description: "Full administrative access",
				Permissions: []string{"*"},
				IsDefault:   false,
				IsSystemRole: true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			{
				ID:          "user",
				Name:        "User",
				Description: "Standard user access",
				Permissions: []string{"policies:read", "evaluations:create"},
				IsDefault:   true,
				IsSystemRole: true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
		Permissions: []TenantPermission{
			{
				ID:          "policies:read",
				Name:        "Read Policies",
				Description: "Read policy definitions",
				Resource:    "policies",
				Action:      "read",
				Scope:       "tenant",
			},
			{
				ID:          "policies:write",
				Name:        "Write Policies",
				Description: "Create and modify policies",
				Resource:    "policies",
				Action:      "write",
				Scope:       "tenant",
			},
			{
				ID:          "evaluations:create",
				Name:        "Create Evaluations",
				Description: "Execute policy evaluations",
				Resource:    "evaluations",
				Action:      "create",
				Scope:       "tenant",
			},
		},
		RoleAssignments: make(map[string][]string),
	}
	
	return settings
}

// addTenantUserInternal adds a user to a tenant (internal method)
func (tm *TenantManager) addTenantUserInternal(tenant *Tenant, user *TenantUser) error {
	// Validate user data
	if user.Email == "" {
		return fmt.Errorf("user email is required")
	}
	
	if user.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	
	// Set defaults
	user.TenantID = tenant.ID
	user.Status = UserStatusActive
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	
	if len(user.Roles) == 0 {
		user.Roles = []string{"user"} // Default role
	}
	
	// In a real implementation, this would store in a database
	return nil
}

// userHasPermission checks if a user has permission to perform an action
func (tm *TenantManager) userHasPermission(user TenantUser, action string) bool {
	// Check if user has admin role
	for _, role := range user.Roles {
		if role == "admin" {
			return true
		}
	}
	
	// Check specific permissions
	for _, permission := range user.Permissions {
		if permission == action || permission == "*" {
			return true
		}
	}
	
	return false
}

// checkRateLimit checks if a tenant is within rate limits
func (tm *TenantManager) checkRateLimit(tenantID string, resource string, amount int64, limit int64) (bool, error) {
	// In a real implementation, this would use a rate limiter like Redis
	// For now, just check if current + amount <= limit
	return amount <= limit, nil
}

// refreshTenantUsageMetrics refreshes usage metrics for a tenant
func (tm *TenantManager) refreshTenantUsageMetrics(tenantID string) error {
	// In a real implementation, this would collect metrics from various sources
	return nil
}

// matchesTenantFilters checks if a tenant matches the provided filters
func (tm *TenantManager) matchesTenantFilters(tenant *Tenant, filters *TenantListFilters) bool {
	if filters == nil {
		return true
	}
	
	// Check status filter
	if len(filters.Status) > 0 {
		found := false
		for _, status := range filters.Status {
			if tenant.Status == status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check type filter
	if len(filters.Type) > 0 {
		found := false
		for _, tenantType := range filters.Type {
			if tenant.Type == tenantType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check plan filter
	if len(filters.Plan) > 0 {
		found := false
		for _, plan := range filters.Plan {
			if tenant.Plan == plan {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check tier filter
	if len(filters.Tier) > 0 {
		found := false
		for _, tier := range filters.Tier {
			if tenant.Tier == tier {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check organization filter
	if filters.Organization != "" && tenant.Organization != filters.Organization {
		return false
	}
	
	// Check domain filter
	if filters.Domain != "" && tenant.Domain != filters.Domain {
		return false
	}
	
	// Check data region filter
	if filters.DataRegion != "" && tenant.DataRegion != filters.DataRegion {
		return false
	}
	
	// Check created after filter
	if filters.CreatedAfter != nil && tenant.CreatedAt.Before(*filters.CreatedAfter) {
		return false
	}
	
	// Check created before filter
	if filters.CreatedBefore != nil && tenant.CreatedAt.After(*filters.CreatedBefore) {
		return false
	}
	
	// Check tags filter
	if len(filters.Tags) > 0 {
		for _, filterTag := range filters.Tags {
			found := false
			for _, tenantTag := range tenant.Tags {
				if tenantTag == filterTag {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	
	// Check search query (simple contains match)
	if filters.SearchQuery != "" {
		query := strings.ToLower(filters.SearchQuery)
		if !strings.Contains(strings.ToLower(tenant.Name), query) &&
		   !strings.Contains(strings.ToLower(tenant.DisplayName), query) &&
		   !strings.Contains(strings.ToLower(tenant.Organization), query) {
			return false
		}
	}
	
	return true
}

// sortTenants sorts tenants based on the provided criteria
func (tm *TenantManager) sortTenants(tenants []*Tenant, sortBy string, sortOrder string) {
	if sortBy == "" {
		sortBy = "created_at"
	}
	
	if sortOrder == "" {
		sortOrder = "desc"
	}
	
	ascending := sortOrder == "asc"
	
	sort.Slice(tenants, func(i, j int) bool {
		var result bool
		
		switch sortBy {
		case "name":
			result = tenants[i].Name < tenants[j].Name
		case "display_name":
			result = tenants[i].DisplayName < tenants[j].DisplayName
		case "organization":
			result = tenants[i].Organization < tenants[j].Organization
		case "status":
			result = string(tenants[i].Status) < string(tenants[j].Status)
		case "plan":
			result = string(tenants[i].Plan) < string(tenants[j].Plan)
		case "tier":
			result = string(tenants[i].Tier) < string(tenants[j].Tier)
		case "created_at":
			result = tenants[i].CreatedAt.Before(tenants[j].CreatedAt)
		case "updated_at":
			result = tenants[i].UpdatedAt.Before(tenants[j].UpdatedAt)
		default:
			result = tenants[i].CreatedAt.Before(tenants[j].CreatedAt)
		}
		
		if ascending {
			return result
		}
		return !result
	})
}

// paginateTenants applies pagination to the tenant list
func (tm *TenantManager) paginateTenants(tenants []*Tenant, limit int, offset int) []*Tenant {
	if offset < 0 {
		offset = 0
	}
	
	if offset >= len(tenants) {
		return []*Tenant{}
	}
	
	end := offset + limit
	if limit <= 0 || end > len(tenants) {
		end = len(tenants)
	}
	
	return tenants[offset:end]
}

// ===== BACKGROUND WORKER IMPLEMENTATIONS =====

// performCleanupTasks performs periodic cleanup operations
func (tm *TenantManager) performCleanupTasks() {
	tm.mu.RLock()
	tenants := make([]*Tenant, 0, len(tm.tenants))
	for _, tenant := range tm.tenants {
		tenants = append(tenants, tenant)
	}
	tm.mu.RUnlock()
	
	for _, tenant := range tenants {
		// Clean up expired trial tenants
		if tenant.Type == TenantTypeTrial && tenant.Status == TenantStatusTrialExpired {
			if tenant.UpdatedAt.Add(7 * 24 * time.Hour).Before(time.Now()) {
				tm.TerminateTenant(tenant.ID, "Trial expired and cleanup period ended", "system")
			}
		}
		
		// Clean up terminated tenants after retention period
		if tenant.Status == TenantStatusTerminated {
			if tenant.UpdatedAt.Add(30 * 24 * time.Hour).Before(time.Now()) {
				tm.DeleteTenant(tenant.ID)
			}
		}
		
		// Rotate logs for tenant loggers
		if logger, exists := tm.tenantLoggers[tenant.ID]; exists {
			logger.RotateLogs()
			logger.PurgeLogs(time.Duration(tm.configuration.AuditRetentionDays) * 24 * time.Hour)
		}
	}
}

// performHealthChecks performs periodic health checks on all tenants
func (tm *TenantManager) performHealthChecks() {
	tm.mu.RLock()
	tenants := make([]*Tenant, 0, len(tm.tenants))
	for _, tenant := range tm.tenants {
		tenants = append(tenants, tenant)
	}
	tm.mu.RUnlock()
	
	for _, tenant := range tenants {
		// Check tenant health
		health, err := tm.GetTenantHealth(tenant.ID)
		if err != nil {
			continue
		}
		
		// Alert on critical issues
		if health.OverallStatus == HealthStatusCritical {
			tm.AlertOnTenantIssues(tenant.ID, "critical_health", map[string]interface{}{
				"health_status": health.OverallStatus,
				"issues_count":  len(health.Issues),
			})
		}
		
		// Check isolation health
		if tm.isolationManager != nil {
			isolationHealth, err := tm.isolationManager.CheckTenantIsolation(tenant.ID)
			if err == nil && len(isolationHealth.Issues) > 0 {
				tm.AlertOnTenantIssues(tenant.ID, "isolation_violation", map[string]interface{}{
					"issues": isolationHealth.Issues,
				})
			}
		}
	}
}

// updateUsageMetrics updates usage metrics for all tenants
func (tm *TenantManager) updateUsageMetrics() {
	tm.mu.RLock()
	tenants := make([]*Tenant, 0, len(tm.tenants))
	for _, tenant := range tm.tenants {
		tenants = append(tenants, tenant)
	}
	tm.mu.RUnlock()
	
	for _, tenant := range tenants {
		// Update tenant usage metrics
		tm.refreshTenantUsageMetrics(tenant.ID)
		
		// Check resource quotas
		if tenant.ResourceLimits != nil {
			usage, _ := tm.GetResourceUsage(tenant.ID)
			if usage != nil {
				// Check memory usage
				if usage.StorageUsed > tenant.ResourceLimits.MaxStorageUsage {
					tm.AlertOnTenantIssues(tenant.ID, "quota_exceeded", map[string]interface{}{
						"resource":     "storage",
						"used":         usage.StorageUsed,
						"limit":        tenant.ResourceLimits.MaxStorageUsage,
						"usage_percent": float64(usage.StorageUsed) / float64(tenant.ResourceLimits.MaxStorageUsage) * 100,
					})
				}
				
				// Check request limits
				if usage.RequestsToday > int64(tenant.ResourceLimits.MaxRequestsPerDay) {
					tm.AlertOnTenantIssues(tenant.ID, "quota_exceeded", map[string]interface{}{
						"resource":     "requests_per_day",
						"used":         usage.RequestsToday,
						"limit":        tenant.ResourceLimits.MaxRequestsPerDay,
						"usage_percent": float64(usage.RequestsToday) / float64(tenant.ResourceLimits.MaxRequestsPerDay) * 100,
					})
				}
			}
		}
	}
}

// ===== HEALTH CHECK HELPERS =====

// checkPolicyEngineHealth checks the health of a tenant's policy engine
func (tm *TenantManager) checkPolicyEngineHealth(tenantID string) ComponentHealth {
	if engine, exists := tm.tenantEngines[tenantID]; exists {
		health := engine.GetHealthStatus()
		return ComponentHealth{
			Name:         "policy_engine",
			Status:       health.PolicyEngineStatus,
			ResponseTime: health.HealthCheckDuration,
			ErrorRate:    0, // Placeholder
		}
	}
	
	return ComponentHealth{
		Name:         "policy_engine",
		Status:       HealthStatusUnhealthy,
		ResponseTime: 0,
		ErrorRate:    100,
	}
}

// checkCacheHealth checks the health of a tenant's cache
func (tm *TenantManager) checkCacheHealth(tenantID string) ComponentHealth {
	if cache, exists := tm.tenantCaches[tenantID]; exists {
		stats := cache.GetCacheStats()
		
		status := HealthStatusHealthy
		if stats.MemoryUsed > stats.MemoryLimit*9/10 { // 90% threshold
			status = HealthStatusDegraded
		}
		
		return ComponentHealth{
			Name:         "cache",
			Status:       status,
			ResponseTime: time.Millisecond,
			ErrorRate:    0,
		}
	}
	
	return ComponentHealth{
		Name:         "cache",
		Status:       HealthStatusUnhealthy,
		ResponseTime: 0,
		ErrorRate:    100,
	}
}

// checkMetricsHealth checks the health of a tenant's metrics
func (tm *TenantManager) checkMetricsHealth(tenantID string) ComponentHealth {
	if metrics, exists := tm.tenantMetrics[tenantID]; exists {
		stats := metrics.GetTenantStats()
		
		status := HealthStatusHealthy
		if stats.MetricsDropped > 0 {
			status = HealthStatusDegraded
		}
		
		return ComponentHealth{
			Name:         "metrics",
			Status:       status,
			ResponseTime: time.Millisecond,
			ErrorRate:    float64(stats.MetricsDropped) / float64(stats.MetricsCollected) * 100,
		}
	}
	
	return ComponentHealth{
		Name:         "metrics",
		Status:       HealthStatusUnhealthy,
		ResponseTime: 0,
		ErrorRate:    100,
	}
}

// checkLoggingHealth checks the health of a tenant's logging
func (tm *TenantManager) checkLoggingHealth(tenantID string) ComponentHealth {
	if logger, exists := tm.tenantLoggers[tenantID]; exists {
		stats := logger.GetLogStats()
		
		status := HealthStatusHealthy
		if stats.LogsDropped > 0 {
			status = HealthStatusDegraded
		}
		
		return ComponentHealth{
			Name:         "logging",
			Status:       status,
			ResponseTime: time.Millisecond,
			ErrorRate:    float64(stats.LogsDropped) / float64(stats.LogsGenerated) * 100,
		}
	}
	
	return ComponentHealth{
		Name:         "logging",
		Status:       HealthStatusUnhealthy,
		ResponseTime: 0,
		ErrorRate:    100,
	}
}

// calculateOverallHealth calculates overall health from component health
func (tm *TenantManager) calculateOverallHealth(components map[string]ComponentHealth) HealthStatus {
	if len(components) == 0 {
		return HealthStatusUnhealthy
	}
	
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	
	for _, component := range components {
		switch component.Status {
		case HealthStatusHealthy:
			healthyCount++
		case HealthStatusDegraded:
			degradedCount++
		default:
			unhealthyCount++
		}
	}
	
	// If more than half are unhealthy, overall is unhealthy
	if unhealthyCount > len(components)/2 {
		return HealthStatusUnhealthy
	}
	
	// If any are degraded, overall is degraded
	if degradedCount > 0 {
		return HealthStatusDegraded
	}
	
	// All are healthy
	return HealthStatusHealthy
}

// ===== METRICS BUILDER HELPERS =====

// buildRequestMetrics builds request metrics from tenant metrics
func (tm *TenantManager) buildRequestMetrics(metrics TenantMetricsInterface) *RequestMetrics {
	return &RequestMetrics{
		TotalRequests:      0, // Placeholder
		SuccessfulRequests: 0,
		FailedRequests:     0,
		RequestsPerSecond:  0,
		RequestsByStatus:   make(map[string]int64),
		RequestsByEndpoint: make(map[string]int64),
		RequestTrends:      []RequestTrend{},
	}
}

// buildPerformanceMetrics builds performance metrics from tenant metrics
func (tm *TenantManager) buildPerformanceMetrics(metrics TenantMetricsInterface) *PerformanceMetrics {
	return &PerformanceMetrics{
		AverageLatency: time.Millisecond,
		MedianLatency:  time.Millisecond,
		P95Latency:     time.Millisecond * 5,
		P99Latency:     time.Millisecond * 10,
		MaxLatency:     time.Millisecond * 20,
		LatencyTrends:  []LatencyTrend{},
		ThroughputTrends: []ThroughputTrend{},
	}
}

// buildResourceMetrics builds resource metrics from tenant metrics
func (tm *TenantManager) buildResourceMetrics(metrics TenantMetricsInterface) *ResourceMetrics {
	return &ResourceMetrics{
		CPUUsage:          0,
		MemoryUsage:       0,
		StorageUsage:      0,
		BandwidthUsage:    0,
		CacheHitRatio:     0.8,
		CacheSize:         0,
		ActiveConnections: 0,
		ResourceTrends:    []ResourceTrend{},
	}
}

// buildErrorMetrics builds error metrics from tenant metrics
func (tm *TenantManager) buildErrorMetrics(metrics TenantMetricsInterface) *ErrorMetrics {
	return &ErrorMetrics{
		TotalErrors:        0,
		ErrorRate:          0,
		ErrorsByType:       make(map[string]int64),
		ErrorsByComponent:  make(map[string]int64),
		RecoverableErrors:  0,
		FatalErrors:        0,
		ErrorTrends:        []ErrorTrend{},
	}
}

// buildBusinessMetrics builds business metrics from tenant metrics
func (tm *TenantManager) buildBusinessMetrics(metrics TenantMetricsInterface) *BusinessMetrics {
	return &BusinessMetrics{
		ActiveUsers:         0,
		ActivePolicies:      0,
		PolicyEvaluations:   0,
		PolicyMatches:       0,
		MatchRate:           0,
		BlockedRequests:     0,
		AllowedRequests:     0,
		ConflictResolutions: 0,
		FeatureUsage:        make(map[string]int64),
	}
} 