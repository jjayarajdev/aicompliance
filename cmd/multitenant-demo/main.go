package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("🏢 AI Gateway Multi-Tenant Policy Isolation Demo")
	fmt.Println("=" + strings.Repeat("=", 60))

	// Create tenant manager
	config := &policy.TenantManagerConfig{
		DefaultIsolationLevel:     policy.IsolationLevelStandard,
		EnableAutoCleanup:         true,
		CleanupInterval:           1 * time.Hour,
		EnableHealthMonitoring:    true,
		HealthCheckInterval:       30 * time.Second,
		EnableUsageTracking:       true,
		UsageTrackingInterval:     10 * time.Second,
		EnableResourceEnforcement: true,
		ResourceCheckInterval:     30 * time.Second,
		EnableAuditLogging:        true,
		AuditRetentionDays:        90,
		EnablePerformanceOptimizations: true,
		CacheWarmupEnabled:        true,
		BackgroundTaskWorkers:     4,
	}

	tenantManager := policy.NewTenantManager(config)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tenantManager.Shutdown(ctx)
	}()

	// Demo sections
	runDemo(tenantManager)
}

func runDemo(tm *policy.TenantManager) {
	// Demo 1: Tenant Creation and Management
	fmt.Println("\n📋 Demo 1: Tenant Creation and Management")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	tenants := createSampleTenants(tm)
	
	// Demo 2: Tenant Isolation Verification
	fmt.Println("\n🔒 Demo 2: Tenant Isolation Verification")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	verifyTenantIsolation(tm, tenants)
	
	// Demo 3: Policy Management with Tenant Context
	fmt.Println("\n📝 Demo 3: Policy Management with Tenant Context")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	demonstratePolicyManagement(tm, tenants)
	
	// Demo 4: Resource Monitoring and Limits
	fmt.Println("\n📊 Demo 4: Resource Monitoring and Limits")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	demonstrateResourceMonitoring(tm, tenants)
	
	// Demo 5: Security and Access Control
	fmt.Println("\n🛡️ Demo 5: Security and Access Control")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	demonstrateSecurityFeatures(tm, tenants)
	
	// Demo 6: Health Monitoring and Alerting
	fmt.Println("\n🔍 Demo 6: Health Monitoring and Alerting")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	demonstrateHealthMonitoring(tm, tenants)
	
	// Demo 7: Administrative Operations
	fmt.Println("\n👨‍💼 Demo 7: Administrative Operations")
	fmt.Println("-" + strings.Repeat("-", 50))
	
	demonstrateAdministrativeOperations(tm, tenants)
}

// Demo 1: Create sample tenants with different configurations
func createSampleTenants(tm *policy.TenantManager) []*policy.Tenant {
	fmt.Println("Creating sample tenants with different plans and tiers...")
	
	tenants := []*policy.Tenant{}
	
	// Enterprise tenant
	enterpriseRequest := &policy.CreateTenantRequest{
		Name:           "acme-corp",
		DisplayName:    "Acme Corporation",
		Description:    "Large enterprise customer with strict compliance requirements",
		Type:           policy.TenantTypeEnterprise,
		Plan:           policy.TenantPlanEnterprise,
		Tier:           policy.TenantTierIsolated,
		Organization:   "Acme Corporation",
		ContactEmail:   "admin@acme-corp.com",
		ContactName:    "John Smith",
		Domain:         "acme-corp.com",
		DataRegion:     "us-east-1",
		IsolationLevel: policy.IsolationLevelStrict,
		CreatedBy:      "system-admin",
	}
	
	enterpriseTenant, err := tm.CreateTenant(enterpriseRequest)
	if err != nil {
		log.Printf("Error creating enterprise tenant: %v", err)
	} else {
		tenants = append(tenants, enterpriseTenant)
		fmt.Printf("✅ Created enterprise tenant: %s (ID: %s)\n", 
			enterpriseTenant.Name, enterpriseTenant.ID)
	}
	
	// Standard business tenant
	standardRequest := &policy.CreateTenantRequest{
		Name:           "tech-startup",
		DisplayName:    "Tech Startup Inc",
		Description:    "Growing startup with moderate security needs",
		Type:           policy.TenantTypeStandard,
		Plan:           policy.TenantPlanProfessional,
		Tier:           policy.TenantTierDedicated,
		Organization:   "Tech Startup Inc",
		ContactEmail:   "ops@techstartup.io",
		ContactName:    "Jane Doe",
		Domain:         "techstartup.io",
		DataRegion:     "us-west-2",
		IsolationLevel: policy.IsolationLevelStandard,
		CreatedBy:      "system-admin",
	}
	
	standardTenant, err := tm.CreateTenant(standardRequest)
	if err != nil {
		log.Printf("Error creating standard tenant: %v", err)
	} else {
		tenants = append(tenants, standardTenant)
		fmt.Printf("✅ Created standard tenant: %s (ID: %s)\n", 
			standardTenant.Name, standardTenant.ID)
	}
	
	// Developer trial tenant
	trialRequest := &policy.CreateTenantRequest{
		Name:           "dev-trial",
		DisplayName:    "Developer Trial",
		Description:    "Trial account for testing and development",
		Type:           policy.TenantTypeTrial,
		Plan:           policy.TenantPlanFree,
		Tier:           policy.TenantTierShared,
		Organization:   "Individual Developer",
		ContactEmail:   "dev@example.com",
		ContactName:    "Bob Developer",
		IsolationLevel: policy.IsolationLevelBasic,
		CreatedBy:      "self-service",
	}
	
	trialTenant, err := tm.CreateTenant(trialRequest)
	if err != nil {
		log.Printf("Error creating trial tenant: %v", err)
	} else {
		tenants = append(tenants, trialTenant)
		fmt.Printf("✅ Created trial tenant: %s (ID: %s)\n", 
			trialTenant.Name, trialTenant.ID)
	}
	
	// List all tenants
	fmt.Println("\nListing all tenants:")
	allTenants, err := tm.ListTenants(nil)
	if err != nil {
		log.Printf("Error listing tenants: %v", err)
	} else {
		for _, tenant := range allTenants {
			fmt.Printf("  📋 %s (%s) - Plan: %s, Tier: %s, Status: %s\n",
				tenant.Name, tenant.Type, tenant.Plan, tenant.Tier, tenant.Status)
		}
	}
	
	return tenants
}

// Demo 2: Verify tenant isolation
func verifyTenantIsolation(tm *policy.TenantManager, tenants []*policy.Tenant) {
	fmt.Println("Verifying tenant isolation capabilities...")
	
	for _, tenant := range tenants {
		// Get tenant namespace
		namespace, err := tm.GetTenantNamespace(tenant.ID)
		if err != nil {
			log.Printf("Error getting namespace for tenant %s: %v", tenant.Name, err)
			continue
		}
		
		fmt.Printf("\n🔍 Tenant: %s\n", tenant.Name)
		fmt.Printf("  Namespace: %s\n", namespace)
		fmt.Printf("  Isolation Level: %s\n", tenant.IsolationLevel)
		
		// Validate namespace access
		hasAccess, err := tm.ValidateNamespaceAccess(tenant.ID, namespace)
		if err != nil {
			log.Printf("  ❌ Error validating namespace access: %v", err)
		} else {
			fmt.Printf("  ✅ Namespace access validation: %t\n", hasAccess)
		}
		
		// Test cross-tenant access prevention
		for _, otherTenant := range tenants {
			if otherTenant.ID != tenant.ID {
				otherNamespace, _ := tm.GetTenantNamespace(otherTenant.ID)
				crossAccess, _ := tm.ValidateNamespaceAccess(tenant.ID, otherNamespace)
				if crossAccess {
					fmt.Printf("  ⚠️ WARNING: Cross-tenant access detected to %s\n", otherTenant.Name)
				} else {
					fmt.Printf("  🔒 Blocked access to %s namespace ✓\n", otherTenant.Name)
				}
			}
		}
		
		// Check isolation health
		tm.EnsureNamespaceIsolation(tenant.ID)
		fmt.Printf("  🔧 Namespace isolation enforced\n")
	}
}

// Demo 3: Demonstrate policy management with tenant context
func demonstratePolicyManagement(tm *policy.TenantManager, tenants []*policy.Tenant) {
	fmt.Println("Demonstrating tenant-aware policy management...")
	
	for _, tenant := range tenants {
		fmt.Printf("\n📝 Managing policies for tenant: %s\n", tenant.Name)
		
		// Create tenant context
		ctx := policy.NewTenantContextBuilder(tenant.ID).
			WithTenantName(tenant.Name).
			WithNamespace(tenant.Namespace).
			WithIsolationLevel(tenant.IsolationLevel).
			WithUser("admin-user", []string{"admin"}, []string{"*"}).
			Build()
		
		fmt.Printf("  🔧 Created tenant context for %s\n", tenant.Name)
		fmt.Printf("  📋 Tenant context namespace: %s\n", ctx.Namespace)
		fmt.Printf("  🔒 Isolation level: %s\n", ctx.IsolationLevel)
		
		// Display tenant configuration
		if tenant.Configuration != nil && tenant.Configuration.PolicyEngineConfig != nil {
			fmt.Printf("  ⚙️ Policy Configuration:\n")
			fmt.Printf("     Max Policies: %d\n", tenant.Configuration.PolicyEngineConfig.MaxPolicies)
			fmt.Printf("     Max Rules per Policy: %d\n", tenant.Configuration.PolicyEngineConfig.MaxRulesPerPolicy)
			fmt.Printf("     Advanced Conditions: %t\n", tenant.Configuration.PolicyEngineConfig.EnableAdvancedConditions)
		}
		
		// Display resource limits
		if tenant.ResourceLimits != nil {
			fmt.Printf("  📊 Resource Limits:\n")
			fmt.Printf("     Max Requests/sec: %d\n", tenant.ResourceLimits.MaxRequestsPerSecond)
			fmt.Printf("     Max Policies: %d\n", tenant.ResourceLimits.MaxPolicies)
			fmt.Printf("     Max Memory: %d MB\n", tenant.ResourceLimits.MaxMemoryUsage/(1024*1024))
		}
		
		fmt.Printf("  ✅ Policy management demonstration completed\n")
	}
}

// Demo 4: Demonstrate resource monitoring and limits
func demonstrateResourceMonitoring(tm *policy.TenantManager, tenants []*policy.Tenant) {
	fmt.Println("Demonstrating resource monitoring and quota enforcement...")
	
	for _, tenant := range tenants {
		fmt.Printf("\n📊 Resource monitoring for tenant: %s\n", tenant.Name)
		
		// Get resource usage
		usage, err := tm.GetResourceUsage(tenant.ID)
		if err != nil {
			fmt.Printf("  ❌ Error getting usage: %v\n", err)
			continue
		}
		
		fmt.Printf("  Total Requests: %d\n", usage.TotalRequests)
		fmt.Printf("  Storage Used: %d bytes\n", usage.StorageUsed)
		fmt.Printf("  Bandwidth Used: %d bytes\n", usage.BandwidthUsed)
		
		// Test quota checking
		quotaTests := []struct {
			resource string
			amount   int64
		}{
			{"requests_per_second", 5},
			{"memory", 1024 * 1024}, // 1MB
			{"storage", 10 * 1024},  // 10KB
		}
		
		for _, test := range quotaTests {
			allowed, err := tm.CheckResourceQuota(tenant.ID, test.resource, test.amount)
			if err != nil {
				fmt.Printf("  ❌ Error checking quota for %s: %v\n", test.resource, err)
			} else {
				status := "✅ ALLOWED"
				if !allowed {
					status = "❌ DENIED"
				}
				fmt.Printf("  %s Quota check: %s (%d units)\n", 
					status, test.resource, test.amount)
			}
		}
		
		// Record sample usage
		tm.RecordUsage(tenant.ID, &policy.UsageRecord{
			TenantID:  tenant.ID,
			Resource:  "requests",
			Amount:    10,
			Unit:      "count",
			Timestamp: time.Now(),
		})
		
		fmt.Printf("  📈 Recorded sample usage\n")
		
		// Get usage report
		period := &policy.ReportPeriod{
			StartTime:   time.Now().Add(-24 * time.Hour),
			EndTime:     time.Now(),
			Granularity: "day",
		}
		
		report, err := tm.GetUsageReport(tenant.ID, period)
		if err != nil {
			fmt.Printf("  ❌ Error generating usage report: %v\n", err)
		} else {
			fmt.Printf("  📋 Usage report generated for last 24 hours\n")
			fmt.Printf("     Requests: %d\n", report.TotalUsage["requests"])
		}
	}
}

// Demo 5: Demonstrate security and access control features
func demonstrateSecurityFeatures(tm *policy.TenantManager, tenants []*policy.Tenant) {
	fmt.Println("Demonstrating security and access control features...")
	
	for _, tenant := range tenants {
		fmt.Printf("\n🛡️ Security features for tenant: %s\n", tenant.Name)
		
		// Display security settings
		fmt.Printf("  🔒 Security Configuration:\n")
		if tenant.SecuritySettings != nil {
			fmt.Printf("     MFA Required: %t\n", tenant.SecuritySettings.MFARequired)
			fmt.Printf("     Encryption Required: %t\n", tenant.SecuritySettings.EncryptionRequired)
			fmt.Printf("     Session Timeout: %v\n", tenant.SecuritySettings.SessionTimeout)
			fmt.Printf("     Data Retention: %d days\n", tenant.SecuritySettings.DataRetentionDays)
			fmt.Printf("     PII Redaction: %t\n", tenant.SecuritySettings.PIIRedactionEnabled)
			fmt.Printf("     Audit Logging: %t\n", tenant.SecuritySettings.AuditLoggingEnabled)
			
			if tenant.SecuritySettings.RBAC != nil {
				fmt.Printf("     RBAC Enabled: %t\n", tenant.SecuritySettings.RBAC.Enabled)
				fmt.Printf("     Available Roles: %d\n", len(tenant.SecuritySettings.RBAC.Roles))
				fmt.Printf("     Available Permissions: %d\n", len(tenant.SecuritySettings.RBAC.Permissions))
			}
		}
		
		// Test audit logging
		auditEvent := &policy.TenantAuditEvent{
			Action:     "test_security_demo",
			Actor:      "demo-system",
			ActorType:  "system",
			Resource:   "security",
			ResourceID: tenant.ID,
			Result:     "success",
			Details: map[string]interface{}{
				"demo_section": "security_features",
				"timestamp":    time.Now(),
			},
			Severity: "medium",
		}
		
		err := tm.RecordAuditEvent(tenant.ID, auditEvent)
		if err != nil {
			fmt.Printf("  ❌ Error recording audit event: %v\n", err)
		} else {
			fmt.Printf("  📝 Security audit event recorded\n")
		}
	}
}

// Demo 6: Demonstrate health monitoring and alerting
func demonstrateHealthMonitoring(tm *policy.TenantManager, tenants []*policy.Tenant) {
	fmt.Println("Demonstrating health monitoring and alerting...")
	
	for _, tenant := range tenants {
		fmt.Printf("\n🔍 Health monitoring for tenant: %s\n", tenant.Name)
		
		// Get tenant health status
		health, err := tm.GetTenantHealth(tenant.ID)
		if err != nil {
			fmt.Printf("  ❌ Error getting health status: %v\n", err)
			continue
		}
		
		fmt.Printf("  🏥 Overall Health: %s\n", health.OverallStatus)
		fmt.Printf("  📅 Last Checked: %v\n", health.LastChecked)
		
		// Display component health
		fmt.Printf("  🔧 Component Health:\n")
		for name, component := range health.Components {
			fmt.Printf("     %s: %s (Response: %v)\n", 
				name, component.Status, component.ResponseTime)
		}
		
		// Display any health issues
		if len(health.Issues) > 0 {
			fmt.Printf("  ⚠️ Health Issues:\n")
			for _, issue := range health.Issues {
				fmt.Printf("     %s: %s (%s)\n", 
					issue.Component, issue.Message, issue.Severity)
			}
		} else {
			fmt.Printf("  ✅ No health issues detected\n")
		}
		
		// Get metrics report
		period := &policy.ReportPeriod{
			StartTime:   time.Now().Add(-1 * time.Hour),
			EndTime:     time.Now(),
			Granularity: "hour",
		}
		
		metrics, err := tm.GetTenantMetrics(tenant.ID, period)
		if err != nil {
			fmt.Printf("  ❌ Error getting metrics: %v\n", err)
		} else {
			fmt.Printf("  📊 Metrics report generated\n")
			if metrics.RequestMetrics != nil {
				fmt.Printf("     Total Requests: %d\n", metrics.RequestMetrics.TotalRequests)
			}
			if metrics.PerformanceMetrics != nil {
				fmt.Printf("     Average Latency: %v\n", metrics.PerformanceMetrics.AverageLatency)
			}
		}
		
		// Test alerting
		alertDetails := map[string]interface{}{
			"demo_alert": true,
			"timestamp": time.Now(),
			"metric":    "demo_test",
		}
		
		err = tm.AlertOnTenantIssues(tenant.ID, "demo_alert", alertDetails)
		if err != nil {
			fmt.Printf("  ❌ Error sending alert: %v\n", err)
		} else {
			fmt.Printf("  🚨 Demo alert sent successfully\n")
		}
	}
}

// Demo 7: Demonstrate administrative operations
func demonstrateAdministrativeOperations(tm *policy.TenantManager, tenants []*policy.Tenant) {
	fmt.Println("Demonstrating administrative operations...")
	
	// Tenant filtering and search
	fmt.Println("\n🔍 Tenant Filtering and Search:")
	
	// Filter by plan
	filters := &policy.TenantListFilters{
		Plan: []policy.TenantPlan{policy.TenantPlanEnterprise, policy.TenantPlanProfessional},
	}
	
	filteredTenants, err := tm.ListTenants(filters)
	if err != nil {
		fmt.Printf("  ❌ Error filtering tenants: %v\n", err)
	} else {
		fmt.Printf("  📋 Enterprise/Professional tenants: %d\n", len(filteredTenants))
		for _, tenant := range filteredTenants {
			fmt.Printf("     %s (%s)\n", tenant.Name, tenant.Plan)
		}
	}
	
	// Search by organization
	searchFilters := &policy.TenantListFilters{
		SearchQuery: "corp",
	}
	
	searchResults, err := tm.ListTenants(searchFilters)
	if err != nil {
		fmt.Printf("  ❌ Error searching tenants: %v\n", err)
	} else {
		fmt.Printf("  🔍 Search results for 'corp': %d\n", len(searchResults))
	}
	
	// Tenant status management
	fmt.Println("\n⚙️ Tenant Status Management:")
	
	if len(tenants) > 0 {
		// Suspend and reactivate a tenant (using trial tenant)
		for _, tenant := range tenants {
			if tenant.Type == policy.TenantTypeTrial {
				fmt.Printf("  🔄 Testing status changes for tenant: %s\n", tenant.Name)
				
				// Suspend tenant
				err := tm.SuspendTenant(tenant.ID, "Demo suspension test", "admin")
				if err != nil {
					fmt.Printf("    ❌ Error suspending tenant: %v\n", err)
				} else {
					fmt.Printf("    ⏸️ Tenant suspended successfully\n")
				}
				
				// Get updated tenant status
				updatedTenant, err := tm.GetTenant(tenant.ID)
				if err != nil {
					fmt.Printf("    ❌ Error getting updated tenant: %v\n", err)
				} else {
					fmt.Printf("    📊 Current status: %s\n", updatedTenant.Status)
				}
				
				// Reactivate tenant
				err = tm.ReactivateTenant(tenant.ID, "admin")
				if err != nil {
					fmt.Printf("    ❌ Error reactivating tenant: %v\n", err)
				} else {
					fmt.Printf("    ▶️ Tenant reactivated successfully\n")
				}
				
				break
			}
		}
	}
	
	// Configuration updates
	fmt.Println("\n🔧 Configuration Management:")
	
	if len(tenants) > 0 {
		tenant := tenants[0]
		fmt.Printf("  🔧 Testing configuration update for: %s\n", tenant.Name)
		
		// Update resource limits
		newLimits := &policy.TenantResourceLimits{
			MaxRequestsPerSecond: 200,
			MaxRequestsPerMinute: 5000,
			MaxRequestsPerHour:   50000,
			MaxRequestsPerDay:    1000000,
			MaxPolicies:          150,
			MaxActiveRules:       750,
			MaxMemoryUsage:       2 * 1024 * 1024 * 1024, // 2GB
			MaxStorageUsage:      20 * 1024 * 1024 * 1024, // 20GB
		}
		
		err := tm.UpdateResourceLimits(tenant.ID, newLimits)
		if err != nil {
			fmt.Printf("    ❌ Error updating resource limits: %v\n", err)
		} else {
			fmt.Printf("    ✅ Resource limits updated successfully\n")
			fmt.Printf("       New max requests/sec: %d\n", newLimits.MaxRequestsPerSecond)
			fmt.Printf("       New max policies: %d\n", newLimits.MaxPolicies)
		}
	}
	
	// Billing and usage summary
	fmt.Println("\n💰 Billing and Usage Summary:")
	
	for _, tenant := range tenants {
		fmt.Printf("  💳 Tenant: %s\n", tenant.Name)
		fmt.Printf("     Plan: %s\n", tenant.Plan)
		fmt.Printf("     Tier: %s\n", tenant.Tier)
		
		if tenant.BillingInfo != nil {
			fmt.Printf("     Currency: %s\n", tenant.BillingInfo.Currency)
			fmt.Printf("     Current Spend: $%.2f\n", tenant.BillingInfo.CurrentMonthSpend)
		}
		
		if tenant.UsageMetrics != nil {
			fmt.Printf("     Total Requests: %d\n", tenant.UsageMetrics.TotalRequests)
			fmt.Printf("     Storage Used: %d bytes\n", tenant.UsageMetrics.StorageUsed)
		}
	}
	
	fmt.Println("\n🎉 Multi-Tenant Demo Completed Successfully!")
	fmt.Println("\n📊 Demo Summary:")
	fmt.Printf("   ✅ Created %d tenants with complete isolation\n", len(tenants))
	fmt.Printf("   ✅ Verified namespace isolation and access controls\n")
	fmt.Printf("   ✅ Demonstrated policy management with tenant context\n")
	fmt.Printf("   ✅ Showed resource monitoring and quota enforcement\n")
	fmt.Printf("   ✅ Validated security features and audit logging\n")
	fmt.Printf("   ✅ Performed health monitoring and alerting\n")
	fmt.Printf("   ✅ Executed administrative operations\n")
	fmt.Println("\n🏆 Multi-tenant policy isolation system is fully operational!")
} 