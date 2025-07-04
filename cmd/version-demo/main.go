package main

import (
	"fmt"
	"log"
	"time"

	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("=== AI Gateway Policy Versioning & Rollback Demo ===")
	fmt.Println()

	// Create version manager with configuration
	config := &policy.VersionManagerConfig{
		AutoApprovalEnabled:    false,
		RequiredApprovers:      []policy.ApprovalRole{policy.ApprovalRoleSecurityOfficer},
		MaxVersionsPerPolicy:   10,
		VersionRetentionPeriod: 30 * 24 * time.Hour,
		ChangeDetectionEnabled: true,
		ImpactAnalysisEnabled:  true,
		RollbackChecksEnabled:  true,
		AuditLoggingEnabled:    true,
	}

	vm := policy.NewPolicyVersionManager(config)

	// Demo: Version Creation
	fmt.Println("📝 Demo 1: Creating Policy Versions")
	fmt.Println("===================================")

	err := demoVersionCreation(vm)
	if err != nil {
		log.Fatalf("Version creation demo failed: %v", err)
	}

	// Demo: Version Comparison
	fmt.Println("\n🔍 Demo 2: Version Comparison and Change Detection")
	fmt.Println("================================================")

	err = demoVersionComparison(vm)
	if err != nil {
		log.Fatalf("Version comparison demo failed: %v", err)
	}

	// Demo: Rollback Operations
	fmt.Println("\n⏪ Demo 3: Version Rollback Operations")
	fmt.Println("====================================")

	err = demoRollbackOperations(vm)
	if err != nil {
		log.Fatalf("Rollback demo failed: %v", err)
	}

	// Demo: Version History
	fmt.Println("\n📜 Demo 4: Version History and Audit")
	fmt.Println("===================================")

	err = demoVersionHistory(vm)
	if err != nil {
		log.Fatalf("Version history demo failed: %v", err)
	}

	fmt.Println("\n🎉 All demos completed successfully!")
	fmt.Println("\nKey Features Demonstrated:")
	fmt.Println("• Semantic versioning with change detection")
	fmt.Println("• Impact analysis and rollback planning")
	fmt.Println("• Safe rollback operations with validation")
	fmt.Println("• Complete audit trail and version history")
	fmt.Println("• Policy snapshot management")
}

func demoVersionCreation(vm *policy.PolicyVersionManager) error {
	// Create initial policy
	policy1 := &policy.Policy{
		ID:          "demo-policy",
		Name:        "Demo Security Policy",
		Description: "Initial security policy",
		Priority:    100,
		CreatedBy:   "admin",
		Rules: []policy.PolicyRule{
			{
				ID:       "rule1",
				Name:     "PII Detection",
				Priority: 10,
				Enabled:  true,
				Action: policy.PolicyAction{
					Type:     policy.ActionBlock,
					Severity: policy.SeverityHigh,
				},
			},
		},
		DefaultAction: policy.PolicyAction{
			Type:     policy.ActionAllow,
			Severity: policy.SeverityInfo,
		},
	}

	fmt.Println("Creating initial policy version...")
	version1, err := vm.CreateVersion("demo-policy", policy1, policy.ChangeTypeCreation, "Initial policy creation")
	if err != nil {
		return err
	}

	fmt.Printf("✅ Created version %s\n", version1.VersionNumber)
	fmt.Printf("   Status: %s\n", version1.Status)
	fmt.Printf("   Change Type: %s\n", version1.ChangeType)

	// Activate the version
	err = vm.ActivateVersion(version1.ID, "admin")
	if err != nil {
		return err
	}
	fmt.Printf("✅ Activated version %s\n", version1.VersionNumber)

	// Create second version with changes
	policy2 := *policy1
	policy2.Description = "Enhanced security policy with content classification"
	policy2.Priority = 150

	fmt.Println("\nCreating enhanced version...")
	version2, err := vm.CreateVersion("demo-policy", &policy2, policy.ChangeTypeMinor, "Added enhanced security features")
	if err != nil {
		return err
	}

	fmt.Printf("✅ Created version %s\n", version2.VersionNumber)
	fmt.Printf("   Previous Version: %s\n", version2.PreviousVersion)
	fmt.Printf("   Changes Detected: %d\n", len(version2.ChangeSummary))

	for _, change := range version2.ChangeSummary {
		fmt.Printf("     - %s: %s (impact: %s)\n", change.Field, change.Description, change.Impact)
	}

	// Create third version with major changes
	policy3 := policy2
	policy3.Description = "Major security update with ML detection"
	policy3.Rules = append(policy3.Rules, policy.PolicyRule{
		ID:       "rule2",
		Name:     "ML Threat Detection",
		Priority: 5,
		Enabled:  true,
		Action: policy.PolicyAction{
			Type:     policy.ActionQuarantine,
			Severity: policy.SeverityCritical,
		},
	})

	fmt.Println("\nCreating major update version...")
	version3, err := vm.CreateVersion("demo-policy", &policy3, policy.ChangeTypeMajor, "Major security enhancements")
	if err != nil {
		return err
	}

	fmt.Printf("✅ Created version %s\n", version3.VersionNumber)
	if version3.ImpactAnalysis != nil {
		fmt.Printf("   Impact: %s\n", version3.ImpactAnalysis.OverallImpact)
		fmt.Printf("   Backward Compatible: %t\n", version3.ImpactAnalysis.BackwardCompatible)
	}

	return nil
}

func demoVersionComparison(vm *policy.PolicyVersionManager) error {
	// Get versions for comparison
	version1, err := vm.GetVersionByNumber("demo-policy", "1.0.0")
	if err != nil {
		return err
	}

	version3, err := vm.GetVersionByNumber("demo-policy", "2.0.0")
	if err != nil {
		return err
	}

	fmt.Printf("Comparing versions %s and %s...\n", version1.VersionNumber, version3.VersionNumber)

	comparison, err := vm.CompareVersions(version1.ID, version3.ID)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Comparison Results:\n")
	fmt.Printf("   Total Changes: %d\n", comparison.Summary.TotalChanges)
	fmt.Printf("   Breaking Changes: %t\n", comparison.Summary.HasBreakingChanges)
	fmt.Printf("   Upgrade Complexity: %s\n", comparison.Summary.UpgradeComplexity)

	fmt.Println("\n📋 Change Details:")
	for _, change := range comparison.Changes {
		fmt.Printf("   • %s: %s (%s)\n", change.Field, change.Description, change.Impact)
	}

	fmt.Println("\n💡 Recommendations:")
	for _, rec := range comparison.Recommendations {
		fmt.Printf("   • %s\n", rec)
	}

	return nil
}

func demoRollbackOperations(vm *policy.PolicyVersionManager) error {
	// First activate the latest version
	version3, err := vm.GetVersionByNumber("demo-policy", "2.0.0")
	if err != nil {
		return err
	}

	err = vm.ActivateVersion(version3.ID, "admin")
	if err != nil {
		return err
	}
	fmt.Printf("Current active version: %s\n", version3.VersionNumber)

	// Simulate rollback scenario
	fmt.Println("\n⚠️ Simulating critical issue - initiating rollback...")

	targetVersion, err := vm.GetVersionByNumber("demo-policy", "1.1.0")
	if err != nil {
		return err
	}

	// Validate rollback
	fmt.Println("Validating rollback safety...")
	validation, err := vm.ValidateRollback("demo-policy", targetVersion.VersionNumber)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Validation: %s - %s\n", validation.Status, validation.Message)

	// Create rollback request
	rollbackRequest := &policy.VersionRollbackRequest{
		PolicyID:          "demo-policy",
		CurrentVersion:    version3.VersionNumber,
		TargetVersion:     targetVersion.VersionNumber,
		RollbackReason:    "Critical bug found in ML detection",
		RequestedBy:       "ops-team",
		RequestedAt:       time.Now(),
		ImmediateRollback: true,
		BackupCurrent:     true,
	}

	fmt.Println("\nExecuting rollback...")
	result, err := vm.RollbackToVersion(rollbackRequest)
	if err != nil {
		return err
	}

	if result.Success {
		fmt.Printf("✅ Rollback successful!\n")
	} else {
		fmt.Printf("❌ Rollback failed!\n")
	}

	fmt.Printf("   From: %s → To: %s\n", result.FromVersion, result.ToVersion)
	fmt.Printf("   Execution Time: %s\n", result.ExecutionTime)
	fmt.Printf("   Message: %s\n", result.Message)

	fmt.Println("\n🔧 Post-rollback checks:")
	for _, check := range result.PostRollbackChecks {
		status := "✅"
		if !check.Passed {
			status = "❌"
		}
		fmt.Printf("   %s %s: %s\n", status, check.CheckName, check.Status)
	}

	// Verify current version
	currentVersion, err := vm.GetCurrentVersion("demo-policy")
	if err != nil {
		return err
	}
	fmt.Printf("\n✅ Current active version: %s\n", currentVersion.VersionNumber)

	return nil
}

func demoVersionHistory(vm *policy.PolicyVersionManager) error {
	fmt.Println("Retrieving version history...")

	history, err := vm.GetVersionHistory("demo-policy")
	if err != nil {
		return err
	}

	fmt.Printf("✅ Policy: %s\n", history.PolicyName)
	fmt.Printf("   Total Versions: %d\n", history.TotalVersions)
	fmt.Printf("   Current Version: %s\n", history.CurrentVersion)

	fmt.Println("\n📋 Version Timeline:")
	for i, version := range history.Versions {
		fmt.Printf("   %d. %s (%s) - %s\n",
			i+1,
			version.VersionNumber,
			version.Status,
			version.ChangeType)
		fmt.Printf("      Created: %s by %s\n",
			version.CreatedAt.Format("2006-01-02 15:04"),
			version.CreatedBy)
		fmt.Printf("      Reason: %s\n", version.ChangeReason)

		if version.RollbackInfo != nil && version.RollbackInfo.RollbackReason != "" {
			fmt.Printf("      Rollback: %s\n", version.RollbackInfo.RollbackReason)
		}
		fmt.Println()
	}

	// Show audit trail
	fmt.Println("📜 Recent Audit Events:")
	if len(history.Versions) > 0 {
		latestVersion := history.Versions[len(history.Versions)-1]
		auditTrail, err := vm.GetVersionAuditTrail(latestVersion.ID)
		if err != nil {
			return err
		}

		for i, entry := range auditTrail {
			if i >= 5 { // Show only first 5 entries
				break
			}
			fmt.Printf("   %d. %s - %s by %s\n",
				i+1,
				entry.Timestamp.Format("15:04:05"),
				entry.Action,
				entry.Actor)
		}
	}

	// Export history
	fmt.Println("\n📤 Exporting version history...")
	exportData, err := vm.ExportVersionHistory("demo-policy", "json")
	if err != nil {
		return err
	}

	fmt.Printf("✅ Exported %d bytes to JSON format\n", len(exportData))

	// Show rollback options
	fmt.Println("\n🔄 Available Rollback Options:")
	rollbackOptions, err := vm.GetRollbackOptions("demo-policy")
	if err != nil {
		return err
	}

	for i, option := range rollbackOptions {
		canRollback := "Yes"
		if option.RollbackInfo != nil && !option.RollbackInfo.CanRollback {
			canRollback = "No"
		}
		fmt.Printf("   %d. %s (%s) - Rollback: %s\n",
			i+1,
			option.VersionNumber,
			option.Status,
			canRollback)
	}

	return nil
} 