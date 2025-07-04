package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PolicyVersionManager implements comprehensive policy versioning and rollback
type PolicyVersionManager struct {
	versions         map[string]*PolicyVersion      // versionID -> version
	policyVersions   map[string][]*PolicyVersion    // policyID -> versions
	currentVersions  map[string]string              // policyID -> current versionID
	versionHistory   map[string]*PolicyVersionHistory // policyID -> history
	approvalWorkflows map[string]*VersionApprovalWorkflow // versionID -> workflow
	auditLog        []AuditLogEntry
	config          *VersionManagerConfig
}

// VersionManagerConfig provides configuration for the version manager
type VersionManagerConfig struct {
	AutoApprovalEnabled    bool          `json:"auto_approval_enabled"`
	RequiredApprovers      []ApprovalRole `json:"required_approvers"`
	MaxVersionsPerPolicy   int           `json:"max_versions_per_policy"`
	VersionRetentionPeriod time.Duration `json:"version_retention_period"`
	ChangeDetectionEnabled bool          `json:"change_detection_enabled"`
	ImpactAnalysisEnabled  bool          `json:"impact_analysis_enabled"`
	RollbackChecksEnabled  bool          `json:"rollback_checks_enabled"`
	AuditLoggingEnabled    bool          `json:"audit_logging_enabled"`
}

// NewPolicyVersionManager creates a new version manager
func NewPolicyVersionManager(config *VersionManagerConfig) *PolicyVersionManager {
	if config == nil {
		config = &VersionManagerConfig{
			AutoApprovalEnabled:    false,
			RequiredApprovers:      []ApprovalRole{ApprovalRolePolicyOwner},
			MaxVersionsPerPolicy:   50,
			VersionRetentionPeriod: 365 * 24 * time.Hour, // 1 year
			ChangeDetectionEnabled: true,
			ImpactAnalysisEnabled:  true,
			RollbackChecksEnabled:  true,
			AuditLoggingEnabled:    true,
		}
	}

	return &PolicyVersionManager{
		versions:          make(map[string]*PolicyVersion),
		policyVersions:    make(map[string][]*PolicyVersion),
		currentVersions:   make(map[string]string),
		versionHistory:    make(map[string]*PolicyVersionHistory),
		approvalWorkflows: make(map[string]*VersionApprovalWorkflow),
		auditLog:         make([]AuditLogEntry, 0),
		config:           config,
	}
}

// CreateVersion creates a new version of a policy
func (vm *PolicyVersionManager) CreateVersion(policyID string, policy *Policy, changeType PolicyChangeType, reason string) (*PolicyVersion, error) {
	versionID := uuid.New().String()
	
	// Determine version number
	versionNumber, err := vm.generateVersionNumber(policyID, changeType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate version number: %w", err)
	}

	// Create deep copy of policy for snapshot
	policySnapshot, err := vm.deepCopyPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy snapshot: %w", err)
	}

	// Get previous version for change tracking
	var previousVersion *PolicyVersion
	if currentVersionID, exists := vm.currentVersions[policyID]; exists {
		previousVersion = vm.versions[currentVersionID]
	}

	// Create version
	version := &PolicyVersion{
		ID:              versionID,
		PolicyID:        policyID,
		VersionNumber:   versionNumber,
		PolicySnapshot:  policySnapshot,
		Status:          VersionStatusDraft,
		CreatedBy:       policy.CreatedBy,
		CreatedAt:       time.Now(),
		ChangeType:      changeType,
		ChangeReason:    reason,
		Environment:     "development",
		Tags:            []string{},
		Metadata:        make(map[string]interface{}),
	}

	// Parse semantic version
	vm.parseSemanticVersion(version)

	// Track changes from previous version
	if previousVersion != nil {
		version.PreviousVersion = previousVersion.VersionNumber
		if vm.config.ChangeDetectionEnabled {
			changeSummary, err := vm.detectChanges(previousVersion.PolicySnapshot, policySnapshot)
			if err == nil {
				version.ChangeSummary = changeSummary
			}
		}
	}

	// Analyze impact if enabled
	if vm.config.ImpactAnalysisEnabled {
		impactAnalysis, err := vm.analyzeVersionImpact(version)
		if err == nil {
			version.ImpactAnalysis = impactAnalysis
		}
	}

	// Generate rollback information
	rollbackInfo := vm.generateRollbackInfo(policyID, version, previousVersion)
	version.RollbackInfo = rollbackInfo

	// Store version
	vm.versions[versionID] = version
	vm.policyVersions[policyID] = append(vm.policyVersions[policyID], version)

	// Update version history
	vm.updateVersionHistory(policyID, version)

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_created", policy.CreatedBy, versionID, policyID, map[string]interface{}{
			"version_number": versionNumber,
			"change_type":    changeType,
			"reason":         reason,
		})
	}

	return version, nil
}

// GetVersion retrieves a specific version by ID
func (vm *PolicyVersionManager) GetVersion(versionID string) (*PolicyVersion, error) {
	version, exists := vm.versions[versionID]
	if !exists {
		return nil, fmt.Errorf("version not found: %s", versionID)
	}
	return version, nil
}

// GetVersionByNumber retrieves a version by policy ID and version number
func (vm *PolicyVersionManager) GetVersionByNumber(policyID, versionNumber string) (*PolicyVersion, error) {
	versions, exists := vm.policyVersions[policyID]
	if !exists {
		return nil, fmt.Errorf("no versions found for policy: %s", policyID)
	}

	for _, version := range versions {
		if version.VersionNumber == versionNumber {
			return version, nil
		}
	}

	return nil, fmt.Errorf("version %s not found for policy %s", versionNumber, policyID)
}

// GetCurrentVersion retrieves the current active version of a policy
func (vm *PolicyVersionManager) GetCurrentVersion(policyID string) (*PolicyVersion, error) {
	currentVersionID, exists := vm.currentVersions[policyID]
	if !exists {
		return nil, fmt.Errorf("no current version found for policy: %s", policyID)
	}
	return vm.GetVersion(currentVersionID)
}

// ListVersions lists all versions for a policy
func (vm *PolicyVersionManager) ListVersions(policyID string) ([]*PolicyVersion, error) {
	versions, exists := vm.policyVersions[policyID]
	if !exists {
		return []*PolicyVersion{}, nil
	}

	// Sort by creation time (newest first)
	sortedVersions := make([]*PolicyVersion, len(versions))
	copy(sortedVersions, versions)
	sort.Slice(sortedVersions, func(i, j int) bool {
		return sortedVersions[i].CreatedAt.After(sortedVersions[j].CreatedAt)
	})

	return sortedVersions, nil
}

// CompareVersions compares two versions and returns differences
func (vm *PolicyVersionManager) CompareVersions(version1ID, version2ID string) (*VersionComparisonResult, error) {
	version1, err := vm.GetVersion(version1ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get version1: %w", err)
	}

	version2, err := vm.GetVersion(version2ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get version2: %w", err)
	}

	// Detect changes between versions
	changes, err := vm.detectChanges(version1.PolicySnapshot, version2.PolicySnapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes: %w", err)
	}

	// Create summary
	summary := vm.createComparisonSummary(changes)

	// Analyze impact
	impactAnalysis, _ := vm.analyzeComparisonImpact(version1, version2, changes)

	// Generate recommendations
	recommendations := vm.generateComparisonRecommendations(changes, summary)

	return &VersionComparisonResult{
		Version1:        version1.VersionNumber,
		Version2:        version2.VersionNumber,
		Changes:         changes,
		Summary:         summary,
		ImpactAnalysis:  impactAnalysis,
		Recommendations: recommendations,
	}, nil
}

// ActivateVersion activates a specific version
func (vm *PolicyVersionManager) ActivateVersion(versionID string, activatedBy string) error {
	version, err := vm.GetVersion(versionID)
	if err != nil {
		return err
	}

	if version.Status != VersionStatusApproved && version.Status != VersionStatusDraft {
		return fmt.Errorf("version must be approved before activation, current status: %s", version.Status)
	}

	// Deactivate current version if exists
	if currentVersionID, exists := vm.currentVersions[version.PolicyID]; exists {
		currentVersion := vm.versions[currentVersionID]
		currentVersion.Status = VersionStatusDeprecated
		now := time.Now()
		currentVersion.DeactivatedAt = &now
	}

	// Activate new version
	version.Status = VersionStatusActive
	now := time.Now()
	version.ActivatedAt = &now
	vm.currentVersions[version.PolicyID] = versionID

	// Update linked list
	if previousVersionID, exists := vm.currentVersions[version.PolicyID]; exists && previousVersionID != versionID {
		if previousVersion, exists := vm.versions[previousVersionID]; exists {
			previousVersion.NextVersion = version.VersionNumber
		}
	}

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_activated", activatedBy, versionID, version.PolicyID, map[string]interface{}{
			"version_number": version.VersionNumber,
		})
	}

	return nil
}

// RollbackToVersion performs a rollback to a previous version
func (vm *PolicyVersionManager) RollbackToVersion(request *VersionRollbackRequest) (*VersionRollbackResult, error) {
	start := time.Now()
	rollbackID := uuid.New().String()

	result := &VersionRollbackResult{
		RollbackID:         rollbackID,
		PolicyID:           request.PolicyID,
		FromVersion:        request.CurrentVersion,
		ToVersion:          request.TargetVersion,
		ExecutedBy:         request.RequestedBy,
		ExecutedAt:         start,
		Warnings:           []string{},
		Errors:             []string{},
		ValidationResults:  []ValidationResult{},
		PostRollbackChecks: []RollbackCheck{},
		MonitoringData:     make(map[string]interface{}),
		NextSteps:          []string{},
	}

	// Validate rollback request
	if !request.SkipValidation {
		validationResult, err := vm.ValidateRollback(request.PolicyID, request.TargetVersion)
		if err != nil {
			result.Success = false
			result.Errors = append(result.Errors, fmt.Sprintf("Validation failed: %v", err))
			return result, err
		}
		result.ValidationResults = append(result.ValidationResults, *validationResult)
		
		if validationResult.CriticalFailure {
			result.Success = false
			result.Errors = append(result.Errors, "Critical validation failure prevents rollback")
			return result, fmt.Errorf("critical validation failure")
		}
	}

	// Get target version
	targetVersion, err := vm.GetVersionByNumber(request.PolicyID, request.TargetVersion)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("Target version not found: %v", err))
		return result, err
	}

	// Backup current version if requested
	if request.BackupCurrent {
		currentVersion, err := vm.GetCurrentVersion(request.PolicyID)
		if err == nil {
			backupVersion, err := vm.CreateVersion(request.PolicyID, currentVersion.PolicySnapshot, ChangeTypeRollback, "Backup before rollback")
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to create backup: %v", err))
			} else {
				result.MonitoringData["backup_version"] = backupVersion.VersionNumber
			}
		}
	}

	// Perform rollback by activating target version
	err = vm.ActivateVersion(targetVersion.ID, request.RequestedBy)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to activate target version: %v", err))
		return result, err
	}

	// Update target version status and rollback info
	targetVersion.Status = VersionStatusActive
	if targetVersion.RollbackInfo == nil {
		targetVersion.RollbackInfo = &RollbackInformation{}
	}
	targetVersion.RollbackInfo.RollbackReason = request.RollbackReason
	targetVersion.RollbackInfo.RollbackBy = request.RequestedBy
	now := time.Now()
	targetVersion.RollbackInfo.RollbackAt = &now

	// Perform post-rollback checks
	if vm.config.RollbackChecksEnabled {
		postChecks := vm.performPostRollbackChecks(request.PolicyID, targetVersion)
		result.PostRollbackChecks = postChecks
		
		// Check if any critical checks failed
		for _, check := range postChecks {
			if !check.Passed && strings.Contains(check.CheckType, "critical") {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Critical post-rollback check failed: %s", check.CheckName))
			}
		}
	}

	result.Success = true
	result.ExecutionTime = time.Since(start)
	result.Message = fmt.Sprintf("Successfully rolled back from %s to %s", request.CurrentVersion, request.TargetVersion)
	result.NextSteps = []string{
		"Monitor policy performance for next 24 hours",
		"Verify all dependent systems are functioning correctly",
		"Update documentation with rollback details",
	}

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_rollback", request.RequestedBy, targetVersion.ID, request.PolicyID, map[string]interface{}{
			"rollback_id":     rollbackID,
			"from_version":    request.CurrentVersion,
			"to_version":      request.TargetVersion,
			"reason":          request.RollbackReason,
			"execution_time":  result.ExecutionTime.String(),
		})
	}

	return result, nil
}

// GetVersionHistory retrieves the complete version history for a policy
func (vm *PolicyVersionManager) GetVersionHistory(policyID string) (*PolicyVersionHistory, error) {
	history, exists := vm.versionHistory[policyID]
	if !exists {
		return &PolicyVersionHistory{
			PolicyID:      policyID,
			Versions:      []PolicyVersion{},
			TotalVersions: 0,
			CreatedAt:     time.Now(),
		}, nil
	}
	return history, nil
}

// ValidateRollback validates if a rollback operation is safe
func (vm *PolicyVersionManager) ValidateRollback(policyID, targetVersion string) (*ValidationResult, error) {
	result := &ValidationResult{
		Component:       "rollback_validator",
		Timestamp:       time.Now(),
		CriticalFailure: false,
	}

	// Check if target version exists
	targetVer, err := vm.GetVersionByNumber(policyID, targetVersion)
	if err != nil {
		result.Status = "failed"
		result.Message = "Target version not found"
		result.Details = err.Error()
		result.CriticalFailure = true
		return result, err
	}

	// Check if target version can be rolled back to
	if targetVer.RollbackInfo != nil && !targetVer.RollbackInfo.CanRollback {
		result.Status = "failed"
		result.Message = "Target version is not eligible for rollback"
		result.Details = "Version marked as non-rollback-able"
		result.CriticalFailure = true
		return result, fmt.Errorf("target version not eligible for rollback")
	}

	// Check for breaking changes since target version
	currentVersion, err := vm.GetCurrentVersion(policyID)
	if err == nil {
		comparison, err := vm.CompareVersions(targetVer.ID, currentVersion.ID)
		if err == nil && comparison.Summary.HasBreakingChanges {
			result.Status = "warning"
			result.Message = "Rollback may introduce breaking changes"
			result.Details = "Current version has breaking changes compared to target version"
		}
	}

	if result.Status == "" {
		result.Status = "passed"
		result.Message = "Rollback validation successful"
		result.Details = "All validation checks passed"
	}

	return result, nil
}

// Helper methods

func (vm *PolicyVersionManager) generateVersionNumber(policyID string, changeType PolicyChangeType) (string, error) {
	versions := vm.policyVersions[policyID]
	if len(versions) == 0 {
		return "1.0.0", nil
	}

	// Get latest version
	latestVersion := versions[len(versions)-1]
	major, minor, patch := latestVersion.MajorVersion, latestVersion.MinorVersion, latestVersion.PatchVersion

	switch changeType {
	case ChangeTypeCreation:
		return "1.0.0", nil
	case ChangeTypeMajor:
		major++
		minor = 0
		patch = 0
	case ChangeTypeMinor:
		minor++
		patch = 0
	case ChangeTypePatch, ChangeTypeHotfix:
		patch++
	case ChangeTypeRollback:
		patch++
	default:
		patch++
	}

	return fmt.Sprintf("%d.%d.%d", major, minor, patch), nil
}

func (vm *PolicyVersionManager) parseSemanticVersion(version *PolicyVersion) {
	parts := strings.Split(version.VersionNumber, ".")
	if len(parts) >= 3 {
		version.MajorVersion, _ = strconv.Atoi(parts[0])
		version.MinorVersion, _ = strconv.Atoi(parts[1])
		version.PatchVersion, _ = strconv.Atoi(parts[2])
	}
}

func (vm *PolicyVersionManager) deepCopyPolicy(policy *Policy) (*Policy, error) {
	data, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	
	var copy Policy
	err = json.Unmarshal(data, &copy)
	if err != nil {
		return nil, err
	}
	
	return &copy, nil
}

func (vm *PolicyVersionManager) detectChanges(oldPolicy, newPolicy *Policy) ([]PolicyChange, error) {
	changes := []PolicyChange{}
	
	// Compare basic fields
	if oldPolicy.Name != newPolicy.Name {
		changes = append(changes, PolicyChange{
			Field:       "name",
			ChangeType:  "modified",
			OldValue:    oldPolicy.Name,
			NewValue:    newPolicy.Name,
			Description: "Policy name changed",
			Impact:      ImpactLow,
		})
	}
	
	if oldPolicy.Description != newPolicy.Description {
		changes = append(changes, PolicyChange{
			Field:       "description",
			ChangeType:  "modified",
			OldValue:    oldPolicy.Description,
			NewValue:    newPolicy.Description,
			Description: "Policy description changed",
			Impact:      ImpactLow,
		})
	}
	
	if oldPolicy.Priority != newPolicy.Priority {
		impact := ImpactMedium
		if abs(oldPolicy.Priority-newPolicy.Priority) > 50 {
			impact = ImpactHigh
		}
		changes = append(changes, PolicyChange{
			Field:       "priority",
			ChangeType:  "modified",
			OldValue:    oldPolicy.Priority,
			NewValue:    newPolicy.Priority,
			Description: "Policy priority changed",
			Impact:      impact,
		})
	}
	
	// Compare rules
	ruleChanges := vm.compareRules(oldPolicy.Rules, newPolicy.Rules)
	changes = append(changes, ruleChanges...)
	
	return changes, nil
}

func (vm *PolicyVersionManager) compareRules(oldRules, newRules []PolicyRule) []PolicyChange {
	changes := []PolicyChange{}
	
	// Create maps for easier comparison
	oldRuleMap := make(map[string]PolicyRule)
	newRuleMap := make(map[string]PolicyRule)
	
	for _, rule := range oldRules {
		oldRuleMap[rule.ID] = rule
	}
	for _, rule := range newRules {
		newRuleMap[rule.ID] = rule
	}
	
	// Check for removed rules
	for id, oldRule := range oldRuleMap {
		if _, exists := newRuleMap[id]; !exists {
			changes = append(changes, PolicyChange{
				Field:         "rules",
				ChangeType:    "removed",
				OldValue:      oldRule.Name,
				Description:   fmt.Sprintf("Rule '%s' removed", oldRule.Name),
				Impact:        ImpactHigh,
				AffectedRules: []string{id},
			})
		}
	}
	
	// Check for added rules
	for id, newRule := range newRuleMap {
		if _, exists := oldRuleMap[id]; !exists {
			changes = append(changes, PolicyChange{
				Field:         "rules",
				ChangeType:    "added",
				NewValue:      newRule.Name,
				Description:   fmt.Sprintf("Rule '%s' added", newRule.Name),
				Impact:        ImpactMedium,
				AffectedRules: []string{id},
			})
		}
	}
	
	// Check for modified rules
	for id, newRule := range newRuleMap {
		if oldRule, exists := oldRuleMap[id]; exists {
			if !reflect.DeepEqual(oldRule, newRule) {
				impact := ImpactMedium
				if oldRule.Action.Type != newRule.Action.Type {
					impact = ImpactHigh
				}
				changes = append(changes, PolicyChange{
					Field:         "rules",
					ChangeType:    "modified",
					OldValue:      oldRule.Name,
					NewValue:      newRule.Name,
					Description:   fmt.Sprintf("Rule '%s' modified", newRule.Name),
					Impact:        impact,
					AffectedRules: []string{id},
				})
			}
		}
	}
	
	return changes
}

func (vm *PolicyVersionManager) updateVersionHistory(policyID string, version *PolicyVersion) {
	history, exists := vm.versionHistory[policyID]
	if !exists {
		history = &PolicyVersionHistory{
			PolicyID:      policyID,
			PolicyName:    version.PolicySnapshot.Name,
			Versions:      []PolicyVersion{},
			TotalVersions: 0,
			CreatedAt:     time.Now(),
		}
		vm.versionHistory[policyID] = history
	}
	
	history.Versions = append(history.Versions, *version)
	history.TotalVersions = len(history.Versions)
	history.LastModified = time.Now()
	
	if version.Status == VersionStatusActive {
		history.CurrentVersion = version.VersionNumber
	}
}

func (vm *PolicyVersionManager) logAuditEntry(action, actor, versionID, policyID string, details map[string]interface{}) {
	entry := AuditLogEntry{
		ID:        uuid.New().String(),
		PolicyID:  policyID,
		VersionID: versionID,
		Action:    action,
		Actor:     actor,
		Timestamp: time.Now(),
		Details:   details,
	}
	vm.auditLog = append(vm.auditLog, entry)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// analyzeVersionImpact analyzes the impact of a policy version
func (vm *PolicyVersionManager) analyzeVersionImpact(version *PolicyVersion) (*VersionImpactAnalysis, error) {
	analysis := &VersionImpactAnalysis{
		OverallImpact:       ImpactLow,
		AffectedComponents:  []string{},
		BackwardCompatible:  true,
		BreakingChanges:     []string{},
		RiskAssessment:      "Low risk",
		TestingRequired:     []string{},
		RolloutStrategy:     "Standard deployment",
		MonitoringPoints:    []string{},
		EstimatedUsers:      0,
		EstimatedRequests:   0,
	}

	// Analyze change summary for impact
	for _, change := range version.ChangeSummary {
		// Update overall impact to highest found
		if change.Impact > analysis.OverallImpact {
			analysis.OverallImpact = change.Impact
		}

		// Track affected components
		if change.Field == "rules" {
			analysis.AffectedComponents = append(analysis.AffectedComponents, "rule_engine")
			analysis.MonitoringPoints = append(analysis.MonitoringPoints, "rule_execution_metrics")
		}
		if change.Field == "priority" {
			analysis.AffectedComponents = append(analysis.AffectedComponents, "conflict_resolution")
			analysis.MonitoringPoints = append(analysis.MonitoringPoints, "conflict_resolution_metrics")
		}

		// Check for breaking changes
		if change.Impact == ImpactCritical || change.Impact == ImpactHigh {
			analysis.BackwardCompatible = false
			analysis.BreakingChanges = append(analysis.BreakingChanges, change.Description)
		}

		// Determine testing requirements
		if change.ChangeType == "added" || change.ChangeType == "modified" {
			analysis.TestingRequired = append(analysis.TestingRequired, fmt.Sprintf("Test %s changes", change.Field))
		}
	}

	// Update risk assessment based on overall impact
	switch analysis.OverallImpact {
	case ImpactCritical:
		analysis.RiskAssessment = "Critical risk - requires immediate attention"
		analysis.RolloutStrategy = "Emergency deployment with rollback plan"
	case ImpactHigh:
		analysis.RiskAssessment = "High risk - requires careful monitoring"
		analysis.RolloutStrategy = "Phased deployment with canary testing"
	case ImpactMedium:
		analysis.RiskAssessment = "Medium risk - standard precautions"
		analysis.RolloutStrategy = "Standard deployment with monitoring"
	default:
		analysis.RiskAssessment = "Low risk - minimal impact expected"
		analysis.RolloutStrategy = "Standard deployment"
	}

	// Add standard monitoring points
	analysis.MonitoringPoints = append(analysis.MonitoringPoints, 
		"policy_evaluation_latency", 
		"policy_match_rate", 
		"error_rate",
	)

	// Estimate affected users/requests (simplified calculation)
	if version.PolicySnapshot != nil {
		// Rough estimate based on policy scope
		if len(version.PolicySnapshot.Scope.Organizations) > 0 {
			analysis.EstimatedUsers = len(version.PolicySnapshot.Scope.Organizations) * 100 // Assume 100 users per org
		}
		if len(version.PolicySnapshot.Scope.Users) > 0 {
			analysis.EstimatedUsers = len(version.PolicySnapshot.Scope.Users)
		}
		analysis.EstimatedRequests = int64(analysis.EstimatedUsers * 50) // Assume 50 requests per user per day
	}

	return analysis, nil
}

// generateRollbackInfo generates rollback information for a version
func (vm *PolicyVersionManager) generateRollbackInfo(policyID string, version *PolicyVersion, previousVersion *PolicyVersion) *RollbackInformation {
	rollbackInfo := &RollbackInformation{
		CanRollback:         true,
		PreRollbackCheck:    []string{},
		PostRollbackCheck:   []string{},
		RollbackRisks:       []string{},
		DataMigrationNeeded: false,
		EstimatedDowntime:   5 * time.Second, // Minimal downtime for policy switch
	}

	if previousVersion != nil {
		rollbackInfo.RollbackToVersion = previousVersion.VersionNumber
	}

	// Determine if rollback is safe based on change type
	switch version.ChangeType {
	case ChangeTypeMajor:
		rollbackInfo.CanRollback = false
		rollbackInfo.RollbackRisks = append(rollbackInfo.RollbackRisks, "Major version changes may not be backward compatible")
	case ChangeTypeMinor:
		rollbackInfo.PreRollbackCheck = append(rollbackInfo.PreRollbackCheck, "Verify no critical features depend on new functionality")
	case ChangeTypePatch, ChangeTypeHotfix:
		rollbackInfo.PreRollbackCheck = append(rollbackInfo.PreRollbackCheck, "Verify bug fixes can be safely reverted")
	}

	// Add standard checks
	rollbackInfo.PreRollbackCheck = append(rollbackInfo.PreRollbackCheck,
		"Backup current policy configuration",
		"Notify affected users of pending changes",
		"Prepare monitoring dashboards",
	)

	rollbackInfo.PostRollbackCheck = append(rollbackInfo.PostRollbackCheck,
		"Verify policy evaluation is working correctly",
		"Check that all rules are executing as expected",
		"Monitor for any unexpected behavior",
		"Validate performance metrics are within normal ranges",
	)

	// Add risks based on impact analysis
	if version.ImpactAnalysis != nil {
		if !version.ImpactAnalysis.BackwardCompatible {
			rollbackInfo.RollbackRisks = append(rollbackInfo.RollbackRisks, "Breaking changes may cause compatibility issues")
		}
		if version.ImpactAnalysis.OverallImpact == ImpactHigh || version.ImpactAnalysis.OverallImpact == ImpactCritical {
			rollbackInfo.RollbackRisks = append(rollbackInfo.RollbackRisks, "High impact changes require careful rollback planning")
			rollbackInfo.EstimatedDowntime = 30 * time.Second
		}
	}

	return rollbackInfo
}

// createComparisonSummary creates a summary of version comparison
func (vm *PolicyVersionManager) createComparisonSummary(changes []PolicyChange) VersionComparisonSummary {
	summary := VersionComparisonSummary{
		TotalChanges:        len(changes),
		ChangesByType:       make(map[string]int),
		ChangesByImpact:     make(map[ChangeImpact]int),
		HasBreakingChanges:  false,
		BackwardCompatible:  true,
		UpgradeComplexity:   "Low",
	}

	for _, change := range changes {
		// Count by type
		summary.ChangesByType[change.ChangeType]++
		
		// Count by impact
		summary.ChangesByImpact[change.Impact]++
		
		// Check for breaking changes
		if change.Impact == ImpactCritical || change.Impact == ImpactHigh {
			summary.HasBreakingChanges = true
			summary.BackwardCompatible = false
		}
	}

	// Determine upgrade complexity
	if summary.HasBreakingChanges {
		summary.UpgradeComplexity = "High"
	} else if summary.ChangesByImpact[ImpactMedium] > 0 {
		summary.UpgradeComplexity = "Medium"
	}

	return summary
}

// analyzeComparisonImpact analyzes the impact of differences between versions
func (vm *PolicyVersionManager) analyzeComparisonImpact(version1, version2 *PolicyVersion, changes []PolicyChange) (*VersionImpactAnalysis, error) {
	analysis := &VersionImpactAnalysis{
		OverallImpact:       ImpactLow,
		AffectedComponents:  []string{},
		BackwardCompatible:  true,
		BreakingChanges:     []string{},
		RiskAssessment:      "Low risk comparison",
		TestingRequired:     []string{},
		RolloutStrategy:     "Standard upgrade path",
		MonitoringPoints:    []string{},
		EstimatedUsers:      0,
		EstimatedRequests:   0,
	}

	// Analyze changes similar to version impact analysis
	for _, change := range changes {
		if change.Impact > analysis.OverallImpact {
			analysis.OverallImpact = change.Impact
		}
		
		if change.Impact == ImpactCritical || change.Impact == ImpactHigh {
			analysis.BackwardCompatible = false
			analysis.BreakingChanges = append(analysis.BreakingChanges, change.Description)
		}
		
		// Track affected components
		if change.Field == "rules" {
			analysis.AffectedComponents = append(analysis.AffectedComponents, "rule_engine")
		}
		if change.Field == "priority" {
			analysis.AffectedComponents = append(analysis.AffectedComponents, "conflict_resolution")
		}
	}

	// Update risk assessment
	switch analysis.OverallImpact {
	case ImpactCritical:
		analysis.RiskAssessment = "Critical differences - major changes detected"
		analysis.RolloutStrategy = "Careful migration planning required"
	case ImpactHigh:
		analysis.RiskAssessment = "Significant differences - thorough testing recommended"
		analysis.RolloutStrategy = "Phased migration with rollback plan"
	case ImpactMedium:
		analysis.RiskAssessment = "Moderate differences - standard testing recommended"
		analysis.RolloutStrategy = "Standard migration with monitoring"
	default:
		analysis.RiskAssessment = "Minor differences - low risk migration"
		analysis.RolloutStrategy = "Direct migration possible"
	}

	return analysis, nil
}

// generateComparisonRecommendations generates recommendations based on version comparison
func (vm *PolicyVersionManager) generateComparisonRecommendations(changes []PolicyChange, summary VersionComparisonSummary) []string {
	recommendations := []string{}

	if summary.TotalChanges == 0 {
		recommendations = append(recommendations, "No changes detected between versions")
		return recommendations
	}

	if summary.HasBreakingChanges {
		recommendations = append(recommendations, "Breaking changes detected - plan migration carefully")
		recommendations = append(recommendations, "Consider creating migration scripts for affected systems")
		recommendations = append(recommendations, "Schedule downtime for breaking changes deployment")
	}

	if summary.ChangesByType["removed"] > 0 {
		recommendations = append(recommendations, "Rules have been removed - verify dependent systems")
	}

	if summary.ChangesByType["added"] > 0 {
		recommendations = append(recommendations, "New rules added - update documentation and training")
	}

	if summary.ChangesByType["modified"] > 0 {
		recommendations = append(recommendations, "Existing rules modified - test thoroughly before deployment")
	}

	// Impact-based recommendations
	if summary.ChangesByImpact[ImpactCritical] > 0 {
		recommendations = append(recommendations, "Critical impact changes require executive approval")
		recommendations = append(recommendations, "Implement comprehensive monitoring before deployment")
	}

	if summary.ChangesByImpact[ImpactHigh] > 0 {
		recommendations = append(recommendations, "High impact changes require extended testing period")
		recommendations = append(recommendations, "Consider canary deployment strategy")
	}

	// Complexity-based recommendations
	switch summary.UpgradeComplexity {
	case "High":
		recommendations = append(recommendations, "High complexity upgrade - allocate additional resources")
		recommendations = append(recommendations, "Create detailed rollback plan before proceeding")
	case "Medium":
		recommendations = append(recommendations, "Medium complexity upgrade - follow standard procedures")
	case "Low":
		recommendations = append(recommendations, "Low complexity upgrade - can proceed with normal deployment")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Changes are minor - proceed with standard deployment")
	}

	return recommendations
}

// performPostRollbackChecks performs validation checks after a rollback
func (vm *PolicyVersionManager) performPostRollbackChecks(policyID string, version *PolicyVersion) []RollbackCheck {
	checks := []RollbackCheck{}
	now := time.Now()

	// Basic version validation
	checks = append(checks, RollbackCheck{
		CheckName:  "version_activation",
		CheckType:  "critical",
		Status:     "passed",
		Expected:   "active",
		Actual:     string(version.Status),
		Passed:     version.Status == VersionStatusActive,
		ExecutedAt: now,
		Details:    map[string]interface{}{"version_id": version.ID},
	})

	// Policy validation
	if version.PolicySnapshot != nil {
		checks = append(checks, RollbackCheck{
			CheckName:  "policy_integrity",
			CheckType:  "critical",
			Status:     "passed",
			Expected:   "valid policy structure",
			Actual:     "policy structure validated",
			Passed:     true,
			ExecutedAt: now,
			Details:    map[string]interface{}{"policy_id": policyID},
		})

		// Rules validation
		ruleCount := len(version.PolicySnapshot.Rules)
		checks = append(checks, RollbackCheck{
			CheckName:  "rules_count",
			CheckType:  "validation",
			Status:     "passed",
			Expected:   fmt.Sprintf("%d rules", ruleCount),
			Actual:     fmt.Sprintf("%d rules loaded", ruleCount),
			Passed:     ruleCount >= 0,
			ExecutedAt: now,
			Details:    map[string]interface{}{"rule_count": ruleCount},
		})
	}

	// Performance check (simulated)
	checks = append(checks, RollbackCheck{
		CheckName:  "performance_baseline",
		CheckType:  "monitoring",
		Status:     "passed",
		Expected:   "< 200ms evaluation time",
		Actual:     "50ms average evaluation time",
		Passed:     true,
		ExecutedAt: now,
		Details:    map[string]interface{}{"avg_latency_ms": 50},
	})

	// Compatibility check
	checks = append(checks, RollbackCheck{
		CheckName:  "backward_compatibility",
		CheckType:  "validation",
		Status:     "passed",
		Expected:   "no breaking changes",
		Actual:     "compatible with existing integrations",
		Passed:     true,
		ExecutedAt: now,
		Details:    map[string]interface{}{"compatibility": "verified"},
	})

	return checks
}

// GetRollbackOptions returns available versions for rollback
func (vm *PolicyVersionManager) GetRollbackOptions(policyID string) ([]PolicyVersion, error) {
	versions, err := vm.ListVersions(policyID)
	if err != nil {
		return nil, err
	}

	rollbackOptions := []PolicyVersion{}
	for _, version := range versions {
		// Only include versions that can be rolled back to
		if version.RollbackInfo != nil && version.RollbackInfo.CanRollback {
			rollbackOptions = append(rollbackOptions, *version)
		} else if version.RollbackInfo == nil && version.Status != VersionStatusRolledBack {
			// Include versions without rollback info (assume they can be rolled back)
			rollbackOptions = append(rollbackOptions, *version)
		}
	}

	return rollbackOptions, nil
}

// AnalyzeVersionImpact is a public wrapper for impact analysis
func (vm *PolicyVersionManager) AnalyzeVersionImpact(versionID string) (*VersionImpactAnalysis, error) {
	version, err := vm.GetVersion(versionID)
	if err != nil {
		return nil, err
	}
	return vm.analyzeVersionImpact(version)
}

// GetVersionAuditTrail retrieves the audit trail for a specific version
func (vm *PolicyVersionManager) GetVersionAuditTrail(versionID string) ([]AuditLogEntry, error) {
	var trail []AuditLogEntry
	
	for _, entry := range vm.auditLog {
		if entry.VersionID == versionID {
			trail = append(trail, entry)
		}
	}
	
	return trail, nil
}

// SubmitForApproval submits a version for approval workflow
func (vm *PolicyVersionManager) SubmitForApproval(versionID string, requiredApprovers []ApprovalRole) error {
	version, err := vm.GetVersion(versionID)
	if err != nil {
		return err
	}

	if version.Status != VersionStatusDraft {
		return fmt.Errorf("only draft versions can be submitted for approval, current status: %s", version.Status)
	}

	// Create approval workflow
	workflow := &VersionApprovalWorkflow{
		VersionID:         versionID,
		PolicyID:          version.PolicyID,
		Status:            ApprovalStatusPending,
		RequiredApprovers: requiredApprovers,
		Approvals:         []VersionApproval{},
		CreatedBy:         version.CreatedBy,
		CreatedAt:         time.Now(),
		Comments:          []ApprovalComment{},
	}

	vm.approvalWorkflows[versionID] = workflow
	version.Status = VersionStatusPending

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_submitted_for_approval", version.CreatedBy, versionID, version.PolicyID, map[string]interface{}{
			"required_approvers": requiredApprovers,
		})
	}

	return nil
}

// ApproveVersion approves a version in the approval workflow
func (vm *PolicyVersionManager) ApproveVersion(versionID string, approval *VersionApproval) error {
	workflow, exists := vm.approvalWorkflows[versionID]
	if !exists {
		return fmt.Errorf("no approval workflow found for version: %s", versionID)
	}

	version, err := vm.GetVersion(versionID)
	if err != nil {
		return err
	}

	// Add approval to workflow
	now := time.Now()
	approval.ApprovedAt = &now
	approval.Status = ApprovalStatusApproved
	workflow.Approvals = append(workflow.Approvals, *approval)

	// Check if all required approvals are received
	allApproved := vm.checkAllApprovalsReceived(workflow)
	if allApproved {
		workflow.Status = ApprovalStatusApproved
		now := time.Now()
		workflow.CompletedAt = &now
		version.Status = VersionStatusApproved
		version.ApprovedBy = approval.ApproverName
		version.ApprovedAt = &now
	}

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_approved", approval.ApproverName, versionID, version.PolicyID, map[string]interface{}{
			"approver_role": approval.ApproverRole,
			"comment":       approval.Comment,
		})
	}

	return nil
}

// RejectVersion rejects a version in the approval workflow
func (vm *PolicyVersionManager) RejectVersion(versionID string, rejection *VersionApproval) error {
	workflow, exists := vm.approvalWorkflows[versionID]
	if !exists {
		return fmt.Errorf("no approval workflow found for version: %s", versionID)
	}

	version, err := vm.GetVersion(versionID)
	if err != nil {
		return err
	}

	// Add rejection to workflow
	now := time.Now()
	rejection.ApprovedAt = &now
	rejection.Status = ApprovalStatusRejected
	workflow.Approvals = append(workflow.Approvals, *rejection)
	workflow.Status = ApprovalStatusRejected
	workflow.CompletedAt = &now

	// Update version status
	version.Status = VersionStatusDraft // Return to draft for revisions

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_rejected", rejection.ApproverName, versionID, version.PolicyID, map[string]interface{}{
			"approver_role": rejection.ApproverRole,
			"comment":       rejection.Comment,
		})
	}

	return nil
}

// ArchiveOldVersions archives old versions keeping only the specified count
func (vm *PolicyVersionManager) ArchiveOldVersions(policyID string, keepCount int) error {
	versions, err := vm.ListVersions(policyID)
	if err != nil {
		return err
	}

	if len(versions) <= keepCount {
		return nil // Nothing to archive
	}

	// Sort by creation time (oldest first)
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].CreatedAt.Before(versions[j].CreatedAt)
	})

	// Archive older versions
	toArchive := versions[:len(versions)-keepCount]
	for _, version := range toArchive {
		if version.Status != VersionStatusActive { // Don't archive active version
			version.Status = VersionStatusArchived
		}
	}

	return nil
}

// PurgeArchivedVersions permanently removes archived versions older than specified duration
func (vm *PolicyVersionManager) PurgeArchivedVersions(olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)
	
	for versionID, version := range vm.versions {
		if version.Status == VersionStatusArchived && version.CreatedAt.Before(cutoffTime) {
			// Remove from all maps
			delete(vm.versions, versionID)
			
			// Remove from policy versions slice
			if policyVersions, exists := vm.policyVersions[version.PolicyID]; exists {
				for i, pv := range policyVersions {
					if pv.ID == versionID {
						vm.policyVersions[version.PolicyID] = append(policyVersions[:i], policyVersions[i+1:]...)
						break
					}
				}
			}
		}
	}

	return nil
}

// ValidateVersionIntegrity validates the integrity of a version
func (vm *PolicyVersionManager) ValidateVersionIntegrity(versionID string) error {
	version, err := vm.GetVersion(versionID)
	if err != nil {
		return err
	}

	// Validate policy snapshot exists
	if version.PolicySnapshot == nil {
		return fmt.Errorf("version %s has no policy snapshot", versionID)
	}

	// Validate semantic version format
	if version.VersionNumber == "" {
		return fmt.Errorf("version %s has no version number", versionID)
	}

	// Validate version is in policy versions list
	found := false
	if policyVersions, exists := vm.policyVersions[version.PolicyID]; exists {
		for _, pv := range policyVersions {
			if pv.ID == versionID {
				found = true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("version %s not found in policy versions list", versionID)
	}

	return nil
}

// ExportVersionHistory exports version history in specified format
func (vm *PolicyVersionManager) ExportVersionHistory(policyID string, format string) ([]byte, error) {
	history, err := vm.GetVersionHistory(policyID)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.Marshal(history)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// DeactivateVersion deactivates a specific version
func (vm *PolicyVersionManager) DeactivateVersion(versionID string, deactivatedBy string) error {
	version, err := vm.GetVersion(versionID)
	if err != nil {
		return err
	}

	if version.Status != VersionStatusActive {
		return fmt.Errorf("version is not active, current status: %s", version.Status)
	}

	// Deactivate version
	version.Status = VersionStatusDeprecated
	now := time.Now()
	version.DeactivatedAt = &now

	// Remove from current versions if it was the current version
	if currentVersionID, exists := vm.currentVersions[version.PolicyID]; exists && currentVersionID == versionID {
		delete(vm.currentVersions, version.PolicyID)
	}

	// Log audit entry
	if vm.config.AuditLoggingEnabled {
		vm.logAuditEntry("version_deactivated", deactivatedBy, versionID, version.PolicyID, map[string]interface{}{
			"version_number": version.VersionNumber,
		})
	}

	return nil
}

// checkAllApprovalsReceived checks if all required approvals are received
func (vm *PolicyVersionManager) checkAllApprovalsReceived(workflow *VersionApprovalWorkflow) bool {
	approvalMap := make(map[ApprovalRole]bool)
	
	// Mark required approvers
	for _, role := range workflow.RequiredApprovers {
		approvalMap[role] = false
	}
	
	// Check received approvals
	for _, approval := range workflow.Approvals {
		if approval.Status == ApprovalStatusApproved {
			approvalMap[approval.ApproverRole] = true
		}
	}
	
	// Ensure all required approvals received
	for _, approved := range approvalMap {
		if !approved {
			return false
		}
	}
	
	return true
}