package policy

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyVersionManager_CreateVersion(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	// Create test policy
	policy := &Policy{
		ID:          "test-policy-1",
		Name:        "Test Policy",
		Description: "Test policy description",
		Version:     "1.0.0",
		Status:      PolicyStatusActive,
		Priority:    100,
		CreatedBy:   "admin",
		Rules: []PolicyRule{
			{
				ID:       "rule-1",
				Name:     "Test Rule",
				Priority: 10,
				Enabled:  true,
				Action: PolicyAction{
					Type:     ActionBlock,
					Severity: SeverityHigh,
				},
			},
		},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	// Test creating first version
	version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial policy creation")
	require.NoError(t, err)
	assert.NotNil(t, version)
	assert.Equal(t, "1.0.0", version.VersionNumber)
	assert.Equal(t, VersionStatusDraft, version.Status)
	assert.Equal(t, ChangeTypeCreation, version.ChangeType)
	assert.Equal(t, "Initial policy creation", version.ChangeReason)
	assert.NotNil(t, version.PolicySnapshot)
	assert.Equal(t, policy.Name, version.PolicySnapshot.Name)
	assert.Equal(t, 1, version.MajorVersion)
	assert.Equal(t, 0, version.MinorVersion)
	assert.Equal(t, 0, version.PatchVersion)

	// Test creating second version (minor change)
	policy.Description = "Updated description"
	version2, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeMinor, "Updated description")
	require.NoError(t, err)
	assert.Equal(t, "1.1.0", version2.VersionNumber)
	assert.Equal(t, 1, version2.MajorVersion)
	assert.Equal(t, 1, version2.MinorVersion)
	assert.Equal(t, 0, version2.PatchVersion)
	assert.Equal(t, version.VersionNumber, version2.PreviousVersion)

	// Verify change detection
	assert.NotEmpty(t, version2.ChangeSummary)
	found := false
	for _, change := range version2.ChangeSummary {
		if change.Field == "description" {
			found = true
			assert.Equal(t, "modified", change.ChangeType)
			assert.Equal(t, "Test policy description", change.OldValue)
			assert.Equal(t, "Updated description", change.NewValue)
		}
	}
	assert.True(t, found, "Description change not detected")
}

func TestPolicyVersionManager_GetVersion(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Test getting version by ID
	retrieved, err := vm.GetVersion(version.ID)
	require.NoError(t, err)
	assert.Equal(t, version.ID, retrieved.ID)
	assert.Equal(t, version.VersionNumber, retrieved.VersionNumber)

	// Test getting non-existent version
	_, err = vm.GetVersion("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version not found")
}

func TestPolicyVersionManager_GetVersionByNumber(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Test getting version by number
	retrieved, err := vm.GetVersionByNumber("test-policy-1", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, version.ID, retrieved.ID)
	assert.Equal(t, "1.0.0", retrieved.VersionNumber)

	// Test getting non-existent version number
	_, err = vm.GetVersionByNumber("test-policy-1", "2.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version 2.0.0 not found")

	// Test getting version for non-existent policy
	_, err = vm.GetVersionByNumber("non-existent-policy", "1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions found")
}

func TestPolicyVersionManager_ActivateVersion(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Test activating version
	err = vm.ActivateVersion(version.ID, "admin")
	require.NoError(t, err)
	
	// Verify version is active
	retrieved, err := vm.GetVersion(version.ID)
	require.NoError(t, err)
	assert.Equal(t, VersionStatusActive, retrieved.Status)
	assert.NotNil(t, retrieved.ActivatedAt)

	// Verify it's set as current version
	currentVersion, err := vm.GetCurrentVersion("test-policy-1")
	require.NoError(t, err)
	assert.Equal(t, version.ID, currentVersion.ID)

	// Create and activate second version
	policy.Description = "Updated"
	version2, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeMinor, "Update")
	require.NoError(t, err)
	
	err = vm.ActivateVersion(version2.ID, "admin")
	require.NoError(t, err)

	// Verify first version is deprecated
	retrieved, err = vm.GetVersion(version.ID)
	require.NoError(t, err)
	assert.Equal(t, VersionStatusDeprecated, retrieved.Status)
	assert.NotNil(t, retrieved.DeactivatedAt)

	// Verify second version is current
	currentVersion, err = vm.GetCurrentVersion("test-policy-1")
	require.NoError(t, err)
	assert.Equal(t, version2.ID, currentVersion.ID)
}

func TestPolicyVersionManager_CompareVersions(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	// Create initial policy
	policy1 := &Policy{
		ID:          "test-policy-1",
		Name:        "Test Policy",
		Description: "Original description",
		Priority:    100,
		CreatedBy:   "admin",
		Rules: []PolicyRule{
			{
				ID:       "rule-1",
				Name:     "Original Rule",
				Priority: 10,
				Enabled:  true,
				Action: PolicyAction{
					Type:     ActionWarn,
					Severity: SeverityMedium,
				},
			},
		},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version1, err := vm.CreateVersion("test-policy-1", policy1, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Create modified policy
	policy2 := &Policy{
		ID:          "test-policy-1",
		Name:        "Test Policy",
		Description: "Updated description",
		Priority:    150,
		CreatedBy:   "admin",
		Rules: []PolicyRule{
			{
				ID:       "rule-1",
				Name:     "Updated Rule",
				Priority: 10,
				Enabled:  true,
				Action: PolicyAction{
					Type:     ActionBlock,
					Severity: SeverityHigh,
				},
			},
			{
				ID:       "rule-2",
				Name:     "New Rule",
				Priority: 20,
				Enabled:  true,
				Action: PolicyAction{
					Type:     ActionRedact,
					Severity: SeverityMedium,
				},
			},
		},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version2, err := vm.CreateVersion("test-policy-1", policy2, ChangeTypeMajor, "Major update")
	require.NoError(t, err)

	// Compare versions
	comparison, err := vm.CompareVersions(version1.ID, version2.ID)
	require.NoError(t, err)
	
	assert.Equal(t, version1.VersionNumber, comparison.Version1)
	assert.Equal(t, version2.VersionNumber, comparison.Version2)
	assert.NotEmpty(t, comparison.Changes)
	assert.True(t, comparison.Summary.TotalChanges > 0)
	
	// Check for specific changes
	foundDescriptionChange := false
	foundPriorityChange := false
	foundRuleChange := false
	
	for _, change := range comparison.Changes {
		switch change.Field {
		case "description":
			foundDescriptionChange = true
			assert.Equal(t, "modified", change.ChangeType)
		case "priority":
			foundPriorityChange = true
			assert.Equal(t, "modified", change.ChangeType)
		case "rules":
			foundRuleChange = true
		}
	}
	
	assert.True(t, foundDescriptionChange, "Description change not found")
	assert.True(t, foundPriorityChange, "Priority change not found")
	assert.True(t, foundRuleChange, "Rule change not found")
}

func TestPolicyVersionManager_RollbackToVersion(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	// Create initial policy
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version1, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)
	
	err = vm.ActivateVersion(version1.ID, "admin")
	require.NoError(t, err)

	// Create second version
	policy.Description = "Updated description"
	version2, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeMinor, "Update")
	require.NoError(t, err)
	
	err = vm.ActivateVersion(version2.ID, "admin")
	require.NoError(t, err)

	// Rollback to version 1
	rollbackRequest := &VersionRollbackRequest{
		PolicyID:          "test-policy-1",
		CurrentVersion:    version2.VersionNumber,
		TargetVersion:     version1.VersionNumber,
		RollbackReason:    "Bug found in version 2",
		RequestedBy:       "admin",
		RequestedAt:       time.Now(),
		ImmediateRollback: true,
		BackupCurrent:     true,
	}

	result, err := vm.RollbackToVersion(rollbackRequest)
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, version2.VersionNumber, result.FromVersion)
	assert.Equal(t, version1.VersionNumber, result.ToVersion)
	assert.NotEmpty(t, result.PostRollbackChecks)

	// Verify version 1 is active again
	currentVersion, err := vm.GetCurrentVersion("test-policy-1")
	require.NoError(t, err)
	assert.Equal(t, version1.ID, currentVersion.ID)
	assert.Equal(t, VersionStatusActive, currentVersion.Status)

	// Verify rollback info is updated
	assert.NotNil(t, currentVersion.RollbackInfo)
	assert.Equal(t, "Bug found in version 2", currentVersion.RollbackInfo.RollbackReason)
	assert.Equal(t, "admin", currentVersion.RollbackInfo.RollbackBy)
}

func TestPolicyVersionManager_ApprovalWorkflow(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Submit for approval
	requiredApprovers := []ApprovalRole{ApprovalRoleSecurityOfficer, ApprovalRolePolicyOwner}
	err = vm.SubmitForApproval(version.ID, requiredApprovers)
	require.NoError(t, err)

	// Verify status changed to pending
	retrieved, err := vm.GetVersion(version.ID)
	require.NoError(t, err)
	assert.Equal(t, VersionStatusPending, retrieved.Status)

	// Approve by security officer
	securityApproval := &VersionApproval{
		ApproverRole:  ApprovalRoleSecurityOfficer,
		ApproverName:  "security-admin",
		ApproverEmail: "security@company.com",
		Comment:       "Security review passed",
	}
	
	err = vm.ApproveVersion(version.ID, securityApproval)
	require.NoError(t, err)

	// Verify still pending (need policy owner approval)
	retrieved, err = vm.GetVersion(version.ID)
	require.NoError(t, err)
	assert.Equal(t, VersionStatusPending, retrieved.Status)

	// Approve by policy owner
	ownerApproval := &VersionApproval{
		ApproverRole:  ApprovalRolePolicyOwner,
		ApproverName:  "policy-owner",
		ApproverEmail: "owner@company.com",
		Comment:       "Policy approved",
	}
	
	err = vm.ApproveVersion(version.ID, ownerApproval)
	require.NoError(t, err)

	// Verify now approved
	retrieved, err = vm.GetVersion(version.ID)
	require.NoError(t, err)
	assert.Equal(t, VersionStatusApproved, retrieved.Status)
	assert.Equal(t, "policy-owner", retrieved.ApprovedBy)
	assert.NotNil(t, retrieved.ApprovedAt)
}

func TestPolicyVersionManager_GetVersionHistory(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	// Create multiple versions
	version1, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)
	
	policy.Description = "Updated"
	version2, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeMinor, "Minor update")
	require.NoError(t, err)
	
	policy.Priority = 200
	version3, err := vm.CreateVersion("test-policy-1", policy, ChangeTypePatch, "Priority update")
	require.NoError(t, err)

	// Get version history
	history, err := vm.GetVersionHistory("test-policy-1")
	require.NoError(t, err)
	
	assert.Equal(t, "test-policy-1", history.PolicyID)
	assert.Equal(t, "Test Policy", history.PolicyName)
	assert.Equal(t, 3, history.TotalVersions)
	assert.Len(t, history.Versions, 3)
	
	// Verify versions are included
	versionNumbers := make([]string, len(history.Versions))
	for i, v := range history.Versions {
		versionNumbers[i] = v.VersionNumber
	}
	assert.Contains(t, versionNumbers, version1.VersionNumber)
	assert.Contains(t, versionNumbers, version2.VersionNumber)
	assert.Contains(t, versionNumbers, version3.VersionNumber)
}

func TestPolicyVersionManager_ArchiveOldVersions(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	// Create 5 versions
	versions := make([]*PolicyVersion, 5)
	for i := 0; i < 5; i++ {
		policy.Description = fmt.Sprintf("Version %d", i+1)
		version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeMinor, fmt.Sprintf("Update %d", i+1))
		require.NoError(t, err)
		versions[i] = version
	}

	// Activate the latest version
	err := vm.ActivateVersion(versions[4].ID, "admin")
	require.NoError(t, err)

	// Archive old versions, keeping only 3
	err = vm.ArchiveOldVersions("test-policy-1", 3)
	require.NoError(t, err)

	// Check that first 2 versions are archived
	for i := 0; i < 2; i++ {
		version, err := vm.GetVersion(versions[i].ID)
		require.NoError(t, err)
		assert.Equal(t, VersionStatusArchived, version.Status)
	}

	// Check that last 3 versions are not archived
	for i := 2; i < 5; i++ {
		version, err := vm.GetVersion(versions[i].ID)
		require.NoError(t, err)
		if i == 4 {
			assert.Equal(t, VersionStatusActive, version.Status) // Latest is active
		} else {
			assert.NotEqual(t, VersionStatusArchived, version.Status)
		}
	}
}

func TestPolicyVersionManager_ValidateVersionIntegrity(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Test valid version
	err = vm.ValidateVersionIntegrity(version.ID)
	assert.NoError(t, err)

	// Test non-existent version
	err = vm.ValidateVersionIntegrity("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version not found")

	// Test version with no policy snapshot
	version.PolicySnapshot = nil
	err = vm.ValidateVersionIntegrity(version.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has no policy snapshot")
}

func TestPolicyVersionManager_ExportVersionHistory(t *testing.T) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "test-policy-1",
		Name:      "Test Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	_, err := vm.CreateVersion("test-policy-1", policy, ChangeTypeCreation, "Initial creation")
	require.NoError(t, err)

	// Export as JSON
	data, err := vm.ExportVersionHistory("test-policy-1", "json")
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Test unsupported format
	_, err = vm.ExportVersionHistory("test-policy-1", "xml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported export format")
}

// Benchmark tests
func BenchmarkVersionManager_CreateVersion(b *testing.B) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "benchmark-policy",
		Name:      "Benchmark Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy.Description = fmt.Sprintf("Version %d", i)
		_, err := vm.CreateVersion("benchmark-policy", policy, ChangeTypeMinor, "Benchmark update")
		if err != nil {
			b.Fatalf("Failed to create version: %v", err)
		}
	}
}

func BenchmarkVersionManager_GetVersion(b *testing.B) {
	vm := NewPolicyVersionManager(nil)
	
	policy := &Policy{
		ID:        "benchmark-policy",
		Name:      "Benchmark Policy",
		CreatedBy: "admin",
		Rules:     []PolicyRule{},
		DefaultAction: PolicyAction{
			Type:     ActionAllow,
			Severity: SeverityInfo,
		},
	}

	version, err := vm.CreateVersion("benchmark-policy", policy, ChangeTypeCreation, "Initial creation")
	if err != nil {
		b.Fatalf("Failed to create version: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := vm.GetVersion(version.ID)
		if err != nil {
			b.Fatalf("Failed to get version: %v", err)
		}
	}
} 