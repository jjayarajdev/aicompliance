package policy

import (
	"context"
	"regexp"
	"sync"
	"time"

	"ai-gateway-poc/internal/analysis"
)

// Policy represents a complete policy with metadata and rules
type Policy struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Version      string                 `json:"version"`
	Status       PolicyStatus           `json:"status"`
	Priority     int                    `json:"priority"`
	Category     string                 `json:"category"`
	Tags         []string               `json:"tags"`
	Owner        string                 `json:"owner"`
	CreatedBy    string                 `json:"created_by"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	EffectiveAt  *time.Time             `json:"effective_at,omitempty"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
	
	// Rule definitions
	Rules        []PolicyRule           `json:"rules"`
	DefaultAction PolicyAction          `json:"default_action"`
	
	// Configuration
	Scope        PolicyScope            `json:"scope"`
	Conditions   *PolicyCondition       `json:"conditions,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
	
	// Performance and monitoring
	ExecutionCount int64                `json:"execution_count"`
	LastExecuted   *time.Time           `json:"last_executed,omitempty"`
	AverageLatency time.Duration        `json:"average_latency"`
}

// PolicyStatus represents the current status of a policy
type PolicyStatus string

const (
	PolicyStatusDraft    PolicyStatus = "draft"
	PolicyStatusActive   PolicyStatus = "active"
	PolicyStatusInactive PolicyStatus = "inactive"
	PolicyStatusArchived PolicyStatus = "archived"
	PolicyStatusTesting  PolicyStatus = "testing"
)

// PolicyRule represents an individual rule within a policy
type PolicyRule struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Priority     int              `json:"priority"`
	Enabled      bool             `json:"enabled"`
	
	// Rule logic
	Condition    *PolicyCondition `json:"condition"`
	Action       PolicyAction     `json:"action"`
	
	// Metadata
	CreatedBy    string           `json:"created_by"`
	CreatedAt    time.Time        `json:"created_at"`
	Tags         []string         `json:"tags"`
	
	// Performance tracking
	HitCount     int64            `json:"hit_count"`
	LastTriggered *time.Time      `json:"last_triggered,omitempty"`
}

// PolicyCondition represents complex conditional logic
type PolicyCondition struct {
	Type      ConditionType            `json:"type"`
	Operator  LogicalOperator          `json:"operator,omitempty"`
	Field     string                   `json:"field,omitempty"`
	Value     interface{}              `json:"value,omitempty"`
	Children  []*PolicyCondition       `json:"children,omitempty"`
	
	// Advanced condition properties
	CaseSensitive    bool            `json:"case_sensitive,omitempty"`
	Regex            bool            `json:"regex,omitempty"`
	Threshold        *float64        `json:"threshold,omitempty"`
	TimeWindow       *time.Duration  `json:"time_window,omitempty"`
	AggregationType  string          `json:"aggregation_type,omitempty"`
}

// ConditionType represents the type of condition
type ConditionType string

const (
	// Basic conditions
	ConditionEquals          ConditionType = "equals"
	ConditionNotEquals       ConditionType = "not_equals"
	ConditionContains        ConditionType = "contains"
	ConditionNotContains     ConditionType = "not_contains"
	ConditionStartsWith      ConditionType = "starts_with"
	ConditionEndsWith        ConditionType = "ends_with"
	ConditionMatches         ConditionType = "matches"
	ConditionNotMatches      ConditionType = "not_matches"
	
	// Numeric conditions
	ConditionGreaterThan     ConditionType = "greater_than"
	ConditionGreaterEqual    ConditionType = "greater_equal"
	ConditionLessThan        ConditionType = "less_than"
	ConditionLessEqual       ConditionType = "less_equal"
	ConditionBetween         ConditionType = "between"
	ConditionNotBetween      ConditionType = "not_between"
	
	// Collection conditions
	ConditionIn              ConditionType = "in"
	ConditionNotIn           ConditionType = "not_in"
	ConditionEmpty           ConditionType = "empty"
	ConditionNotEmpty        ConditionType = "not_empty"
	ConditionCount           ConditionType = "count"
	
	// Complex conditions
	ConditionAnd             ConditionType = "and"
	ConditionOr              ConditionType = "or"
	ConditionNot             ConditionType = "not"
	ConditionAny             ConditionType = "any"
	ConditionAll             ConditionType = "all"
	ConditionNone            ConditionType = "none"
	
	// Analysis-specific conditions
	ConditionPIIDetected     ConditionType = "pii_detected"
	ConditionSensitivityLevel ConditionType = "sensitivity_level"
	ConditionConfidenceAbove ConditionType = "confidence_above"
	ConditionRiskLevel       ConditionType = "risk_level"
	ConditionEntityCount     ConditionType = "entity_count"
	ConditionSentiment       ConditionType = "sentiment"
	ConditionBusinessCategory ConditionType = "business_category"
)

// LogicalOperator represents logical operators for combining conditions
type LogicalOperator string

const (
	LogicalAnd LogicalOperator = "AND"
	LogicalOr  LogicalOperator = "OR"
	LogicalNot LogicalOperator = "NOT"
)

// PolicyAction represents the action to take when a rule matches
type PolicyAction struct {
	Type         ActionType             `json:"type"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Severity     ActionSeverity         `json:"severity"`
	
	// Action modifiers
	StopProcessing bool                 `json:"stop_processing,omitempty"`
	LogDecision    bool                 `json:"log_decision"`
	NotifyAdmin    bool                 `json:"notify_admin,omitempty"`
	
	// Custom actions
	CustomHandler  string               `json:"custom_handler,omitempty"`
	Webhook        *WebhookConfig       `json:"webhook,omitempty"`
}

// ActionType represents the type of action to take
type ActionType string

const (
	// Basic actions
	ActionAllow        ActionType = "allow"
	ActionBlock        ActionType = "block"
	ActionWarn         ActionType = "warn"
	ActionLog          ActionType = "log"
	
	// Content modification actions
	ActionRedact       ActionType = "redact"
	ActionMask         ActionType = "mask"
	ActionTokenize     ActionType = "tokenize"
	ActionSanitize     ActionType = "sanitize"
	
	// Routing actions
	ActionRoute        ActionType = "route"
	ActionQueue        ActionType = "queue"
	ActionDelay        ActionType = "delay"
	ActionRetry        ActionType = "retry"
	
	// Security actions
	ActionQuarantine   ActionType = "quarantine"
	ActionFlag         ActionType = "flag"
	ActionEncrypt      ActionType = "encrypt"
	ActionAudit        ActionType = "audit"
	
	// Custom actions
	ActionCustom       ActionType = "custom"
	ActionWebhook      ActionType = "webhook"
)

// ActionSeverity represents the severity level of an action
type ActionSeverity string

const (
	SeverityInfo     ActionSeverity = "info"
	SeverityLow      ActionSeverity = "low"
	SeverityMedium   ActionSeverity = "medium"
	SeverityHigh     ActionSeverity = "high"
	SeverityCritical ActionSeverity = "critical"
)

// WebhookConfig configures webhook actions
type WebhookConfig struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     time.Duration     `json:"timeout"`
	RetryCount  int               `json:"retry_count"`
	RetryDelay  time.Duration     `json:"retry_delay"`
}

// PolicyScope defines the scope where a policy applies
type PolicyScope struct {
	Organizations  []string `json:"organizations,omitempty"`
	Users          []string `json:"users,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	ContentTypes   []string `json:"content_types,omitempty"`
	Sources        []string `json:"sources,omitempty"`
	TimeWindows    []TimeWindow `json:"time_windows,omitempty"`
}

// TimeWindow defines a time-based scope
type TimeWindow struct {
	StartTime    string `json:"start_time"` // HH:MM format
	EndTime      string `json:"end_time"`   // HH:MM format
	Days         []string `json:"days"`     // Monday, Tuesday, etc.
	Timezone     string `json:"timezone"`
}

// PolicyRuleset represents a collection of related policies
type PolicyRuleset struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Version      string                 `json:"version"`
	Policies     []string               `json:"policies"` // Policy IDs
	Priority     int                    `json:"priority"`
	Enabled      bool                   `json:"enabled"`
	CreatedBy    string                 `json:"created_by"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PolicyEvaluationRequest represents a request to evaluate policies
type PolicyEvaluationRequest struct {
	ID           string                    `json:"id"`
	Content      string                    `json:"content"`
	ContentType  string                    `json:"content_type"`
	Source       string                    `json:"source"`
	User         string                    `json:"user"`
	Organization string                    `json:"organization"`
	Roles        []string                  `json:"roles"`
	Context      map[string]interface{}    `json:"context"`
	Analysis     *analysis.AnalysisResult  `json:"analysis"`
	Timestamp    time.Time                 `json:"timestamp"`
}

// PolicyEvaluationResult represents the result of policy evaluation
type PolicyEvaluationResult struct {
	RequestID        string                 `json:"request_id"`
	Decision         PolicyDecision         `json:"decision"`
	MatchedPolicies  []PolicyMatch          `json:"matched_policies"`
	Actions          []ExecutedAction       `json:"actions"`
	Confidence       float64                `json:"confidence"`
	ProcessingTime   time.Duration          `json:"processing_time"`
	Timestamp        time.Time              `json:"timestamp"`
	
	// Detailed results
	EvaluationTrace  []EvaluationStep       `json:"evaluation_trace,omitempty"`
	Conflicts        []PolicyConflict       `json:"conflicts,omitempty"`
	Recommendations  []string               `json:"recommendations"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// PolicyDecision represents the final decision
type PolicyDecision struct {
	Action           ActionType             `json:"action"`
	Reason           string                 `json:"reason"`
	Confidence       float64                `json:"confidence"`
	Severity         ActionSeverity         `json:"severity"`
	Message          string                 `json:"message,omitempty"`
	ProcessedContent string                 `json:"processed_content,omitempty"`
	Parameters       map[string]interface{} `json:"parameters,omitempty"`
}

// PolicyMatch represents a matched policy
type PolicyMatch struct {
	PolicyID         string           `json:"policy_id"`
	PolicyName       string           `json:"policy_name"`
	RuleID           string           `json:"rule_id,omitempty"`
	RuleName         string           `json:"rule_name,omitempty"`
	Priority         int              `json:"priority"`
	Confidence       float64          `json:"confidence"`
	MatchedConditions []ConditionMatch `json:"matched_conditions"`
	Action           PolicyAction     `json:"action"`
}

// ConditionMatch represents a matched condition
type ConditionMatch struct {
	Field           string      `json:"field"`
	Operator        string      `json:"operator"`
	Expected        interface{} `json:"expected"`
	Actual          interface{} `json:"actual"`
	Matched         bool        `json:"matched"`
	Confidence      float64     `json:"confidence"`
	Details         string      `json:"details,omitempty"`
}

// ExecutedAction represents an action that was executed
type ExecutedAction struct {
	Type           ActionType             `json:"type"`
	Status         ActionStatus           `json:"status"`
	Result         interface{}            `json:"result,omitempty"`
	Error          string                 `json:"error,omitempty"`
	ExecutionTime  time.Duration          `json:"execution_time"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
}

// ActionStatus represents the status of action execution
type ActionStatus string

const (
	ActionStatusSuccess  ActionStatus = "success"
	ActionStatusFailed   ActionStatus = "failed"
	ActionStatusSkipped  ActionStatus = "skipped"
	ActionStatusPending  ActionStatus = "pending"
)

// EvaluationStep represents one step in policy evaluation
type EvaluationStep struct {
	StepType       string                 `json:"step_type"`
	PolicyID       string                 `json:"policy_id,omitempty"`
	RuleID         string                 `json:"rule_id,omitempty"`
	Condition      *PolicyCondition       `json:"condition,omitempty"`
	Result         bool                   `json:"result"`
	Details        string                 `json:"details"`
	ExecutionTime  time.Duration          `json:"execution_time"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ConflictType represents the type of policy conflict
type ConflictType string

const (
	ConflictTypeAction     ConflictType = "action_conflict"
	ConflictTypePriority   ConflictType = "priority_conflict"
	ConflictTypeScope      ConflictType = "scope_conflict"
	ConflictTypeCondition  ConflictType = "condition_conflict"
)

// ConflictSeverity represents the severity of a policy conflict
type ConflictSeverity string

const (
	ConflictSeverityLow    ConflictSeverity = "low"
	ConflictSeverityMedium ConflictSeverity = "medium"
	ConflictSeverityHigh   ConflictSeverity = "high"
)

// PolicyConflict represents a conflict between policies
type PolicyConflict struct {
	Type           ConflictType     `json:"type"`
	PolicyIDs      []string         `json:"policy_ids"`
	PolicyNames    []string         `json:"policy_names"`
	Description    string           `json:"description"`
	Severity       ConflictSeverity `json:"severity"`
	Resolution     string           `json:"resolution"`
	ResolvedBy     string           `json:"resolved_by"`
}

// PolicyValidator provides validation for policies
type PolicyValidator struct {
	schema          *PolicySchema
	customValidators map[string]ValidatorFunc
}

// PolicySchema defines the validation schema for policies
type PolicySchema struct {
	RequiredFields    []string                    `json:"required_fields"`
	FieldTypes        map[string]string           `json:"field_types"`
	FieldConstraints  map[string]FieldConstraint  `json:"field_constraints"`
	CustomValidations []CustomValidation          `json:"custom_validations"`
}

// FieldConstraint defines constraints for policy fields
type FieldConstraint struct {
	MinValue     *float64 `json:"min_value,omitempty"`
	MaxValue     *float64 `json:"max_value,omitempty"`
	MinLength    *int     `json:"min_length,omitempty"`
	MaxLength    *int     `json:"max_length,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
	AllowedValues []interface{} `json:"allowed_values,omitempty"`
	Required     bool     `json:"required"`
}

// CustomValidation defines custom validation rules
type CustomValidation struct {
	Name        string                 `json:"name"`
	Field       string                 `json:"field"`
	Function    string                 `json:"function"`
	Parameters  map[string]interface{} `json:"parameters"`
	ErrorMessage string                `json:"error_message"`
}

// ValidatorFunc represents a custom validation function
type ValidatorFunc func(value interface{}, params map[string]interface{}) error

// PolicyValidationResult represents the result of policy validation
type PolicyValidationResult struct {
	Valid        bool                    `json:"valid"`
	Errors       []ValidationError       `json:"errors,omitempty"`
	Warnings     []ValidationWarning     `json:"warnings,omitempty"`
	Suggestions  []ValidationSuggestion  `json:"suggestions,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
}

// ValidationSuggestion represents a validation suggestion
type ValidationSuggestion struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Suggestion  string `json:"suggestion"`
}

// PolicyLogger interface for policy logging
type PolicyLogger interface {
	LogEvaluation(result *PolicyEvaluationResult) error
	LogAction(action *ExecutedAction) error
	LogConflict(conflict *PolicyConflict) error
	GetEvaluationHistory(filters PolicyLogFilters) ([]PolicyEvaluationResult, error)
}

// PolicyLogFilters defines filters for policy log queries
type PolicyLogFilters struct {
	PolicyIDs     []string    `json:"policy_ids,omitempty"`
	Users         []string    `json:"users,omitempty"`
	Organizations []string    `json:"organizations,omitempty"`
	Actions       []ActionType `json:"actions,omitempty"`
	StartTime     *time.Time  `json:"start_time,omitempty"`
	EndTime       *time.Time  `json:"end_time,omitempty"`
	Limit         int         `json:"limit,omitempty"`
	Offset        int         `json:"offset,omitempty"`
}

// PolicyCacheInterface interface for policy caching
type PolicyCacheInterface interface {
	GetPolicy(id string) (*Policy, error)
	SetPolicy(policy *Policy) error
	InvalidatePolicy(id string) error
	GetEvaluationResult(requestHash string) (*PolicyEvaluationResult, error)
	SetEvaluationResult(requestHash string, result *PolicyEvaluationResult, ttl time.Duration) error
}

// PolicyMetrics interface for policy metrics collection
type PolicyMetrics interface {
	RecordEvaluation(policyID string, duration time.Duration)
	RecordAction(actionType ActionType, status ActionStatus)
	RecordConflict(conflictType ConflictType)
	GetPolicyStats(policyID string) PolicyStats
}

// PolicyStats represents policy execution statistics
type PolicyStats struct {
	PolicyID         string        `json:"policy_id"`
	ExecutionCount   int64         `json:"execution_count"`
	MatchCount       int64         `json:"match_count"`
	AverageLatency   time.Duration `json:"average_latency"`
	MaxLatency       time.Duration `json:"max_latency"`
	MinLatency       time.Duration `json:"min_latency"`
	ErrorCount       int64         `json:"error_count"`
	LastExecuted     *time.Time    `json:"last_executed"`
}

// ===== POLICY VERSIONING SYSTEM =====

// PolicyVersion represents a specific version of a policy with complete snapshot
type PolicyVersion struct {
	ID              string                 `json:"id"`              // Unique version ID
	PolicyID        string                 `json:"policy_id"`       // Policy this version belongs to
	VersionNumber   string                 `json:"version_number"`  // Semantic version (e.g., "1.2.0")
	MajorVersion    int                    `json:"major_version"`
	MinorVersion    int                    `json:"minor_version"`
	PatchVersion    int                    `json:"patch_version"`
	
	// Policy snapshot - complete policy at this version
	PolicySnapshot  *Policy                `json:"policy_snapshot"`
	
	// Version metadata
	Status          PolicyVersionStatus    `json:"status"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       time.Time              `json:"created_at"`
	ApprovedBy      string                 `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time             `json:"approved_at,omitempty"`
	ActivatedAt     *time.Time             `json:"activated_at,omitempty"`
	DeactivatedAt   *time.Time             `json:"deactivated_at,omitempty"`
	
	// Change tracking
	ChangeType      PolicyChangeType       `json:"change_type"`
	ChangeReason    string                 `json:"change_reason"`
	ChangeNotes     string                 `json:"change_notes"`
	ChangeSummary   []PolicyChange         `json:"change_summary"`
	PreviousVersion string                 `json:"previous_version,omitempty"`
	NextVersion     string                 `json:"next_version,omitempty"`
	
	// Impact analysis
	ImpactAnalysis  *VersionImpactAnalysis `json:"impact_analysis,omitempty"`
	RollbackInfo    *RollbackInformation   `json:"rollback_info,omitempty"`
	
	// Metadata
	Tags            []string               `json:"tags"`
	Environment     string                 `json:"environment"`     // dev, staging, prod
	ReleaseNotes    string                 `json:"release_notes"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// PolicyVersionStatus represents the status of a policy version
type PolicyVersionStatus string

const (
	VersionStatusDraft      PolicyVersionStatus = "draft"       // Being edited
	VersionStatusPending    PolicyVersionStatus = "pending"     // Awaiting approval
	VersionStatusApproved   PolicyVersionStatus = "approved"    // Approved but not active
	VersionStatusActive     PolicyVersionStatus = "active"      // Currently active version
	VersionStatusDeprecated PolicyVersionStatus = "deprecated"  // Superseded by newer version
	VersionStatusArchived   PolicyVersionStatus = "archived"    // Archived/historical
	VersionStatusRolledBack PolicyVersionStatus = "rolled_back" // Rolled back due to issues
)

// PolicyChangeType represents the type of change between versions
type PolicyChangeType string

const (
	ChangeTypeCreation     PolicyChangeType = "creation"      // Initial policy creation
	ChangeTypeMajor        PolicyChangeType = "major"         // Breaking changes
	ChangeTypeMinor        PolicyChangeType = "minor"         // New features, backward compatible
	ChangeTypePatch        PolicyChangeType = "patch"         // Bug fixes, minor tweaks
	ChangeTypeHotfix       PolicyChangeType = "hotfix"        // Emergency fixes
	ChangeTypeRollback     PolicyChangeType = "rollback"      // Rollback to previous version
	ChangeTypeDeprecation  PolicyChangeType = "deprecation"   // Marking as deprecated
	ChangeTypeArchival     PolicyChangeType = "archival"      // Moving to archive
)

// PolicyChange represents a specific change between policy versions
type PolicyChange struct {
	Field           string                 `json:"field"`             // Field that changed
	ChangeType      string                 `json:"change_type"`       // added, modified, removed
	OldValue        interface{}            `json:"old_value,omitempty"`
	NewValue        interface{}            `json:"new_value,omitempty"`
	Description     string                 `json:"description"`
	Impact          ChangeImpact           `json:"impact"`
	AffectedRules   []string               `json:"affected_rules,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ChangeImpact represents the impact level of a change
type ChangeImpact string

const (
	ImpactLow       ChangeImpact = "low"       // Minimal impact
	ImpactMedium    ChangeImpact = "medium"    // Moderate impact
	ImpactHigh      ChangeImpact = "high"      // Significant impact
	ImpactCritical  ChangeImpact = "critical"  // Critical breaking changes
)

// VersionImpactAnalysis provides detailed analysis of version changes
type VersionImpactAnalysis struct {
	OverallImpact       ChangeImpact           `json:"overall_impact"`
	AffectedComponents  []string               `json:"affected_components"`
	BackwardCompatible  bool                   `json:"backward_compatible"`
	BreakingChanges     []string               `json:"breaking_changes"`
	RiskAssessment      string                 `json:"risk_assessment"`
	TestingRequired     []string               `json:"testing_required"`
	RolloutStrategy     string                 `json:"rollout_strategy"`
	MonitoringPoints    []string               `json:"monitoring_points"`
	EstimatedUsers      int                    `json:"estimated_users"`
	EstimatedRequests   int64                  `json:"estimated_requests"`
}

// RollbackInformation contains information needed for rolling back a version
type RollbackInformation struct {
	CanRollback        bool                   `json:"can_rollback"`
	RollbackToVersion  string                 `json:"rollback_to_version,omitempty"`
	RollbackReason     string                 `json:"rollback_reason,omitempty"`
	RollbackBy         string                 `json:"rollback_by,omitempty"`
	RollbackAt         *time.Time             `json:"rollback_at,omitempty"`
	PreRollbackCheck   []string               `json:"pre_rollback_check"`
	PostRollbackCheck  []string               `json:"post_rollback_check"`
	RollbackRisks      []string               `json:"rollback_risks"`
	DataMigrationNeeded bool                  `json:"data_migration_needed"`
	EstimatedDowntime  time.Duration          `json:"estimated_downtime"`
}

// PolicyVersionHistory tracks the complete version history of a policy
type PolicyVersionHistory struct {
	PolicyID         string                 `json:"policy_id"`
	PolicyName       string                 `json:"policy_name"`
	Versions         []PolicyVersion        `json:"versions"`
	CurrentVersion   string                 `json:"current_version"`
	TotalVersions    int                    `json:"total_versions"`
	CreatedAt        time.Time              `json:"created_at"`
	LastModified     time.Time              `json:"last_modified"`
	VersionBranches  []VersionBranch        `json:"version_branches,omitempty"`
}

// VersionBranch represents different version branches (e.g., for A/B testing)
type VersionBranch struct {
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Versions        []string  `json:"versions"`
	Active          bool      `json:"active"`
	TrafficPercent  float64   `json:"traffic_percent"`
	CreatedAt       time.Time `json:"created_at"`
}

// VersionComparisonResult shows differences between two policy versions
type VersionComparisonResult struct {
	Version1        string                 `json:"version1"`
	Version2        string                 `json:"version2"`
	Changes         []PolicyChange         `json:"changes"`
	Summary         VersionComparisonSummary `json:"summary"`
	ImpactAnalysis  *VersionImpactAnalysis `json:"impact_analysis"`
	Recommendations []string               `json:"recommendations"`
}

// VersionComparisonSummary provides a high-level summary of version differences
type VersionComparisonSummary struct {
	TotalChanges        int                    `json:"total_changes"`
	ChangesByType       map[string]int         `json:"changes_by_type"`
	ChangesByImpact     map[ChangeImpact]int   `json:"changes_by_impact"`
	HasBreakingChanges  bool                   `json:"has_breaking_changes"`
	BackwardCompatible  bool                   `json:"backward_compatible"`
	UpgradeComplexity   string                 `json:"upgrade_complexity"`
}

// VersionApprovalWorkflow manages the approval process for policy versions
type VersionApprovalWorkflow struct {
	VersionID       string                 `json:"version_id"`
	PolicyID        string                 `json:"policy_id"`
	Status          ApprovalStatus         `json:"status"`
	RequiredApprovers []ApprovalRole       `json:"required_approvers"`
	Approvals       []VersionApproval      `json:"approvals"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       time.Time              `json:"created_at"`
	CompletedAt     *time.Time             `json:"completed_at,omitempty"`
	Comments        []ApprovalComment      `json:"comments"`
}

// ApprovalStatus represents the status of version approval
type ApprovalStatus string

const (
	ApprovalStatusPending    ApprovalStatus = "pending"
	ApprovalStatusInReview   ApprovalStatus = "in_review"
	ApprovalStatusApproved   ApprovalStatus = "approved"
	ApprovalStatusRejected   ApprovalStatus = "rejected"
	ApprovalStatusWithdrawn  ApprovalStatus = "withdrawn"
)

// ApprovalRole represents different roles that can approve versions
type ApprovalRole string

const (
	ApprovalRoleSecurityOfficer ApprovalRole = "security_officer"
	ApprovalRoleComplianceOfficer ApprovalRole = "compliance_officer"
	ApprovalRolePolicyOwner     ApprovalRole = "policy_owner"
	ApprovalRoleAdmin           ApprovalRole = "admin"
	ApprovalRoleArchitect       ApprovalRole = "architect"
)

// VersionApproval represents an individual approval
type VersionApproval struct {
	ApproverRole    ApprovalRole  `json:"approver_role"`
	ApproverName    string        `json:"approver_name"`
	ApproverEmail   string        `json:"approver_email"`
	Status          ApprovalStatus `json:"status"`
	ApprovedAt      *time.Time    `json:"approved_at,omitempty"`
	Comment         string        `json:"comment,omitempty"`
	Conditions      []string      `json:"conditions,omitempty"`
}

// ApprovalComment represents comments in the approval workflow
type ApprovalComment struct {
	ID          string    `json:"id"`
	Author      string    `json:"author"`
	Role        ApprovalRole `json:"role"`
	Content     string    `json:"content"`
	Timestamp   time.Time `json:"timestamp"`
	CommentType string    `json:"comment_type"` // review, question, concern, suggestion
}

// VersionRollbackRequest represents a request to rollback to a previous version
type VersionRollbackRequest struct {
	PolicyID           string                 `json:"policy_id"`
	CurrentVersion     string                 `json:"current_version"`
	TargetVersion      string                 `json:"target_version"`
	RollbackReason     string                 `json:"rollback_reason"`
	RequestedBy        string                 `json:"requested_by"`
	RequestedAt        time.Time              `json:"requested_at"`
	
	// Rollback configuration
	ImmediateRollback  bool                   `json:"immediate_rollback"`
	ScheduledTime      *time.Time             `json:"scheduled_time,omitempty"`
	MaintenanceWindow  bool                   `json:"maintenance_window"`
	NotificationList   []string               `json:"notification_list"`
	
	// Safety checks
	RequireApproval    bool                   `json:"require_approval"`
	SkipValidation     bool                   `json:"skip_validation"`
	BackupCurrent      bool                   `json:"backup_current"`
	CanRollForward     bool                   `json:"can_roll_forward"`
	
	// Impact mitigation
	GracefulDegradation bool                  `json:"graceful_degradation"`
	FallbackStrategy    string                `json:"fallback_strategy"`
	MonitoringAlerts    []string              `json:"monitoring_alerts"`
}

// VersionRollbackResult contains the result of a rollback operation
type VersionRollbackResult struct {
	Success            bool                   `json:"success"`
	RollbackID         string                 `json:"rollback_id"`
	PolicyID           string                 `json:"policy_id"`
	FromVersion        string                 `json:"from_version"`
	ToVersion          string                 `json:"to_version"`
	ExecutedBy         string                 `json:"executed_by"`
	ExecutedAt         time.Time              `json:"executed_at"`
	
	// Execution details
	ExecutionTime      time.Duration          `json:"execution_time"`
	AffectedRequests   int64                  `json:"affected_requests"`
	DowntimeExperienced time.Duration         `json:"downtime_experienced"`
	
	// Result information
	Message            string                 `json:"message"`
	Warnings           []string               `json:"warnings"`
	Errors             []string               `json:"errors"`
	ValidationResults  []ValidationResult     `json:"validation_results"`
	
	// Post-rollback status
	PostRollbackChecks []RollbackCheck        `json:"post_rollback_checks"`
	MonitoringData     map[string]interface{} `json:"monitoring_data"`
	NextSteps          []string               `json:"next_steps"`
}

// ValidationResult represents the result of version validation
type ValidationResult struct {
	Component       string    `json:"component"`
	Status          string    `json:"status"`       // passed, failed, warning
	Message         string    `json:"message"`
	Details         string    `json:"details"`
	Timestamp       time.Time `json:"timestamp"`
	CriticalFailure bool      `json:"critical_failure"`
}

// RollbackCheck represents post-rollback validation checks
type RollbackCheck struct {
	CheckName       string                 `json:"check_name"`
	CheckType       string                 `json:"check_type"`
	Status          string                 `json:"status"`
	Expected        interface{}            `json:"expected"`
	Actual          interface{}            `json:"actual"`
	Passed          bool                   `json:"passed"`
	ExecutedAt      time.Time              `json:"executed_at"`
	Details         map[string]interface{} `json:"details"`
}

// VersionManagerInterface defines the interface for policy version management
type VersionManagerInterface interface {
	// Version creation and management
	CreateVersion(policyID string, policy *Policy, changeType PolicyChangeType, reason string) (*PolicyVersion, error)
	GetVersion(versionID string) (*PolicyVersion, error)
	GetVersionByNumber(policyID, versionNumber string) (*PolicyVersion, error)
	GetCurrentVersion(policyID string) (*PolicyVersion, error)
	ListVersions(policyID string) ([]*PolicyVersion, error)
	
	// Version comparison and analysis
	CompareVersions(version1ID, version2ID string) (*VersionComparisonResult, error)
	AnalyzeVersionImpact(versionID string) (*VersionImpactAnalysis, error)
	
	// Version activation and deployment
	ActivateVersion(versionID string, activatedBy string) error
	DeactivateVersion(versionID string, deactivatedBy string) error
	
	// Rollback operations
	RollbackToVersion(request *VersionRollbackRequest) (*VersionRollbackResult, error)
	GetRollbackOptions(policyID string) ([]PolicyVersion, error)
	ValidateRollback(policyID, targetVersion string) (*ValidationResult, error)
	
	// Approval workflow
	SubmitForApproval(versionID string, requiredApprovers []ApprovalRole) error
	ApproveVersion(versionID string, approval *VersionApproval) error
	RejectVersion(versionID string, rejection *VersionApproval) error
	
	// History and audit
	GetVersionHistory(policyID string) (*PolicyVersionHistory, error)
	GetVersionAuditTrail(versionID string) ([]AuditLogEntry, error)
	ExportVersionHistory(policyID string, format string) ([]byte, error)
	
	// Cleanup and maintenance
	ArchiveOldVersions(policyID string, keepCount int) error
	PurgeArchivedVersions(olderThan time.Duration) error
	ValidateVersionIntegrity(versionID string) error
}

// AuditLogEntry represents an entry in the version audit trail
type AuditLogEntry struct {
	ID          string                 `json:"id"`
	PolicyID    string                 `json:"policy_id"`
	VersionID   string                 `json:"version_id"`
	Action      string                 `json:"action"`
	Actor       string                 `json:"actor"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
}

// ===== ADVANCED CONDITION EVALUATION SYSTEM =====

// AdvancedConditionEvaluator handles complex condition evaluation with regex, ML, and expression support
type AdvancedConditionEvaluator struct {
	regexCache          map[string]*regexp.Regexp
	mlModelCache        map[string]MLModelInterface
	functionRegistry    map[string]BuiltinFunction
	expressionCache     map[string]*CompiledExpression
	evaluationContext   *EvaluationContext
	performanceMetrics  *ConditionMetrics
	config              *AdvancedEvaluatorConfig
	mu                  sync.RWMutex
}

// AdvancedEvaluatorConfig configures the advanced condition evaluator
type AdvancedEvaluatorConfig struct {
	EnableRegexCaching     bool          `json:"enable_regex_caching"`
	EnableMLModels         bool          `json:"enable_ml_models"`
	EnableExpressions      bool          `json:"enable_expressions"`
	RegexCacheSize         int           `json:"regex_cache_size"`
	ExpressionCacheSize    int           `json:"expression_cache_size"`
	ModelCacheSize         int           `json:"model_cache_size"`
	EvaluationTimeout      time.Duration `json:"evaluation_timeout"`
	MaxRegexComplexity     int           `json:"max_regex_complexity"`
	MaxExpressionDepth     int           `json:"max_expression_depth"`
	EnablePerformanceStats bool          `json:"enable_performance_stats"`
}

// EvaluationContext provides context for condition evaluation
type EvaluationContext struct {
	Request         *PolicyEvaluationRequest `json:"request"`
	Variables       map[string]interface{}   `json:"variables"`
	Functions       map[string]interface{}   `json:"functions"`
	TrustedSources  []string                 `json:"trusted_sources"`
	SecurityLevel   SecurityLevel            `json:"security_level"`
	Cache           ContextCache             `json:"cache"`
	PerformanceMode bool                     `json:"performance_mode"`
}

// SecurityLevel defines the security level for condition evaluation
type SecurityLevel string

const (
	SecurityLevelLow    SecurityLevel = "low"     // Basic validation
	SecurityLevelMedium SecurityLevel = "medium"  // Standard validation
	SecurityLevelHigh   SecurityLevel = "high"    // Strict validation
	SecurityLevelMax    SecurityLevel = "max"     // Maximum security
)

// ContextCache provides caching within evaluation context
type ContextCache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Clear()
}

// CompiledExpression represents a pre-compiled expression for performance
type CompiledExpression struct {
	Expression    string                 `json:"expression"`
	AST           *ExpressionAST         `json:"ast"`
	CompiledAt    time.Time              `json:"compiled_at"`
	Variables     []string               `json:"variables"`
	Functions     []string               `json:"functions"`
	Complexity    int                    `json:"complexity"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ExpressionAST represents the abstract syntax tree of an expression
type ExpressionAST struct {
	Type     ASTNodeType            `json:"type"`
	Value    interface{}            `json:"value"`
	Operator string                 `json:"operator,omitempty"`
	Children []*ExpressionAST       `json:"children,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ASTNodeType represents the type of AST node
type ASTNodeType string

const (
	ASTNodeLiteral    ASTNodeType = "literal"
	ASTNodeVariable   ASTNodeType = "variable"
	ASTNodeFunction   ASTNodeType = "function"
	ASTNodeBinary     ASTNodeType = "binary"
	ASTNodeUnary      ASTNodeType = "unary"
	ASTNodeCondition  ASTNodeType = "condition"
	ASTNodeArray      ASTNodeType = "array"
	ASTNodeObject     ASTNodeType = "object"
)

// BuiltinFunction represents a built-in function for conditions
type BuiltinFunction struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Category        FunctionCategory       `json:"category"`
	Parameters      []FunctionParameter    `json:"parameters"`
	ReturnType      string                 `json:"return_type"`
	Implementation  FunctionImplementation `json:"-"`
	SecurityLevel   SecurityLevel          `json:"security_level"`
	PerformanceHint string                 `json:"performance_hint"`
	Examples        []FunctionExample      `json:"examples"`
}

// FunctionCategory categorizes built-in functions
type FunctionCategory string

const (
	CategoryString     FunctionCategory = "string"      // String manipulation
	CategoryMath       FunctionCategory = "math"        // Mathematical operations
	CategoryDate       FunctionCategory = "date"        // Date/time operations
	CategoryArray      FunctionCategory = "array"       // Array operations
	CategoryRegex      FunctionCategory = "regex"       // Regular expressions
	CategoryML         FunctionCategory = "ml"          // Machine learning
	CategorySecurity   FunctionCategory = "security"    // Security operations
	CategoryAnalysis   FunctionCategory = "analysis"    // Content analysis
	CategoryValidation FunctionCategory = "validation"  // Data validation
	CategoryUtility    FunctionCategory = "utility"     // General utilities
)

// FunctionParameter defines a function parameter
type FunctionParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	DefaultValue interface{} `json:"default_value,omitempty"`
	Description  string      `json:"description"`
	Validation   string      `json:"validation,omitempty"`
}

// FunctionImplementation is the actual implementation of a function
type FunctionImplementation func(ctx *EvaluationContext, args []interface{}) (interface{}, error)

// FunctionExample provides usage examples for functions
type FunctionExample struct {
	Description string                 `json:"description"`
	Input       map[string]interface{} `json:"input"`
	Expression  string                 `json:"expression"`
	Expected    interface{}            `json:"expected"`
	Context     string                 `json:"context,omitempty"`
}

// MLModelInterface defines the interface for ML model integration
type MLModelInterface interface {
	Name() string
	Version() string
	Predict(input interface{}) (*MLModelResult, error)
	GetMetadata() *MLModelMetadata
	IsLoaded() bool
	Load() error
	Unload() error
}

// MLModelResult represents the result from an ML model
type MLModelResult struct {
	Prediction   interface{}            `json:"prediction"`
	Confidence   float64                `json:"confidence"`
	Probabilities map[string]float64    `json:"probabilities,omitempty"`
	Features     map[string]interface{} `json:"features,omitempty"`
	ModelName    string                 `json:"model_name"`
	ModelVersion string                 `json:"model_version"`
	ExecutionTime time.Duration         `json:"execution_time"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// MLModelMetadata provides metadata about an ML model
type MLModelMetadata struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Type            MLModelType            `json:"type"`
	Description     string                 `json:"description"`
	InputSchema     *MLModelSchema         `json:"input_schema"`
	OutputSchema    *MLModelSchema         `json:"output_schema"`
	TrainingData    string                 `json:"training_data"`
	Accuracy        float64                `json:"accuracy"`
	LastTrained     time.Time              `json:"last_trained"`
	SupportedTasks  []string               `json:"supported_tasks"`
	Requirements    []string               `json:"requirements"`
	PerformanceHints map[string]interface{} `json:"performance_hints"`
}

// MLModelType represents the type of ML model
type MLModelType string

const (
	ModelTypeClassification MLModelType = "classification"
	ModelTypeRegression     MLModelType = "regression"
	ModelTypeClustering     MLModelType = "clustering"
	ModelTypeNLP            MLModelType = "nlp"
	ModelTypeAnomalyDetection MLModelType = "anomaly_detection"
	ModelTypeRecommendation MLModelType = "recommendation"
	ModelTypeTimeSeries     MLModelType = "time_series"
	ModelTypeCustom         MLModelType = "custom"
)

// MLModelSchema defines the schema for model input/output
type MLModelSchema struct {
	Type        string                 `json:"type"`
	Properties  map[string]*SchemaProperty `json:"properties"`
	Required    []string               `json:"required"`
	Description string                 `json:"description"`
	Examples    []interface{}          `json:"examples,omitempty"`
}

// SchemaProperty defines a property in an ML model schema
type SchemaProperty struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Format      string      `json:"format,omitempty"`
	Minimum     *float64    `json:"minimum,omitempty"`
	Maximum     *float64    `json:"maximum,omitempty"`
	MinLength   *int        `json:"min_length,omitempty"`
	MaxLength   *int        `json:"max_length,omitempty"`
	Pattern     string      `json:"pattern,omitempty"`
	Enum        []interface{} `json:"enum,omitempty"`
}

// ConditionMetrics tracks performance metrics for condition evaluation
type ConditionMetrics struct {
	TotalEvaluations    int64                   `json:"total_evaluations"`
	SuccessfulEvaluations int64                 `json:"successful_evaluations"`
	FailedEvaluations   int64                   `json:"failed_evaluations"`
	AverageLatency      time.Duration           `json:"average_latency"`
	MaxLatency          time.Duration           `json:"max_latency"`
	MinLatency          time.Duration           `json:"min_latency"`
	
	// Category-specific metrics
	RegexEvaluations    int64                   `json:"regex_evaluations"`
	MLEvaluations       int64                   `json:"ml_evaluations"`
	ExpressionEvaluations int64                 `json:"expression_evaluations"`
	FunctionCalls       map[string]int64        `json:"function_calls"`
	
	// Cache metrics
	CacheHits           int64                   `json:"cache_hits"`
	CacheMisses         int64                   `json:"cache_misses"`
	CacheHitRatio       float64                 `json:"cache_hit_ratio"`
	
	// Error metrics
	ErrorsByType        map[string]int64        `json:"errors_by_type"`
	TimeoutCount        int64                   `json:"timeout_count"`
	SecurityViolations  int64                   `json:"security_violations"`
	
	// Performance tracking
	LastUpdated         time.Time               `json:"last_updated"`
	PerformanceHistory  []PerformanceSnapshot   `json:"performance_history"`
}

// PerformanceSnapshot captures performance metrics at a point in time
type PerformanceSnapshot struct {
	Timestamp       time.Time     `json:"timestamp"`
	Evaluations     int64         `json:"evaluations"`
	AverageLatency  time.Duration `json:"average_latency"`
	ErrorRate       float64       `json:"error_rate"`
	ThroughputRPS   float64       `json:"throughput_rps"`
	MemoryUsage     int64         `json:"memory_usage"`
}

// AdvancedConditionType extends basic condition types with advanced features
type AdvancedConditionType string

const (
	// Regex-based conditions
	ConditionRegexMatch       AdvancedConditionType = "regex_match"
	ConditionRegexFind        AdvancedConditionType = "regex_find"
	ConditionRegexReplace     AdvancedConditionType = "regex_replace"
	ConditionRegexSplit       AdvancedConditionType = "regex_split"
	ConditionRegexExtract     AdvancedConditionType = "regex_extract"
	
	// ML-based conditions
	ConditionMLClassify       AdvancedConditionType = "ml_classify"
	ConditionMLScore          AdvancedConditionType = "ml_score"
	ConditionMLAnomaly        AdvancedConditionType = "ml_anomaly"
	ConditionMLSentiment      AdvancedConditionType = "ml_sentiment"
	ConditionMLTopic          AdvancedConditionType = "ml_topic"
	ConditionMLEntity         AdvancedConditionType = "ml_entity"
	ConditionMLSimilarity     AdvancedConditionType = "ml_similarity"
	
	// Expression-based conditions
	ConditionExpression       AdvancedConditionType = "expression"
	ConditionFormula          AdvancedConditionType = "formula"
	ConditionScript           AdvancedConditionType = "script"
	ConditionTemplate         AdvancedConditionType = "template"
	
	// Function-based conditions
	ConditionFunction         AdvancedConditionType = "function"
	ConditionBuiltinFunction  AdvancedConditionType = "builtin_function"
	ConditionCustomFunction   AdvancedConditionType = "custom_function"
	
	// Advanced string operations
	ConditionStringLength     AdvancedConditionType = "string_length"
	ConditionStringWords      AdvancedConditionType = "string_words"
	ConditionStringLines      AdvancedConditionType = "string_lines"
	ConditionStringEncoding   AdvancedConditionType = "string_encoding"
	ConditionStringLanguage   AdvancedConditionType = "string_language"
	ConditionStringComplexity AdvancedConditionType = "string_complexity"
	
	// Advanced numeric operations
	ConditionMathExpression   AdvancedConditionType = "math_expression"
	ConditionStatistical      AdvancedConditionType = "statistical"
	ConditionPercentile       AdvancedConditionType = "percentile"
	ConditionMovingAverage    AdvancedConditionType = "moving_average"
	ConditionOutlierDetection AdvancedConditionType = "outlier_detection"
	
	// Time-based conditions
	ConditionTimeWindow       AdvancedConditionType = "time_window"
	ConditionTimeRecurring    AdvancedConditionType = "time_recurring"
	ConditionTimeRate         AdvancedConditionType = "time_rate"
	ConditionTimeSeries       AdvancedConditionType = "time_series"
	
	// Geo-based conditions
	ConditionGeoLocation      AdvancedConditionType = "geo_location"
	ConditionGeoDistance      AdvancedConditionType = "geo_distance"
	ConditionGeoRegion        AdvancedConditionType = "geo_region"
	
	// Network-based conditions
	ConditionIPAddress        AdvancedConditionType = "ip_address"
	ConditionDomainName       AdvancedConditionType = "domain_name"
	ConditionURLPattern       AdvancedConditionType = "url_pattern"
	
	// Data validation conditions
	ConditionDataFormat       AdvancedConditionType = "data_format"
	ConditionDataSchema       AdvancedConditionType = "data_schema"
	ConditionDataIntegrity    AdvancedConditionType = "data_integrity"
	ConditionDataQuality      AdvancedConditionType = "data_quality"
)

// AdvancedConditionConfig provides configuration for advanced conditions
type AdvancedConditionConfig struct {
	Type              AdvancedConditionType  `json:"type"`
	Expression        string                 `json:"expression,omitempty"`
	RegexPattern      string                 `json:"regex_pattern,omitempty"`
	RegexFlags        []string               `json:"regex_flags,omitempty"`
	MLModelName       string                 `json:"ml_model_name,omitempty"`
	MLModelVersion    string                 `json:"ml_model_version,omitempty"`
	FunctionName      string                 `json:"function_name,omitempty"`
	FunctionArgs      map[string]interface{} `json:"function_args,omitempty"`
	CacheEnabled      bool                   `json:"cache_enabled"`
	CacheTTL          time.Duration          `json:"cache_ttl"`
	Timeout           time.Duration          `json:"timeout"`
	SecurityLevel     SecurityLevel          `json:"security_level"`
	PerformanceMode   bool                   `json:"performance_mode"`
}

// ConditionEvaluationResult represents the result of evaluating an advanced condition
type ConditionEvaluationResult struct {
	Matched         bool                   `json:"matched"`
	Confidence      float64                `json:"confidence"`
	Value           interface{}            `json:"value"`
	Details         string                 `json:"details"`
	ExecutionTime   time.Duration          `json:"execution_time"`
	CacheHit        bool                   `json:"cache_hit"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	IntermediateResults map[string]interface{} `json:"intermediate_results,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// RegexConditionConfig configures regex-based conditions
type RegexConditionConfig struct {
	Pattern       string   `json:"pattern"`
	Flags         []string `json:"flags"`         // i, m, s, x, etc.
	CaseSensitive bool     `json:"case_sensitive"`
	Multiline     bool     `json:"multiline"`
	DotAll        bool     `json:"dot_all"`
	Unicode       bool     `json:"unicode"`
	Compiled      bool     `json:"compiled"`      // Whether to pre-compile
	MaxMatches    int      `json:"max_matches"`   // Limit number of matches
	Timeout       time.Duration `json:"timeout"`
}

// MLConditionConfig configures ML-based conditions
type MLConditionConfig struct {
	ModelName     string                 `json:"model_name"`
	ModelVersion  string                 `json:"model_version,omitempty"`
	Task          string                 `json:"task"`           // classify, score, detect, etc.
	Threshold     float64                `json:"threshold"`
	InputMapping  map[string]string      `json:"input_mapping"`  // Map request fields to model inputs
	OutputMapping map[string]string      `json:"output_mapping"` // Map model outputs to condition results
	Preprocessing []string               `json:"preprocessing"`  // Preprocessing steps
	Postprocessing []string              `json:"postprocessing"` // Postprocessing steps
	CacheEnabled  bool                   `json:"cache_enabled"`
	CacheTTL      time.Duration          `json:"cache_ttl"`
	Timeout       time.Duration          `json:"timeout"`
}

// ExpressionConditionConfig configures expression-based conditions
type ExpressionConditionConfig struct {
	Expression     string                 `json:"expression"`
	Language       ExpressionLanguage     `json:"language"`       // javascript, go, python, etc.
	Variables      map[string]interface{} `json:"variables"`
	Functions      []string               `json:"functions"`      // Available functions
	MaxDepth       int                    `json:"max_depth"`      // Max recursion depth
	MaxExecutions  int                    `json:"max_executions"` // Max operations
	SandboxEnabled bool                   `json:"sandbox_enabled"`
	Timeout        time.Duration          `json:"timeout"`
	CompileOnce    bool                   `json:"compile_once"`   // Pre-compile for performance
}

// ExpressionLanguage defines supported expression languages
type ExpressionLanguage string

const (
	ExpressionLanguageJavaScript ExpressionLanguage = "javascript"
	ExpressionLanguageGo         ExpressionLanguage = "go"
	ExpressionLanguagePython     ExpressionLanguage = "python"
	ExpressionLanguageSQL        ExpressionLanguage = "sql"
	ExpressionLanguageJSONPath   ExpressionLanguage = "jsonpath"
	ExpressionLanguageXPath      ExpressionLanguage = "xpath"
	ExpressionLanguageMath       ExpressionLanguage = "math"
	ExpressionLanguageTemplate   ExpressionLanguage = "template"
)

// ===== MULTI-TENANT POLICY ISOLATION SYSTEM =====

// Tenant represents a multi-tenant entity with complete isolation
type Tenant struct {
	ID                  string                 `json:"id"`                    // Unique tenant identifier
	Name                string                 `json:"name"`                  // Human-readable tenant name
	DisplayName         string                 `json:"display_name"`          // UI display name
	Description         string                 `json:"description,omitempty"`
	
	// Tenant classification
	Type                TenantType             `json:"type"`                  // enterprise, standard, trial, etc.
	Status              TenantStatus           `json:"status"`                // active, suspended, etc.
	Plan                TenantPlan             `json:"plan"`                  // subscription plan
	Tier                TenantTier             `json:"tier"`                  // performance tier
	
	// Contact and organization info
	Organization        string                 `json:"organization"`
	ContactEmail        string                 `json:"contact_email"`
	ContactName         string                 `json:"contact_name,omitempty"`
	Domain              string                 `json:"domain,omitempty"`      // tenant domain
	
	// Tenant configuration
	Configuration       *TenantConfiguration   `json:"configuration"`
	ResourceLimits      *TenantResourceLimits  `json:"resource_limits"`
	SecuritySettings    *TenantSecuritySettings `json:"security_settings"`
	FeatureFlags        map[string]bool        `json:"feature_flags"`
	
	// Isolation settings
	Namespace           string                 `json:"namespace"`             // unique namespace
	IsolationLevel      IsolationLevel         `json:"isolation_level"`       // strict, standard, etc.
	DataRegion          string                 `json:"data_region,omitempty"` // data residency
	
	// Administrative info
	CreatedBy           string                 `json:"created_by"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	LastAccessAt        *time.Time             `json:"last_access_at,omitempty"`
	
	// Billing and usage
	BillingInfo         *TenantBillingInfo     `json:"billing_info,omitempty"`
	UsageMetrics        *TenantUsageMetrics    `json:"usage_metrics,omitempty"`
	
	// Metadata and tags
	Tags                []string               `json:"tags,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
	CustomFields        map[string]interface{} `json:"custom_fields,omitempty"`
}

// TenantType represents the type of tenant
type TenantType string

const (
	TenantTypeEnterprise TenantType = "enterprise"  // Large enterprise customer
	TenantTypeStandard   TenantType = "standard"    // Standard business customer
	TenantTypeStartup    TenantType = "startup"     // Startup/small business
	TenantTypeTrial      TenantType = "trial"       // Trial customer
	TenantTypeInternal   TenantType = "internal"    // Internal/testing tenant
	TenantTypePartner    TenantType = "partner"     // Partner tenant
	TenantTypeDeveloper  TenantType = "developer"   // Developer/sandbox tenant
)

// TenantStatus represents the current status of a tenant
type TenantStatus string

const (
	TenantStatusActive     TenantStatus = "active"       // Fully operational
	TenantStatusSuspended  TenantStatus = "suspended"    // Temporarily suspended
	TenantStatusInactive   TenantStatus = "inactive"     // Inactive but not deleted
	TenantStatusPending    TenantStatus = "pending"      // Pending activation
	TenantStatusTrialExpired TenantStatus = "trial_expired" // Trial period expired
	TenantStatusTerminated TenantStatus = "terminated"   // Terminated/deleted
	TenantStatusMaintenance TenantStatus = "maintenance" // Under maintenance
)

// TenantPlan represents the subscription plan
type TenantPlan string

const (
	TenantPlanFree       TenantPlan = "free"
	TenantPlanBasic      TenantPlan = "basic"
	TenantPlanProfessional TenantPlan = "professional"
	TenantPlanEnterprise TenantPlan = "enterprise"
	TenantPlanCustom     TenantPlan = "custom"
)

// TenantTier represents the performance tier
type TenantTier string

const (
	TenantTierShared     TenantTier = "shared"      // Shared infrastructure
	TenantTierDedicated  TenantTier = "dedicated"   // Dedicated resources
	TenantTierIsolated   TenantTier = "isolated"    // Complete isolation
	TenantTierPremium    TenantTier = "premium"     // Premium performance
)

// IsolationLevel represents the level of tenant isolation
type IsolationLevel string

const (
	IsolationLevelStrict   IsolationLevel = "strict"    // Complete isolation
	IsolationLevelStandard IsolationLevel = "standard"  // Standard isolation
	IsolationLevelBasic    IsolationLevel = "basic"     // Basic isolation
	IsolationLevelShared   IsolationLevel = "shared"    // Shared resources
)

// TenantConfiguration contains tenant-specific configuration
type TenantConfiguration struct {
	// Policy engine configuration
	PolicyEngineConfig     *TenantPolicyConfig    `json:"policy_engine_config"`
	
	// Cache configuration
	CacheConfig            *TenantCacheConfig     `json:"cache_config"`
	
	// Logging configuration
	LoggingConfig          *TenantLoggingConfig   `json:"logging_config"`
	
	// Metrics and monitoring
	MetricsConfig          *TenantMetricsConfig   `json:"metrics_config"`
	
	// Integration settings
	IntegrationConfig      *TenantIntegrationConfig `json:"integration_config"`
	
	// UI/UX customization
	UICustomization        *TenantUIConfig        `json:"ui_customization"`
	
	// API configuration
	APIConfig              *TenantAPIConfig       `json:"api_config"`
	
	// Notification settings
	NotificationConfig     *TenantNotificationConfig `json:"notification_config"`
}

// TenantPolicyConfig contains policy-related configuration for tenant
type TenantPolicyConfig struct {
	MaxPolicies            int                    `json:"max_policies"`
	MaxRulesPerPolicy      int                    `json:"max_rules_per_policy"`
	MaxConditionDepth      int                    `json:"max_condition_depth"`
	EnableAdvancedConditions bool                 `json:"enable_advanced_conditions"`
	EnableMLIntegration    bool                   `json:"enable_ml_integration"`
	EnableCustomFunctions  bool                   `json:"enable_custom_functions"`
	AllowRegexConditions   bool                   `json:"allow_regex_conditions"`
	PolicyVersionLimit     int                    `json:"policy_version_limit"`
	DefaultCacheTTL        time.Duration          `json:"default_cache_ttl"`
	EvaluationTimeout      time.Duration          `json:"evaluation_timeout"`
	ConflictResolutionStrategy string             `json:"conflict_resolution_strategy"`
}

// TenantCacheConfig contains cache configuration for tenant
type TenantCacheConfig struct {
	Enabled                bool                   `json:"enabled"`
	Provider               string                 `json:"provider"`         // redis, memory, etc.
	MaxSize                int64                  `json:"max_size"`         // bytes
	MaxEntries             int                    `json:"max_entries"`
	DefaultTTL             time.Duration          `json:"default_ttl"`
	PolicyCacheTTL         time.Duration          `json:"policy_cache_ttl"`
	ResultCacheTTL         time.Duration          `json:"result_cache_ttl"`
	EvictionPolicy         string                 `json:"eviction_policy"`  // lru, lfu, ttl
	IsolationEnabled       bool                   `json:"isolation_enabled"`
}

// TenantResourceLimits defines resource limits for a tenant
type TenantResourceLimits struct {
	// Request limits
	MaxRequestsPerSecond   int                    `json:"max_requests_per_second"`
	MaxRequestsPerMinute   int                    `json:"max_requests_per_minute"`
	MaxRequestsPerHour     int                    `json:"max_requests_per_hour"`
	MaxRequestsPerDay      int                    `json:"max_requests_per_day"`
	
	// Content limits
	MaxContentSize         int64                  `json:"max_content_size"`     // bytes
	MaxBatchSize           int                    `json:"max_batch_size"`       // items per batch
	
	// Policy limits
	MaxPolicies            int                    `json:"max_policies"`
	MaxActiveRules         int                    `json:"max_active_rules"`
	MaxConcurrentEvaluations int                  `json:"max_concurrent_evaluations"`
	
	// Resource limits
	MaxMemoryUsage         int64                  `json:"max_memory_usage"`     // bytes
	MaxStorageUsage        int64                  `json:"max_storage_usage"`    // bytes
	MaxCPUUsage            float64                `json:"max_cpu_usage"`        // percentage
	
	// Time limits
	MaxEvaluationTime      time.Duration          `json:"max_evaluation_time"`
	MaxProcessingTime      time.Duration          `json:"max_processing_time"`
	
	// Feature limits
	MaxWebhooks            int                    `json:"max_webhooks"`
	MaxIntegrations        int                    `json:"max_integrations"`
	MaxUsers               int                    `json:"max_users"`
	MaxAdmins              int                    `json:"max_admins"`
}

// TenantSecuritySettings contains security settings for tenant
type TenantSecuritySettings struct {
	// Authentication settings
	RequireAuth            bool                   `json:"require_auth"`
	AllowedAuthMethods     []string               `json:"allowed_auth_methods"`
	PasswordPolicy         *PasswordPolicy        `json:"password_policy"`
	MFARequired            bool                   `json:"mfa_required"`
	SessionTimeout         time.Duration          `json:"session_timeout"`
	
	// Authorization settings
	RBAC                   *RBACSettings          `json:"rbac"`
	DefaultRole            string                 `json:"default_role"`
	AdminApprovalRequired  bool                   `json:"admin_approval_required"`
	
	// Network security
	AllowedIPs             []string               `json:"allowed_ips"`
	BlockedIPs             []string               `json:"blocked_ips"`
	RequireHTTPS           bool                   `json:"require_https"`
	AllowedDomains         []string               `json:"allowed_domains"`
	
	// Data security
	EncryptionRequired     bool                   `json:"encryption_required"`
	EncryptionMethod       string                 `json:"encryption_method"`
	DataRetentionDays      int                    `json:"data_retention_days"`
	PIIRedactionEnabled    bool                   `json:"pii_redaction_enabled"`
	
	// Audit and compliance
	AuditLoggingEnabled    bool                   `json:"audit_logging_enabled"`
	ComplianceMode         string                 `json:"compliance_mode"`     // GDPR, HIPAA, SOX, etc.
	RequireDataAgreement   bool                   `json:"require_data_agreement"`
}

// TenantUsageMetrics contains usage statistics for a tenant
type TenantUsageMetrics struct {
	// Request metrics
	TotalRequests          int64                  `json:"total_requests"`
	RequestsThisMonth      int64                  `json:"requests_this_month"`
	RequestsToday          int64                  `json:"requests_today"`
	SuccessfulRequests     int64                  `json:"successful_requests"`
	FailedRequests         int64                  `json:"failed_requests"`
	
	// Performance metrics
	AverageLatency         time.Duration          `json:"average_latency"`
	P95Latency             time.Duration          `json:"p95_latency"`
	P99Latency             time.Duration          `json:"p99_latency"`
	
	// Resource usage
	StorageUsed            int64                  `json:"storage_used"`         // bytes
	BandwidthUsed          int64                  `json:"bandwidth_used"`       // bytes
	ComputeTimeUsed        time.Duration          `json:"compute_time_used"`
	
	// Policy metrics
	ActivePolicies         int                    `json:"active_policies"`
	PolicyEvaluations      int64                  `json:"policy_evaluations"`
	PolicyMatches          int64                  `json:"policy_matches"`
	ConflictResolutions    int64                  `json:"conflict_resolutions"`
	
	// Feature usage
	MLModelCalls           int64                  `json:"ml_model_calls"`
	WebhookCalls           int64                  `json:"webhook_calls"`
	CacheHits              int64                  `json:"cache_hits"`
	CacheMisses            int64                  `json:"cache_misses"`
	
	// Time tracking
	FirstRequest           *time.Time             `json:"first_request,omitempty"`
	LastRequest            *time.Time             `json:"last_request,omitempty"`
	LastUpdated            time.Time              `json:"last_updated"`
}

// TenantBillingInfo contains billing information for a tenant
type TenantBillingInfo struct {
	BillingID              string                 `json:"billing_id"`
	PaymentMethod          string                 `json:"payment_method"`
	BillingAddress         *Address               `json:"billing_address"`
	Currency               string                 `json:"currency"`
	BillingCycle           BillingCycle           `json:"billing_cycle"`
	NextBillingDate        *time.Time             `json:"next_billing_date"`
	TotalSpent             float64                `json:"total_spent"`
	CurrentMonthSpend      float64                `json:"current_month_spend"`
	CreditBalance          float64                `json:"credit_balance"`
	AutoRenewal            bool                   `json:"auto_renewal"`
}

// Address represents a billing address
type Address struct {
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

// BillingCycle represents billing frequency
type BillingCycle string

const (
	BillingCycleMonthly  BillingCycle = "monthly"
	BillingCycleYearly   BillingCycle = "yearly"
	BillingCycleQuarterly BillingCycle = "quarterly"
)

// TenantLoggingConfig contains logging configuration
type TenantLoggingConfig struct {
	Level                  string                 `json:"level"`               // debug, info, warn, error
	Format                 string                 `json:"format"`              // json, text
	Destination            string                 `json:"destination"`         // file, syslog, external
	RetentionDays          int                    `json:"retention_days"`
	MaxLogSize             int64                  `json:"max_log_size"`        // bytes
	EnableStructuredLogs   bool                   `json:"enable_structured_logs"`
	EnablePerformanceLogs  bool                   `json:"enable_performance_logs"`
	EnableSecurityLogs     bool                   `json:"enable_security_logs"`
	ExternalConfig         map[string]interface{} `json:"external_config,omitempty"`
}

// TenantMetricsConfig contains metrics configuration
type TenantMetricsConfig struct {
	Enabled                bool                   `json:"enabled"`
	Provider               string                 `json:"provider"`            // prometheus, datadog, etc.
	RetentionPeriod        time.Duration          `json:"retention_period"`
	SamplingRate           float64                `json:"sampling_rate"`
	EnableCustomMetrics    bool                   `json:"enable_custom_metrics"`
	MetricsPrefix          string                 `json:"metrics_prefix"`
	Tags                   map[string]string      `json:"tags"`
	ExportInterval         time.Duration          `json:"export_interval"`
	ExternalConfig         map[string]interface{} `json:"external_config,omitempty"`
}

// TenantIntegrationConfig contains integration settings
type TenantIntegrationConfig struct {
	Webhooks               *WebhookSettings       `json:"webhooks"`
	ExternalAPIs           map[string]*APIIntegration `json:"external_apis"`
	NotificationChannels   map[string]*TenantNotificationChannel `json:"notification_channels"`
	DataExports            *DataExportSettings    `json:"data_exports"`
	SSOConfig              *SSOSettings           `json:"sso_config"`
}

// WebhookSettings contains webhook configuration
type WebhookSettings struct {
	Enabled                bool                   `json:"enabled"`
	MaxWebhooks            int                    `json:"max_webhooks"`
	DefaultTimeout         time.Duration          `json:"default_timeout"`
	MaxRetries             int                    `json:"max_retries"`
	RequireSSL             bool                   `json:"require_ssl"`
	AllowedEvents          []string               `json:"allowed_events"`
	RateLimitPerMinute     int                    `json:"rate_limit_per_minute"`
}

// APIIntegration represents an external API integration
type APIIntegration struct {
	Name                   string                 `json:"name"`
	Enabled                bool                   `json:"enabled"`
	BaseURL                string                 `json:"base_url"`
	AuthMethod             string                 `json:"auth_method"`
	Credentials            map[string]interface{} `json:"credentials"`
	RateLimit              int                    `json:"rate_limit"`
	Timeout                time.Duration          `json:"timeout"`
	RetryPolicy            *RetryPolicy           `json:"retry_policy"`
}

// TenantNotificationChannel represents a tenant notification channel
type TenantNotificationChannel struct {
	Type                   string                 `json:"type"`               // email, slack, teams, etc.
	Enabled                bool                   `json:"enabled"`
	Configuration          map[string]interface{} `json:"configuration"`
	Events                 []string               `json:"events"`             // Which events to notify
	Recipients             []string               `json:"recipients"`
}

// DataExportSettings contains data export configuration
type DataExportSettings struct {
	Enabled                bool                   `json:"enabled"`
	AllowedFormats         []string               `json:"allowed_formats"`    // json, csv, parquet, etc.
	MaxExportSize          int64                  `json:"max_export_size"`    // bytes
	RetentionDays          int                    `json:"retention_days"`
	ScheduledExports       []ScheduledExport      `json:"scheduled_exports"`
}

// ScheduledExport represents a scheduled data export
type ScheduledExport struct {
	Name                   string                 `json:"name"`
	Format                 string                 `json:"format"`
	Schedule               string                 `json:"schedule"`           // cron expression
	Destination            string                 `json:"destination"`
	Filters                map[string]interface{} `json:"filters"`
	Enabled                bool                   `json:"enabled"`
}

// SSOSettings contains Single Sign-On configuration
type SSOSettings struct {
	Enabled                bool                   `json:"enabled"`
	Provider               string                 `json:"provider"`           // SAML, OIDC, etc.
	ProviderConfig         map[string]interface{} `json:"provider_config"`
	AttributeMapping       map[string]string      `json:"attribute_mapping"`  // Map SSO attributes to tenant fields
	RequireSSO             bool                   `json:"require_sso"`
	AllowLocalAuth         bool                   `json:"allow_local_auth"`
	AutoProvisionUsers     bool                   `json:"auto_provision_users"`
}

// TenantUIConfig contains UI customization settings
type TenantUIConfig struct {
	BrandingEnabled        bool                   `json:"branding_enabled"`
	LogoURL                string                 `json:"logo_url,omitempty"`
	FaviconURL             string                 `json:"favicon_url,omitempty"`
	PrimaryColor           string                 `json:"primary_color,omitempty"`
	SecondaryColor         string                 `json:"secondary_color,omitempty"`
	CustomCSS              string                 `json:"custom_css,omitempty"`
	HideDefaultBranding    bool                   `json:"hide_default_branding"`
	CustomDashboard        *CustomDashboardConfig `json:"custom_dashboard,omitempty"`
	WhiteLabeling          bool                   `json:"white_labeling"`
}

// CustomDashboardConfig contains custom dashboard settings
type CustomDashboardConfig struct {
	Enabled                bool                   `json:"enabled"`
	Layout                 string                 `json:"layout"`
	Widgets                []DashboardWidget      `json:"widgets"`
	DefaultView            string                 `json:"default_view"`
	AllowCustomization     bool                   `json:"allow_customization"`
}

// DashboardWidget represents a dashboard widget
type DashboardWidget struct {
	ID                     string                 `json:"id"`
	Type                   string                 `json:"type"`
	Title                  string                 `json:"title"`
	Position               WidgetPosition         `json:"position"`
	Size                   WidgetSize             `json:"size"`
	Configuration          map[string]interface{} `json:"configuration"`
	DataSource             string                 `json:"data_source"`
	RefreshInterval        time.Duration          `json:"refresh_interval"`
}

// WidgetPosition represents widget position
type WidgetPosition struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// WidgetSize represents widget size
type WidgetSize struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// TenantAPIConfig contains API configuration
type TenantAPIConfig struct {
	RateLimit              *APIRateLimit          `json:"rate_limit"`
	AllowedVersions        []string               `json:"allowed_versions"`
	RequireAPIKey          bool                   `json:"require_api_key"`
	AllowedOrigins         []string               `json:"allowed_origins"`
	EnableCORS             bool                   `json:"enable_cors"`
	MaxRequestSize         int64                  `json:"max_request_size"`    // bytes
	DefaultTimeout         time.Duration          `json:"default_timeout"`
	EnableBatching         bool                   `json:"enable_batching"`
	MaxBatchSize           int                    `json:"max_batch_size"`
}

// APIRateLimit contains API rate limiting configuration
type APIRateLimit struct {
	RequestsPerSecond      int                    `json:"requests_per_second"`
	RequestsPerMinute      int                    `json:"requests_per_minute"`
	RequestsPerHour        int                    `json:"requests_per_hour"`
	BurstSize              int                    `json:"burst_size"`
	EnableAdaptive         bool                   `json:"enable_adaptive"`
	BackoffStrategy        string                 `json:"backoff_strategy"`
}

// TenantNotificationConfig contains notification settings
type TenantNotificationConfig struct {
	Enabled                bool                   `json:"enabled"`
	DefaultChannel         string                 `json:"default_channel"`
	Channels               map[string]*TenantNotificationChannel `json:"channels"`
	EventSubscriptions     map[string][]string    `json:"event_subscriptions"`  // event -> channels
	QuietHours             *QuietHours            `json:"quiet_hours,omitempty"`
	AlertThresholds        map[string]float64     `json:"alert_thresholds"`
}

// QuietHours represents notification quiet hours
type QuietHours struct {
	Enabled                bool                   `json:"enabled"`
	StartTime              string                 `json:"start_time"`          // HH:MM
	EndTime                string                 `json:"end_time"`            // HH:MM
	Timezone               string                 `json:"timezone"`
	DaysOfWeek             []string               `json:"days_of_week"`
}

// RetryPolicy represents a retry policy
type RetryPolicy struct {
	MaxRetries             int                    `json:"max_retries"`
	InitialDelay           time.Duration          `json:"initial_delay"`
	MaxDelay               time.Duration          `json:"max_delay"`
	BackoffMultiplier      float64                `json:"backoff_multiplier"`
	RetryableStatuses      []int                  `json:"retryable_statuses"`
}

// PasswordPolicy represents password requirements
type PasswordPolicy struct {
	MinLength              int                    `json:"min_length"`
	RequireUppercase       bool                   `json:"require_uppercase"`
	RequireLowercase       bool                   `json:"require_lowercase"`
	RequireNumbers         bool                   `json:"require_numbers"`
	RequireSymbols         bool                   `json:"require_symbols"`
	MaxAge                 time.Duration          `json:"max_age"`
	PreventReuse           int                    `json:"prevent_reuse"`      // Number of previous passwords to check
}

// RBACSettings represents Role-Based Access Control settings
type RBACSettings struct {
	Enabled                bool                   `json:"enabled"`
	Roles                  []TenantRole           `json:"roles"`
	Permissions            []TenantPermission     `json:"permissions"`
	RoleAssignments        map[string][]string    `json:"role_assignments"`   // user -> roles
	InheritanceEnabled     bool                   `json:"inheritance_enabled"`
}

// TenantRole represents a role within a tenant
type TenantRole struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Description            string                 `json:"description"`
	Permissions            []string               `json:"permissions"`        // Permission IDs
	IsDefault              bool                   `json:"is_default"`
	IsSystemRole           bool                   `json:"is_system_role"`
	ParentRole             string                 `json:"parent_role,omitempty"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
}

// TenantPermission represents a permission within a tenant
type TenantPermission struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Description            string                 `json:"description"`
	Resource               string                 `json:"resource"`           // policies, settings, users, etc.
	Action                 string                 `json:"action"`             // read, write, delete, execute
	Scope                  string                 `json:"scope"`              // tenant, global, resource-specific
	Conditions             map[string]interface{} `json:"conditions,omitempty"`
}

// ===== TENANT MANAGEMENT INTERFACES =====

// TenantManagerInterface defines the interface for tenant management
type TenantManagerInterface interface {
	// Tenant lifecycle management
	CreateTenant(request *CreateTenantRequest) (*Tenant, error)
	GetTenant(tenantID string) (*Tenant, error)
	GetTenantByName(name string) (*Tenant, error)
	GetTenantByDomain(domain string) (*Tenant, error)
	UpdateTenant(tenantID string, updates *TenantUpdateRequest) (*Tenant, error)
	DeleteTenant(tenantID string) error
	ListTenants(filters *TenantListFilters) ([]*Tenant, error)
	
	// Tenant status management
	ActivateTenant(tenantID string, activatedBy string) error
	SuspendTenant(tenantID string, reason string, suspendedBy string) error
	ReactivateTenant(tenantID string, reactivatedBy string) error
	TerminateTenant(tenantID string, reason string, terminatedBy string) error
	
	// Tenant configuration
	UpdateTenantConfiguration(tenantID string, config *TenantConfiguration) error
	GetTenantConfiguration(tenantID string) (*TenantConfiguration, error)
	ResetTenantConfiguration(tenantID string) error
	
	// Resource management
	UpdateResourceLimits(tenantID string, limits *TenantResourceLimits) error
	GetResourceUsage(tenantID string) (*TenantUsageMetrics, error)
	CheckResourceQuota(tenantID string, resource string, amount int64) (bool, error)
	
	// Security and access control
	UpdateSecuritySettings(tenantID string, settings *TenantSecuritySettings) error
	ValidateTenantAccess(tenantID string, userID string, action string) (bool, error)
	GetTenantUsers(tenantID string) ([]TenantUser, error)
	AddTenantUser(tenantID string, user *TenantUser) error
	RemoveTenantUser(tenantID string, userID string) error
	
	// Namespace and isolation
	GetTenantNamespace(tenantID string) (string, error)
	EnsureNamespaceIsolation(tenantID string) error
	ValidateNamespaceAccess(tenantID string, namespace string) (bool, error)
	
	// Billing and usage
	GetBillingInfo(tenantID string) (*TenantBillingInfo, error)
	UpdateBillingInfo(tenantID string, billing *TenantBillingInfo) error
	RecordUsage(tenantID string, usage *UsageRecord) error
	GetUsageReport(tenantID string, period *ReportPeriod) (*UsageReport, error)
	
	// Audit and compliance
	GetTenantAuditLog(tenantID string, filters *AuditLogFilters) ([]TenantAuditEntry, error)
	RecordAuditEvent(tenantID string, event *TenantAuditEvent) error
	
	// Health and monitoring
	GetTenantHealth(tenantID string) (*TenantHealthStatus, error)
	GetTenantMetrics(tenantID string, period *ReportPeriod) (*TenantMetricsReport, error)
	AlertOnTenantIssues(tenantID string, alertType string, details map[string]interface{}) error
}

// CreateTenantRequest represents a request to create a new tenant
type CreateTenantRequest struct {
	Name                   string                 `json:"name"`
	DisplayName            string                 `json:"display_name"`
	Description            string                 `json:"description,omitempty"`
	Type                   TenantType             `json:"type"`
	Plan                   TenantPlan             `json:"plan"`
	Tier                   TenantTier             `json:"tier"`
	Organization           string                 `json:"organization"`
	ContactEmail           string                 `json:"contact_email"`
	ContactName            string                 `json:"contact_name,omitempty"`
	Domain                 string                 `json:"domain,omitempty"`
	DataRegion             string                 `json:"data_region,omitempty"`
	IsolationLevel         IsolationLevel         `json:"isolation_level"`
	InitialConfiguration   *TenantConfiguration   `json:"initial_configuration,omitempty"`
	InitialUsers           []TenantUser           `json:"initial_users,omitempty"`
	BillingInfo            *TenantBillingInfo     `json:"billing_info,omitempty"`
	CustomFields           map[string]interface{} `json:"custom_fields,omitempty"`
	CreatedBy              string                 `json:"created_by"`
}

// TenantUpdateRequest represents a request to update a tenant
type TenantUpdateRequest struct {
	Name                   *string                `json:"name,omitempty"`
	DisplayName            *string                `json:"display_name,omitempty"`
	Description            *string                `json:"description,omitempty"`
	ContactEmail           *string                `json:"contact_email,omitempty"`
	ContactName            *string                `json:"contact_name,omitempty"`
	Domain                 *string                `json:"domain,omitempty"`
	Plan                   *TenantPlan            `json:"plan,omitempty"`
	Tier                   *TenantTier            `json:"tier,omitempty"`
	Status                 *TenantStatus          `json:"status,omitempty"`
	FeatureFlags           map[string]bool        `json:"feature_flags,omitempty"`
	Tags                   []string               `json:"tags,omitempty"`
	CustomFields           map[string]interface{} `json:"custom_fields,omitempty"`
	UpdatedBy              string                 `json:"updated_by"`
}

// TenantListFilters represents filters for listing tenants
type TenantListFilters struct {
	Status                 []TenantStatus         `json:"status,omitempty"`
	Type                   []TenantType           `json:"type,omitempty"`
	Plan                   []TenantPlan           `json:"plan,omitempty"`
	Tier                   []TenantTier           `json:"tier,omitempty"`
	Organization           string                 `json:"organization,omitempty"`
	Domain                 string                 `json:"domain,omitempty"`
	DataRegion             string                 `json:"data_region,omitempty"`
	CreatedAfter           *time.Time             `json:"created_after,omitempty"`
	CreatedBefore          *time.Time             `json:"created_before,omitempty"`
	Tags                   []string               `json:"tags,omitempty"`
	SearchQuery            string                 `json:"search_query,omitempty"`
	SortBy                 string                 `json:"sort_by,omitempty"`
	SortOrder              string                 `json:"sort_order,omitempty"`
	Limit                  int                    `json:"limit,omitempty"`
	Offset                 int                    `json:"offset,omitempty"`
}

// TenantUser represents a user within a tenant
type TenantUser struct {
	ID                     string                 `json:"id"`
	TenantID               string                 `json:"tenant_id"`
	UserID                 string                 `json:"user_id"`
	Email                  string                 `json:"email"`
	Name                   string                 `json:"name"`
	Roles                  []string               `json:"roles"`
	Permissions            []string               `json:"permissions"`
	Status                 UserStatus             `json:"status"`
	LastLoginAt            *time.Time             `json:"last_login_at,omitempty"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusActive       UserStatus = "active"
	UserStatusInactive     UserStatus = "inactive"
	UserStatusSuspended    UserStatus = "suspended"
	UserStatusPending      UserStatus = "pending"
)

// UsageRecord represents a usage record for billing
type UsageRecord struct {
	TenantID               string                 `json:"tenant_id"`
	Resource               string                 `json:"resource"`           // requests, storage, compute, etc.
	Amount                 int64                  `json:"amount"`
	Unit                   string                 `json:"unit"`               // count, bytes, seconds, etc.
	Timestamp              time.Time              `json:"timestamp"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// ReportPeriod represents a time period for reports
type ReportPeriod struct {
	StartTime              time.Time              `json:"start_time"`
	EndTime                time.Time              `json:"end_time"`
	Granularity            string                 `json:"granularity"`        // hour, day, week, month
}

// UsageReport represents a usage report
type UsageReport struct {
	TenantID               string                 `json:"tenant_id"`
	Period                 *ReportPeriod          `json:"period"`
	TotalUsage             map[string]int64       `json:"total_usage"`        // resource -> amount
	UsageByDay             []DailyUsage           `json:"usage_by_day"`
	Costs                  map[string]float64     `json:"costs"`              // resource -> cost
	TotalCost              float64                `json:"total_cost"`
	Currency               string                 `json:"currency"`
	GeneratedAt            time.Time              `json:"generated_at"`
}

// DailyUsage represents usage for a single day
type DailyUsage struct {
	Date                   time.Time              `json:"date"`
	Usage                  map[string]int64       `json:"usage"`              // resource -> amount
	Cost                   float64                `json:"cost"`
}

// TenantAuditEntry represents an audit log entry for a tenant
type TenantAuditEntry struct {
	ID                     string                 `json:"id"`
	TenantID               string                 `json:"tenant_id"`
	Action                 string                 `json:"action"`
	Actor                  string                 `json:"actor"`              // User or system component
	ActorType              string                 `json:"actor_type"`         // user, system, api
	Resource               string                 `json:"resource"`           // What was acted upon
	ResourceID             string                 `json:"resource_id,omitempty"`
	Details                map[string]interface{} `json:"details"`
	Result                 string                 `json:"result"`             // success, failure, partial
	ErrorMessage           string                 `json:"error_message,omitempty"`
	IPAddress              string                 `json:"ip_address,omitempty"`
	UserAgent              string                 `json:"user_agent,omitempty"`
	Timestamp              time.Time              `json:"timestamp"`
	Severity               string                 `json:"severity"`           // low, medium, high, critical
}

// TenantAuditEvent represents an event to be audited
type TenantAuditEvent struct {
	Action                 string                 `json:"action"`
	Actor                  string                 `json:"actor"`
	ActorType              string                 `json:"actor_type"`
	Resource               string                 `json:"resource"`
	ResourceID             string                 `json:"resource_id,omitempty"`
	Details                map[string]interface{} `json:"details,omitempty"`
	Result                 string                 `json:"result"`
	ErrorMessage           string                 `json:"error_message,omitempty"`
	IPAddress              string                 `json:"ip_address,omitempty"`
	UserAgent              string                 `json:"user_agent,omitempty"`
	Severity               string                 `json:"severity"`
}

// AuditLogFilters represents filters for audit log queries
type AuditLogFilters struct {
	Actions                []string               `json:"actions,omitempty"`
	Actors                 []string               `json:"actors,omitempty"`
	ActorTypes             []string               `json:"actor_types,omitempty"`
	Resources              []string               `json:"resources,omitempty"`
	StartTime              *time.Time             `json:"start_time,omitempty"`
	EndTime                *time.Time             `json:"end_time,omitempty"`
	Severity               []string               `json:"severity,omitempty"`
	Result                 []string               `json:"result,omitempty"`
	IPAddress              string                 `json:"ip_address,omitempty"`
	Limit                  int                    `json:"limit,omitempty"`
	Offset                 int                    `json:"offset,omitempty"`
}

// TenantHealthStatus represents the health status of a tenant
type TenantHealthStatus struct {
	TenantID               string                 `json:"tenant_id"`
	OverallStatus          HealthStatus           `json:"overall_status"`
	Components             map[string]ComponentHealth `json:"components"`
	LastChecked            time.Time              `json:"last_checked"`
	Uptime                 time.Duration          `json:"uptime"`
	Issues                 []HealthIssue          `json:"issues,omitempty"`
	Recommendations        []string               `json:"recommendations,omitempty"`
}

// HealthStatus represents overall health status
type HealthStatus string

const (
	HealthStatusHealthy    HealthStatus = "healthy"
	HealthStatusDegraded   HealthStatus = "degraded"
	HealthStatusUnhealthy  HealthStatus = "unhealthy"
	HealthStatusCritical   HealthStatus = "critical"
)

// ComponentHealth represents health of a component
type ComponentHealth struct {
	Name                   string                 `json:"name"`
	Status                 HealthStatus           `json:"status"`
	ResponseTime           time.Duration          `json:"response_time"`
	ErrorRate              float64                `json:"error_rate"`
	LastHealthy            *time.Time             `json:"last_healthy,omitempty"`
	Details                map[string]interface{} `json:"details,omitempty"`
}

// HealthIssue represents a health issue
type HealthIssue struct {
	Component              string                 `json:"component"`
	Severity               string                 `json:"severity"`
	Message                string                 `json:"message"`
	FirstDetected          time.Time              `json:"first_detected"`
	LastDetected           time.Time              `json:"last_detected"`
	Count                  int                    `json:"count"`
	Details                map[string]interface{} `json:"details,omitempty"`
}

// TenantMetricsReport represents metrics for a tenant
type TenantMetricsReport struct {
	TenantID               string                 `json:"tenant_id"`
	Period                 *ReportPeriod          `json:"period"`
	RequestMetrics         *RequestMetrics        `json:"request_metrics"`
	PerformanceMetrics     *PerformanceMetrics    `json:"performance_metrics"`
	ResourceMetrics        *ResourceMetrics       `json:"resource_metrics"`
	ErrorMetrics           *ErrorMetrics          `json:"error_metrics"`
	BusinessMetrics        *BusinessMetrics       `json:"business_metrics"`
	GeneratedAt            time.Time              `json:"generated_at"`
}

// RequestMetrics represents request-related metrics
type RequestMetrics struct {
	TotalRequests          int64                  `json:"total_requests"`
	SuccessfulRequests     int64                  `json:"successful_requests"`
	FailedRequests         int64                  `json:"failed_requests"`
	RequestsPerSecond      float64                `json:"requests_per_second"`
	PeakRequestsPerSecond  float64                `json:"peak_requests_per_second"`
	RequestsByStatus       map[string]int64       `json:"requests_by_status"`
	RequestsByEndpoint     map[string]int64       `json:"requests_by_endpoint"`
	RequestTrends          []RequestTrend         `json:"request_trends"`
}

// PerformanceMetrics represents performance-related metrics
type PerformanceMetrics struct {
	AverageLatency         time.Duration          `json:"average_latency"`
	MedianLatency          time.Duration          `json:"median_latency"`
	P95Latency             time.Duration          `json:"p95_latency"`
	P99Latency             time.Duration          `json:"p99_latency"`
	MaxLatency             time.Duration          `json:"max_latency"`
	LatencyTrends          []LatencyTrend         `json:"latency_trends"`
	ThroughputTrends       []ThroughputTrend      `json:"throughput_trends"`
}

// ResourceMetrics represents resource usage metrics
type ResourceMetrics struct {
	CPUUsage               float64                `json:"cpu_usage"`              // percentage
	MemoryUsage            int64                  `json:"memory_usage"`           // bytes
	StorageUsage           int64                  `json:"storage_usage"`          // bytes
	BandwidthUsage         int64                  `json:"bandwidth_usage"`        // bytes
	CacheHitRatio          float64                `json:"cache_hit_ratio"`
	CacheSize              int64                  `json:"cache_size"`             // bytes
	ActiveConnections      int                    `json:"active_connections"`
	ResourceTrends         []ResourceTrend        `json:"resource_trends"`
}

// ErrorMetrics represents error-related metrics
type ErrorMetrics struct {
	TotalErrors            int64                  `json:"total_errors"`
	ErrorRate              float64                `json:"error_rate"`             // percentage
	ErrorsByType           map[string]int64       `json:"errors_by_type"`
	ErrorsByComponent      map[string]int64       `json:"errors_by_component"`
	RecoverableErrors      int64                  `json:"recoverable_errors"`
	FatalErrors            int64                  `json:"fatal_errors"`
	ErrorTrends            []ErrorTrend           `json:"error_trends"`
}

// BusinessMetrics represents business-related metrics
type BusinessMetrics struct {
	ActiveUsers            int                    `json:"active_users"`
	ActivePolicies         int                    `json:"active_policies"`
	PolicyEvaluations      int64                  `json:"policy_evaluations"`
	PolicyMatches          int64                  `json:"policy_matches"`
	MatchRate              float64                `json:"match_rate"`             // percentage
	BlockedRequests        int64                  `json:"blocked_requests"`
	AllowedRequests        int64                  `json:"allowed_requests"`
	ConflictResolutions    int64                  `json:"conflict_resolutions"`
	FeatureUsage           map[string]int64       `json:"feature_usage"`
}

// RequestTrend represents request trends over time
type RequestTrend struct {
	Timestamp              time.Time              `json:"timestamp"`
	Count                  int64                  `json:"count"`
	SuccessRate            float64                `json:"success_rate"`
}

// LatencyTrend represents latency trends over time
type LatencyTrend struct {
	Timestamp              time.Time              `json:"timestamp"`
	AverageLatency         time.Duration          `json:"average_latency"`
	P95Latency             time.Duration          `json:"p95_latency"`
}

// ThroughputTrend represents throughput trends over time
type ThroughputTrend struct {
	Timestamp              time.Time              `json:"timestamp"`
	RequestsPerSecond      float64                `json:"requests_per_second"`
}

// ResourceTrend represents resource usage trends over time
type ResourceTrend struct {
	Timestamp              time.Time              `json:"timestamp"`
	CPUUsage               float64                `json:"cpu_usage"`
	MemoryUsage            int64                  `json:"memory_usage"`
	StorageUsage           int64                  `json:"storage_usage"`
}

// ErrorTrend represents error trends over time
type ErrorTrend struct {
	Timestamp              time.Time              `json:"timestamp"`
	ErrorCount             int64                  `json:"error_count"`
	ErrorRate              float64                `json:"error_rate"`
}

// ===== TENANT CONTEXT SYSTEM =====

// TenantContext represents the context for tenant-aware operations
type TenantContext struct {
	TenantID               string                 `json:"tenant_id"`
	TenantName             string                 `json:"tenant_name"`
	Namespace              string                 `json:"namespace"`
	IsolationLevel         IsolationLevel         `json:"isolation_level"`
	
	// User context
	UserID                 string                 `json:"user_id,omitempty"`
	UserRoles              []string               `json:"user_roles,omitempty"`
	UserPermissions        []string               `json:"user_permissions,omitempty"`
	
	// Request context
	RequestID              string                 `json:"request_id,omitempty"`
	SessionID              string                 `json:"session_id,omitempty"`
	IPAddress              string                 `json:"ip_address,omitempty"`
	UserAgent              string                 `json:"user_agent,omitempty"`
	
	// Configuration context
	Configuration          *TenantConfiguration   `json:"configuration,omitempty"`
	ResourceLimits         *TenantResourceLimits  `json:"resource_limits,omitempty"`
	SecuritySettings       *TenantSecuritySettings `json:"security_settings,omitempty"`
	
	// Runtime context
	StartTime              time.Time              `json:"start_time"`
	Timeout                time.Duration          `json:"timeout,omitempty"`
	TraceID                string                 `json:"trace_id,omitempty"`
	CorrelationID          string                 `json:"correlation_id,omitempty"`
	
	// Additional metadata
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// TenantContextBuilder provides a builder pattern for TenantContext
type TenantContextBuilder struct {
	context *TenantContext
}

// NewTenantContextBuilder creates a new tenant context builder
func NewTenantContextBuilder(tenantID string) *TenantContextBuilder {
	return &TenantContextBuilder{
		context: &TenantContext{
			TenantID:  tenantID,
			StartTime: time.Now(),
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithTenantName sets the tenant name
func (b *TenantContextBuilder) WithTenantName(name string) *TenantContextBuilder {
	b.context.TenantName = name
	return b
}

// WithNamespace sets the namespace
func (b *TenantContextBuilder) WithNamespace(namespace string) *TenantContextBuilder {
	b.context.Namespace = namespace
	return b
}

// WithIsolationLevel sets the isolation level
func (b *TenantContextBuilder) WithIsolationLevel(level IsolationLevel) *TenantContextBuilder {
	b.context.IsolationLevel = level
	return b
}

// WithUser sets user context
func (b *TenantContextBuilder) WithUser(userID string, roles []string, permissions []string) *TenantContextBuilder {
	b.context.UserID = userID
	b.context.UserRoles = roles
	b.context.UserPermissions = permissions
	return b
}

// WithRequest sets request context
func (b *TenantContextBuilder) WithRequest(requestID, sessionID, ipAddress, userAgent string) *TenantContextBuilder {
	b.context.RequestID = requestID
	b.context.SessionID = sessionID
	b.context.IPAddress = ipAddress
	b.context.UserAgent = userAgent
	return b
}

// WithConfiguration sets tenant configuration
func (b *TenantContextBuilder) WithConfiguration(config *TenantConfiguration) *TenantContextBuilder {
	b.context.Configuration = config
	return b
}

// WithResourceLimits sets resource limits
func (b *TenantContextBuilder) WithResourceLimits(limits *TenantResourceLimits) *TenantContextBuilder {
	b.context.ResourceLimits = limits
	return b
}

// WithSecuritySettings sets security settings
func (b *TenantContextBuilder) WithSecuritySettings(settings *TenantSecuritySettings) *TenantContextBuilder {
	b.context.SecuritySettings = settings
	return b
}

// WithTimeout sets timeout
func (b *TenantContextBuilder) WithTimeout(timeout time.Duration) *TenantContextBuilder {
	b.context.Timeout = timeout
	return b
}

// WithTracing sets trace and correlation IDs
func (b *TenantContextBuilder) WithTracing(traceID, correlationID string) *TenantContextBuilder {
	b.context.TraceID = traceID
	b.context.CorrelationID = correlationID
	return b
}

// WithMetadata adds metadata
func (b *TenantContextBuilder) WithMetadata(key string, value interface{}) *TenantContextBuilder {
	b.context.Metadata[key] = value
	return b
}

// Build creates the tenant context
func (b *TenantContextBuilder) Build() *TenantContext {
	return b.context
}

// ===== TENANT ISOLATION SYSTEM =====

// TenantIsolationManager manages tenant isolation and resource separation
type TenantIsolationManager interface {
	// Namespace management
	CreateNamespace(tenantID string) (string, error)
	DeleteNamespace(tenantID string) error
	GetNamespace(tenantID string) (string, error)
	ValidateNamespace(tenantID, namespace string) (bool, error)
	
	// Resource isolation
	CreateTenantCache(tenantID string) (TenantCacheInterface, error)
	GetTenantCache(tenantID string) (TenantCacheInterface, error)
	DeleteTenantCache(tenantID string) error
	
	CreateTenantMetrics(tenantID string) (TenantMetricsInterface, error)
	GetTenantMetrics(tenantID string) (TenantMetricsInterface, error)
	DeleteTenantMetrics(tenantID string) error
	
	CreateTenantLogger(tenantID string) (TenantLoggerInterface, error)
	GetTenantLogger(tenantID string) (TenantLoggerInterface, error)
	DeleteTenantLogger(tenantID string) error
	
	// Policy isolation
	CreateTenantPolicyEngine(tenantID string, config *TenantConfiguration) (TenantPolicyEngineInterface, error)
	GetTenantPolicyEngine(tenantID string) (TenantPolicyEngineInterface, error)
	DeleteTenantPolicyEngine(tenantID string) error
	
	// Health and monitoring
	CheckTenantIsolation(tenantID string) (*IsolationHealthCheck, error)
	EnforceIsolation(tenantID string) error
	GetIsolationMetrics(tenantID string) (*IsolationMetrics, error)
}

// TenantCacheInterface extends PolicyCacheInterface with tenant-aware operations
type TenantCacheInterface interface {
	PolicyCacheInterface
	
	// Tenant-specific operations
	GetTenantID() string
	GetNamespace() string
	GetMemoryUsage() int64
	GetEntryCount() int
	ClearTenantData() error
	GetCacheStats() *TenantCacheStats
	
	// Isolation controls
	SetMaxMemory(bytes int64) error
	SetMaxEntries(count int) error
	EnforceQuotas() error
}

// TenantMetricsInterface provides tenant-isolated metrics collection
type TenantMetricsInterface interface {
	PolicyMetrics
	
	// Tenant-specific operations
	GetTenantID() string
	GetNamespace() string
	RecordTenantUsage(resource string, amount int64) error
	GetTenantResourceUsage() map[string]int64
	GetTenantStats() *TenantMetricsStats
	
	// Quota and limits
	CheckQuota(resource string, amount int64) (bool, error)
	GetQuotaUsage() map[string]*QuotaUsage
	ResetMetrics() error
}

// TenantLoggerInterface provides tenant-isolated logging
type TenantLoggerInterface interface {
	PolicyLogger
	
	// Tenant-specific operations
	GetTenantID() string
	GetNamespace() string
	LogTenantEvent(event *TenantAuditEvent) error
	GetTenantLogs(filters *TenantLogFilters) ([]TenantLogEntry, error)
	
	// Log management
	RotateLogs() error
	PurgeLogs(olderThan time.Duration) error
	GetLogStats() *TenantLogStats
}

// TenantPolicyEngineInterface provides tenant-isolated policy evaluation
type TenantPolicyEngineInterface interface {
	// Core policy operations with tenant context
	AddPolicy(ctx *TenantContext, policy *Policy) error
	GetPolicy(ctx *TenantContext, id string) (*Policy, error)
	UpdatePolicy(ctx *TenantContext, policy *Policy) error
	DeletePolicy(ctx *TenantContext, id string) error
	ListPolicies(ctx *TenantContext) []*Policy
	
	// Tenant-aware evaluation
	EvaluateRequest(ctx *TenantContext, request *TenantPolicyEvaluationRequest) (*TenantPolicyEvaluationResult, error)
	
	// Tenant isolation
	GetTenantID() string
	GetNamespace() string
	GetTenantConfiguration() *TenantConfiguration
	UpdateTenantConfiguration(config *TenantConfiguration) error
	
	// Resource management
	GetResourceUsage() *TenantEngineResourceUsage
	EnforceResourceLimits() error
	
	// Health and monitoring
	GetHealthStatus() *TenantEngineHealth
	GetPerformanceMetrics() *TenantEngineMetrics
}

// TenantPolicyEvaluationRequest extends PolicyEvaluationRequest with tenant context
type TenantPolicyEvaluationRequest struct {
	PolicyEvaluationRequest
	TenantContext *TenantContext `json:"tenant_context"`
}

// TenantPolicyEvaluationResult extends PolicyEvaluationResult with tenant context
type TenantPolicyEvaluationResult struct {
	PolicyEvaluationResult
	TenantContext *TenantContext `json:"tenant_context"`
	ResourceUsage *RequestResourceUsage `json:"resource_usage"`
}

// RequestResourceUsage tracks resource usage for a single request
type RequestResourceUsage struct {
	CPUTime        time.Duration `json:"cpu_time"`
	MemoryUsed     int64         `json:"memory_used"`      // bytes
	CacheAccesses  int           `json:"cache_accesses"`
	DatabaseQueries int          `json:"database_queries"`
	NetworkCalls   int           `json:"network_calls"`
	StorageReads   int64         `json:"storage_reads"`    // bytes
	StorageWrites  int64         `json:"storage_writes"`   // bytes
}

// IsolationHealthCheck represents isolation health status
type IsolationHealthCheck struct {
	TenantID           string                 `json:"tenant_id"`
	Namespace          string                 `json:"namespace"`
	IsolationLevel     IsolationLevel         `json:"isolation_level"`
	OverallHealth      HealthStatus           `json:"overall_health"`
	Components         map[string]ComponentHealth `json:"components"`
	Issues             []IsolationIssue       `json:"issues,omitempty"`
	LastChecked        time.Time              `json:"last_checked"`
}

// IsolationIssue represents an isolation-related issue
type IsolationIssue struct {
	Component    string    `json:"component"`
	Type         string    `json:"type"`        // data_leak, resource_bleed, access_violation
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
	DetectedAt   time.Time `json:"detected_at"`
	Impact       string    `json:"impact"`
	Remediation  string    `json:"remediation"`
}

// IsolationMetrics tracks isolation-related metrics
type IsolationMetrics struct {
	TenantID              string                 `json:"tenant_id"`
	Namespace             string                 `json:"namespace"`
	DataLeaks             int64                  `json:"data_leaks"`
	AccessViolations      int64                  `json:"access_violations"`
	ResourceBleeds        int64                  `json:"resource_bleeds"`
	CrossTenantRequests   int64                  `json:"cross_tenant_requests"`
	IsolationViolations   int64                  `json:"isolation_violations"`
	LastViolation         *time.Time             `json:"last_violation,omitempty"`
	ViolationsByType      map[string]int64       `json:"violations_by_type"`
	MitigationActions     int64                  `json:"mitigation_actions"`
}

// TenantCacheStats provides cache statistics for a tenant
type TenantCacheStats struct {
	TenantID         string        `json:"tenant_id"`
	Namespace        string        `json:"namespace"`
	MemoryUsed       int64         `json:"memory_used"`       // bytes
	MemoryLimit      int64         `json:"memory_limit"`      // bytes
	EntryCount       int           `json:"entry_count"`
	EntryLimit       int           `json:"entry_limit"`
	HitCount         int64         `json:"hit_count"`
	MissCount        int64         `json:"miss_count"`
	HitRatio         float64       `json:"hit_ratio"`
	EvictionCount    int64         `json:"eviction_count"`
	LastEviction     *time.Time    `json:"last_eviction,omitempty"`
	AverageKeySize   int           `json:"average_key_size"`
	AverageValueSize int           `json:"average_value_size"`
}

// TenantMetricsStats provides metrics statistics for a tenant
type TenantMetricsStats struct {
	TenantID              string                 `json:"tenant_id"`
	Namespace             string                 `json:"namespace"`
	MetricsCollected      int64                  `json:"metrics_collected"`
	MetricsDropped        int64                  `json:"metrics_dropped"`
	LastCollection        time.Time              `json:"last_collection"`
	CollectionLatency     time.Duration          `json:"collection_latency"`
	StorageUsed           int64                  `json:"storage_used"`       // bytes
	ExportedMetrics       int64                  `json:"exported_metrics"`
	ExportErrors          int64                  `json:"export_errors"`
	RetentionViolations   int64                  `json:"retention_violations"`
}

// QuotaUsage tracks quota usage for a resource
type QuotaUsage struct {
	Resource      string    `json:"resource"`
	Used          int64     `json:"used"`
	Limit         int64     `json:"limit"`
	Unit          string    `json:"unit"`
	UsagePercent  float64   `json:"usage_percent"`
	LastUpdated   time.Time `json:"last_updated"`
	Violations    int64     `json:"violations"`
	LastViolation *time.Time `json:"last_violation,omitempty"`
}

// TenantLogFilters extends audit log filters with tenant-specific options
type TenantLogFilters struct {
	AuditLogFilters
	LogLevel    []string `json:"log_level,omitempty"`     // debug, info, warn, error
	Component   []string `json:"component,omitempty"`
	UserID      []string `json:"user_id,omitempty"`
	SessionID   []string `json:"session_id,omitempty"`
}

// TenantLogEntry represents a tenant-specific log entry
type TenantLogEntry struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	Namespace    string                 `json:"namespace"`
	Level        string                 `json:"level"`
	Component    string                 `json:"component"`
	Message      string                 `json:"message"`
	Timestamp    time.Time              `json:"timestamp"`
	UserID       string                 `json:"user_id,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	TraceID      string                 `json:"trace_id,omitempty"`
	Fields       map[string]interface{} `json:"fields,omitempty"`
	StackTrace   string                 `json:"stack_trace,omitempty"`
}

// TenantLogStats provides log statistics for a tenant
type TenantLogStats struct {
	TenantID         string                 `json:"tenant_id"`
	Namespace        string                 `json:"namespace"`
	LogsGenerated    int64                  `json:"logs_generated"`
	LogsDropped      int64                  `json:"logs_dropped"`
	LogsByLevel      map[string]int64       `json:"logs_by_level"`
	LogsByComponent  map[string]int64       `json:"logs_by_component"`
	StorageUsed      int64                  `json:"storage_used"`      // bytes
	OldestLog        *time.Time             `json:"oldest_log,omitempty"`
	LatestLog        *time.Time             `json:"latest_log,omitempty"`
	RotationCount    int64                  `json:"rotation_count"`
	LastRotation     *time.Time             `json:"last_rotation,omitempty"`
}

// TenantEngineResourceUsage tracks resource usage for a tenant's policy engine
type TenantEngineResourceUsage struct {
	TenantID            string        `json:"tenant_id"`
	Namespace           string        `json:"namespace"`
	PoliciesLoaded      int           `json:"policies_loaded"`
	PoliciesLimit       int           `json:"policies_limit"`
	RulesLoaded         int           `json:"rules_loaded"`
	RulesLimit          int           `json:"rules_limit"`
	MemoryUsed          int64         `json:"memory_used"`          // bytes
	MemoryLimit         int64         `json:"memory_limit"`         // bytes
	CPUTimeUsed         time.Duration `json:"cpu_time_used"`
	RequestsProcessed   int64         `json:"requests_processed"`
	RequestsLimit       int64         `json:"requests_limit"`
	ConcurrentRequests  int           `json:"concurrent_requests"`
	ConcurrentLimit     int           `json:"concurrent_limit"`
	LastUpdated         time.Time     `json:"last_updated"`
}

// TenantEngineHealth represents health status of a tenant's policy engine
type TenantEngineHealth struct {
	TenantID             string                 `json:"tenant_id"`
	Namespace            string                 `json:"namespace"`
	OverallHealth        HealthStatus           `json:"overall_health"`
	PolicyEngineStatus   HealthStatus           `json:"policy_engine_status"`
	CacheStatus          HealthStatus           `json:"cache_status"`
	MetricsStatus        HealthStatus           `json:"metrics_status"`
	LoggingStatus        HealthStatus           `json:"logging_status"`
	LastHealthCheck      time.Time              `json:"last_health_check"`
	HealthCheckDuration  time.Duration          `json:"health_check_duration"`
	Issues               []HealthIssue          `json:"issues,omitempty"`
	ResourceUtilization  map[string]float64     `json:"resource_utilization"` // percentage
}

// TenantEngineMetrics provides performance metrics for a tenant's policy engine
type TenantEngineMetrics struct {
	TenantID                string                 `json:"tenant_id"`
	Namespace               string                 `json:"namespace"`
	EvaluationsPerSecond    float64                `json:"evaluations_per_second"`
	AverageLatency          time.Duration          `json:"average_latency"`
	P95Latency              time.Duration          `json:"p95_latency"`
	P99Latency              time.Duration          `json:"p99_latency"`
	ErrorRate               float64                `json:"error_rate"`              // percentage
	ThroughputTrend         []ThroughputDataPoint  `json:"throughput_trend"`
	LatencyTrend            []LatencyDataPoint     `json:"latency_trend"`
	ErrorTrend              []ErrorDataPoint       `json:"error_trend"`
	CachePerformance        *CachePerformanceMetrics `json:"cache_performance"`
	PolicyPerformance       map[string]*PolicyPerformanceMetrics `json:"policy_performance"`
	LastUpdated             time.Time              `json:"last_updated"`
}

// ThroughputDataPoint represents a throughput measurement
type ThroughputDataPoint struct {
	Timestamp        time.Time `json:"timestamp"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	EvaluationsPerSecond float64 `json:"evaluations_per_second"`
}

// LatencyDataPoint represents a latency measurement
type LatencyDataPoint struct {
	Timestamp        time.Time     `json:"timestamp"`
	AverageLatency   time.Duration `json:"average_latency"`
	P95Latency       time.Duration `json:"p95_latency"`
	P99Latency       time.Duration `json:"p99_latency"`
}

// ErrorDataPoint represents an error rate measurement
type ErrorDataPoint struct {
	Timestamp    time.Time `json:"timestamp"`
	ErrorCount   int64     `json:"error_count"`
	TotalRequests int64    `json:"total_requests"`
	ErrorRate    float64   `json:"error_rate"`
}

// CachePerformanceMetrics tracks cache performance for a tenant
type CachePerformanceMetrics struct {
	HitRatio         float64       `json:"hit_ratio"`
	MissRatio        float64       `json:"miss_ratio"`
	AverageHitTime   time.Duration `json:"average_hit_time"`
	AverageMissTime  time.Duration `json:"average_miss_time"`
	EvictionsPerSecond float64     `json:"evictions_per_second"`
	MemoryEfficiency float64       `json:"memory_efficiency"`   // percentage
}

// PolicyPerformanceMetrics tracks performance for individual policies
type PolicyPerformanceMetrics struct {
	PolicyID         string        `json:"policy_id"`
	PolicyName       string        `json:"policy_name"`
	EvaluationCount  int64         `json:"evaluation_count"`
	MatchCount       int64         `json:"match_count"`
	MatchRatio       float64       `json:"match_ratio"`
	AverageLatency   time.Duration `json:"average_latency"`
	MaxLatency       time.Duration `json:"max_latency"`
	MinLatency       time.Duration `json:"min_latency"`
	ErrorCount       int64         `json:"error_count"`
	ErrorRate        float64       `json:"error_rate"`
	LastEvaluation   time.Time     `json:"last_evaluation"`
}

// ===== POLICY TEMPLATE SYSTEM =====

// PolicyTemplate represents a reusable policy template
type PolicyTemplate struct {
	ID                    string                 `json:"id"`                      // Unique template ID
	Name                  string                 `json:"name"`                    // Human-readable name
	DisplayName           string                 `json:"display_name"`            // UI display name
	Description           string                 `json:"description"`             // Template description
	LongDescription       string                 `json:"long_description"`        // Detailed description
	Version               string                 `json:"version"`                 // Template version
	Category              TemplateCategory       `json:"category"`                // Template category
	SubCategory           string                 `json:"sub_category"`            // Sub-category
	Tags                  []string               `json:"tags"`                    // Template tags
	
	// Template content
	PolicyTemplate        *Policy                `json:"policy_template"`         // Base policy structure
	Rules                 []PolicyRuleTemplate   `json:"rules"`                   // Rule templates
	DefaultConfiguration  *TemplateConfiguration `json:"default_configuration"`   // Default config
	CustomizationOptions  []TemplateParameter    `json:"customization_options"`   // Customizable parameters
	
	// Metadata
	Author                string                 `json:"author"`                  // Template author
	Organization          string                 `json:"organization"`            // Publishing organization
	CreatedAt             time.Time              `json:"created_at"`              // Creation timestamp
	UpdatedAt             time.Time              `json:"updated_at"`              // Last update
	PublishedAt           *time.Time             `json:"published_at,omitempty"`  // Publication timestamp
	
	// Usage and compatibility
	TargetUseCase         string                 `json:"target_use_case"`         // Primary use case
	IndustryVerticals     []string               `json:"industry_verticals"`      // Target industries
	ComplianceFrameworks  []string               `json:"compliance_frameworks"`   // Supported frameworks
	Prerequisites         []string               `json:"prerequisites"`           // Required components
	Dependencies          []string               `json:"dependencies"`            // Template dependencies
	
	// Template validation
	Schema                *TemplateSchema        `json:"schema"`                  // Validation schema
	Examples              []TemplateExample      `json:"examples"`                // Usage examples
	TestCases             []TemplateTestCase     `json:"test_cases"`              // Test scenarios
	
	// Deployment and lifecycle
	Status                TemplateStatus         `json:"status"`                  // Template status
	Maturity              TemplateMaturity       `json:"maturity"`                // Maturity level
	SupportLevel          TemplateSupportLevel   `json:"support_level"`           // Support level
	LicenseType           string                 `json:"license_type"`            // License
	
	// Statistics and metrics
	UsageCount            int64                  `json:"usage_count"`             // Times used
	LastUsed              *time.Time             `json:"last_used,omitempty"`     // Last usage
	Rating                float64                `json:"rating"`                  // Community rating
	ReviewCount           int                    `json:"review_count"`            // Number of reviews
	SuccessRate           float64                `json:"success_rate"`            // Deployment success rate
	
	// Additional metadata
	Metadata              map[string]interface{} `json:"metadata"`                // Additional metadata
}

// TemplateCategory represents the category of policy template
type TemplateCategory string

const (
	TemplateCategoryPII          TemplateCategory = "pii_protection"       // PII protection templates
	TemplateCategoryCompliance   TemplateCategory = "compliance"           // Compliance templates
	TemplateCategorySecurity     TemplateCategory = "security"             // Security templates
	TemplateCategoryIndustry     TemplateCategory = "industry_specific"    // Industry-specific templates
	TemplateCategoryContent      TemplateCategory = "content_governance"   // Content governance
	TemplateCategoryAccess       TemplateCategory = "access_control"       // Access control
	TemplateCategoryData         TemplateCategory = "data_protection"      // Data protection
	TemplateCategoryRisk         TemplateCategory = "risk_management"      // Risk management
	TemplateCategoryMonitoring   TemplateCategory = "monitoring"           // Monitoring and alerting
	TemplateCategoryWorkflow     TemplateCategory = "workflow"             // Workflow automation
	TemplateCategoryGeneral      TemplateCategory = "general"              // General purpose
	TemplateCategoryCustom       TemplateCategory = "custom"               // Custom templates
)

// TemplateStatus represents the status of a template
type TemplateStatus string

const (
	TemplateStatusDraft       TemplateStatus = "draft"         // Draft template
	TemplateStatusReview      TemplateStatus = "review"        // Under review
	TemplateStatusActive      TemplateStatus = "active"        // Active and available
	TemplateStatusDeprecated  TemplateStatus = "deprecated"    // Deprecated
	TemplateStatusArchived    TemplateStatus = "archived"      // Archived
	TemplateStatusPrivate     TemplateStatus = "private"       // Private template
)

// TemplateMaturity represents the maturity level of a template
type TemplateMaturity string

const (
	TemplateMaturityExperimental TemplateMaturity = "experimental" // Experimental
	TemplateMaturityBeta         TemplateMaturity = "beta"         // Beta
	TemplateMaturityStable       TemplateMaturity = "stable"       // Stable
	TemplateMaturityEnterprise   TemplateMaturity = "enterprise"   // Enterprise-grade
)

// TemplateSupportLevel represents the support level for a template
type TemplateSupportLevel string

const (
	TemplateSupportCommunity     TemplateSupportLevel = "community"      // Community support
	TemplateSupportCommercial    TemplateSupportLevel = "commercial"     // Commercial support
	TemplateSupportEnterprise    TemplateSupportLevel = "enterprise"     // Enterprise support
	TemplateSupportNone          TemplateSupportLevel = "none"           // No support
)

// PolicyRuleTemplate represents a rule template with parameterization
type PolicyRuleTemplate struct {
	PolicyRule                                                              // Embedded base rule
	ParameterizedCondition *ParameterizedCondition    `json:"parameterized_condition"` // Parameterized condition
	Parameters             []TemplateParameter        `json:"parameters"`              // Template parameters
	Variations             []RuleVariation            `json:"variations"`              // Rule variations
	ConfigurationHints     []string                   `json:"configuration_hints"`     // Configuration hints
}

// ParameterizedCondition represents a condition with parameters
type ParameterizedCondition struct {
	Template     string                 `json:"template"`      // Condition template string
	Parameters   map[string]interface{} `json:"parameters"`    // Parameter values
	Constraints  map[string]Constraint  `json:"constraints"`   // Parameter constraints
	Examples     []ConditionExample     `json:"examples"`      // Usage examples
}

// TemplateParameter represents a customizable parameter in a template
type TemplateParameter struct {
	Name            string                 `json:"name"`              // Parameter name
	DisplayName     string                 `json:"display_name"`      // UI display name
	Description     string                 `json:"description"`       // Parameter description
	Type            ParameterType          `json:"type"`              // Parameter type
	DefaultValue    interface{}            `json:"default_value"`     // Default value
	Required        bool                   `json:"required"`          // Whether required
	Constraints     *ParameterConstraints  `json:"constraints"`       // Value constraints
	Options         []ParameterOption      `json:"options"`           // Available options
	DependsOn       []string               `json:"depends_on"`        // Dependencies
	ConditionalShow *ConditionalLogic      `json:"conditional_show"`  // Show conditions
	ValidationRules []ValidationRule       `json:"validation_rules"`  // Validation rules
	UIHints         *UIHints               `json:"ui_hints"`          // UI rendering hints
	Examples        []interface{}          `json:"examples"`          // Example values
	Metadata        map[string]interface{} `json:"metadata"`          // Additional metadata
}

// ParameterType represents the type of template parameter
type ParameterType string

const (
	ParameterTypeString     ParameterType = "string"      // String parameter
	ParameterTypeNumber     ParameterType = "number"      // Numeric parameter
	ParameterTypeBoolean    ParameterType = "boolean"     // Boolean parameter
	ParameterTypeArray      ParameterType = "array"       // Array parameter
	ParameterTypeObject     ParameterType = "object"      // Object parameter
	ParameterTypeEnum       ParameterType = "enum"        // Enumeration
	ParameterTypeDate       ParameterType = "date"        // Date parameter
	ParameterTypeDuration   ParameterType = "duration"    // Duration parameter
	ParameterTypeRegex      ParameterType = "regex"       // Regular expression
	ParameterTypeEmail      ParameterType = "email"       // Email address
	ParameterTypeURL        ParameterType = "url"         // URL parameter
	ParameterTypeJSON       ParameterType = "json"        // JSON parameter
	ParameterTypeSelect     ParameterType = "select"      // Single selection
	ParameterTypeMultiSelect ParameterType = "multiselect" // Multiple selection
)

// ParameterConstraints represents constraints for template parameters
type ParameterConstraints struct {
	MinValue     *float64 `json:"min_value,omitempty"`     // Minimum value
	MaxValue     *float64 `json:"max_value,omitempty"`     // Maximum value
	MinLength    *int     `json:"min_length,omitempty"`    // Minimum length
	MaxLength    *int     `json:"max_length,omitempty"`    // Maximum length
	Pattern      string   `json:"pattern,omitempty"`       // Regex pattern
	Format       string   `json:"format,omitempty"`        // Format specification
	AllowedValues []interface{} `json:"allowed_values,omitempty"` // Allowed values
	ExcludedValues []interface{} `json:"excluded_values,omitempty"` // Excluded values
}

// ParameterOption represents an option for enum/select parameters
type ParameterOption struct {
	Value       interface{} `json:"value"`              // Option value
	Label       string      `json:"label"`              // Display label
	Description string      `json:"description"`        // Option description
	Deprecated  bool        `json:"deprecated"`         // Whether deprecated
	Group       string      `json:"group,omitempty"`    // Option group
	Icon        string      `json:"icon,omitempty"`     // Icon name
}

// ConditionalLogic represents conditional display logic
type ConditionalLogic struct {
	Condition string                 `json:"condition"`   // Condition expression
	Variables map[string]interface{} `json:"variables"`   // Available variables
}

// ValidationRule represents a parameter validation rule
type ValidationRule struct {
	Type        string                 `json:"type"`         // Validation type
	Expression  string                 `json:"expression"`   // Validation expression
	Message     string                 `json:"message"`      // Error message
	Severity    string                 `json:"severity"`     // Validation severity
	Parameters  map[string]interface{} `json:"parameters"`   // Rule parameters
}

// UIHints represents UI rendering hints for parameters
type UIHints struct {
	Widget      string                 `json:"widget"`       // UI widget type
	Placeholder string                 `json:"placeholder"`  // Placeholder text
	HelpText    string                 `json:"help_text"`    // Help text
	Rows        int                    `json:"rows"`         // Textarea rows
	Columns     int                    `json:"columns"`      // Grid columns
	Sortable    bool                   `json:"sortable"`     // Whether sortable
	Searchable  bool                   `json:"searchable"`   // Whether searchable
	Multiple    bool                   `json:"multiple"`     // Multiple selection
	Clearable   bool                   `json:"clearable"`    // Whether clearable
	Properties  map[string]interface{} `json:"properties"`   // Additional properties
}

// RuleVariation represents a variation of a rule template
type RuleVariation struct {
	Name            string                 `json:"name"`              // Variation name
	Description     string                 `json:"description"`       // Variation description
	Parameters      map[string]interface{} `json:"parameters"`        // Parameter overrides
	Condition       *PolicyCondition       `json:"condition"`         // Custom condition
	Action          *PolicyAction          `json:"action"`            // Custom action
	UseCase         string                 `json:"use_case"`          // Specific use case
	Complexity      string                 `json:"complexity"`        // Complexity level
	RecommendedFor  []string               `json:"recommended_for"`   // Recommended scenarios
}

// TemplateConfiguration represents default configuration for a template
type TemplateConfiguration struct {
	Parameters          map[string]interface{} `json:"parameters"`            // Default parameter values
	Scope               *PolicyScope           `json:"scope"`                 // Default scope
	Priority            int                    `json:"priority"`              // Default priority
	Category            string                 `json:"category"`              // Default category
	Tags                []string               `json:"tags"`                  // Default tags
	EnableByDefault     bool                   `json:"enable_by_default"`     // Whether enabled by default
	RequireApproval     bool                   `json:"require_approval"`      // Whether requires approval
	TestingRequired     bool                   `json:"testing_required"`      // Whether testing required
	NotificationSettings *NotificationSettings `json:"notification_settings"` // Notification settings
	MonitoringSettings  *MonitoringSettings    `json:"monitoring_settings"`   // Monitoring settings
}

// NotificationSettings represents notification configuration
type NotificationSettings struct {
	EnableAlerts      bool     `json:"enable_alerts"`        // Enable alerts
	Recipients        []string `json:"recipients"`           // Alert recipients
	Channels          []string `json:"channels"`             // Notification channels
	Frequency         string   `json:"frequency"`            // Alert frequency
	Severity          string   `json:"severity"`             // Alert severity
	CustomMessage     string   `json:"custom_message"`       // Custom alert message
}

// MonitoringSettings represents monitoring configuration
type MonitoringSettings struct {
	EnableMetrics     bool              `json:"enable_metrics"`       // Enable metrics collection
	MetricLabels      map[string]string `json:"metric_labels"`        // Metric labels
	SamplingRate      float64           `json:"sampling_rate"`        // Sampling rate
	RetentionPeriod   time.Duration     `json:"retention_period"`     // Retention period
	DashboardConfig   string            `json:"dashboard_config"`     // Dashboard configuration
}

// TemplateSchema represents validation schema for a template
type TemplateSchema struct {
	Version             string                    `json:"version"`               // Schema version
	ParameterSchema     map[string]*ParameterSchema `json:"parameter_schema"`   // Parameter schemas
	RuleSchema          *RuleSchema               `json:"rule_schema"`           // Rule validation schema
	CompatibilityRules  []CompatibilityRule       `json:"compatibility_rules"`   // Compatibility rules
	ValidationRules     []SchemaValidationRule    `json:"validation_rules"`      // Validation rules
	RequiredFeatures    []string                  `json:"required_features"`     // Required platform features
	MinPlatformVersion  string                    `json:"min_platform_version"`  // Minimum platform version
}

// ParameterSchema represents schema for a template parameter
type ParameterSchema struct {
	Type           string                 `json:"type"`             // Parameter type
	Required       bool                   `json:"required"`         // Whether required
	Constraints    *ParameterConstraints  `json:"constraints"`      // Value constraints
	DefaultValue   interface{}            `json:"default_value"`    // Default value
	Dependencies   []string               `json:"dependencies"`     // Parameter dependencies
	ConflictsWith  []string               `json:"conflicts_with"`   // Conflicting parameters
	Transformations []ParameterTransform  `json:"transformations"`  // Value transformations
}

// ParameterTransform represents a parameter value transformation
type ParameterTransform struct {
	Type       string                 `json:"type"`        // Transform type
	Expression string                 `json:"expression"`  // Transform expression
	Parameters map[string]interface{} `json:"parameters"`  // Transform parameters
}

// RuleSchema represents validation schema for rules
type RuleSchema struct {
	AllowedConditionTypes []ConditionType `json:"allowed_condition_types"` // Allowed condition types
	AllowedActionTypes    []ActionType    `json:"allowed_action_types"`    // Allowed action types
	MaxConditionDepth     int             `json:"max_condition_depth"`     // Max condition nesting
	RequiredFields        []string        `json:"required_fields"`         // Required rule fields
	CustomValidations     []string        `json:"custom_validations"`      // Custom validation functions
}

// CompatibilityRule represents a compatibility constraint
type CompatibilityRule struct {
	Name        string                 `json:"name"`         // Rule name
	Description string                 `json:"description"`  // Rule description
	Condition   string                 `json:"condition"`    // Compatibility condition
	Severity    string                 `json:"severity"`     // Rule severity
	Message     string                 `json:"message"`      // Error message
	Parameters  map[string]interface{} `json:"parameters"`   // Rule parameters
}

// SchemaValidationRule represents a schema validation rule
type SchemaValidationRule struct {
	Name       string                 `json:"name"`        // Rule name
	Type       string                 `json:"type"`        // Validation type
	Expression string                 `json:"expression"`  // Validation expression
	Message    string                 `json:"message"`     // Error message
	Severity   string                 `json:"severity"`    // Rule severity
	Context    map[string]interface{} `json:"context"`     // Validation context
}

// TemplateExample represents an example usage of a template
type TemplateExample struct {
	Name            string                 `json:"name"`              // Example name
	Description     string                 `json:"description"`       // Example description
	Scenario        string                 `json:"scenario"`          // Use case scenario
	Parameters      map[string]interface{} `json:"parameters"`        // Parameter values
	ExpectedOutcome string                 `json:"expected_outcome"`  // Expected outcome
	TestData        []ExampleTestData      `json:"test_data"`         // Test data
	Notes           string                 `json:"notes"`             // Additional notes
}

// ExampleTestData represents test data for an example
type ExampleTestData struct {
	Input           map[string]interface{} `json:"input"`             // Test input
	ExpectedResult  string                 `json:"expected_result"`   // Expected result
	Description     string                 `json:"description"`       // Test description
}

// TemplateTestCase represents a test case for a template
type TemplateTestCase struct {
	ID              string                    `json:"id"`                // Test case ID
	Name            string                    `json:"name"`              // Test case name
	Description     string                    `json:"description"`       // Test description
	Category        string                    `json:"category"`          // Test category
	Parameters      map[string]interface{}    `json:"parameters"`        // Test parameters
	TestData        []TestCaseData            `json:"test_data"`         // Test data sets
	ExpectedResults []TestCaseExpectedResult  `json:"expected_results"`  // Expected results
	Assertions      []TestAssertion           `json:"assertions"`        // Test assertions
	Tags            []string                  `json:"tags"`              // Test tags
}

// TestCaseData represents test data for a test case
type TestCaseData struct {
	Name        string                    `json:"name"`         // Data set name
	Request     *PolicyEvaluationRequest  `json:"request"`      // Test request
	Context     map[string]interface{}    `json:"context"`      // Test context
	Description string                    `json:"description"`  // Data description
}

// TestCaseExpectedResult represents expected result for a test case
type TestCaseExpectedResult struct {
	Action      ActionType `json:"action"`       // Expected action
	Matched     bool       `json:"matched"`      // Whether should match
	Confidence  float64    `json:"confidence"`   // Expected confidence
	Message     string     `json:"message"`      // Expected message
	Description string     `json:"description"`  // Result description
}

// TestAssertion represents a test assertion
type TestAssertion struct {
	Type        string      `json:"type"`         // Assertion type
	Field       string      `json:"field"`        // Field to test
	Operator    string      `json:"operator"`     // Comparison operator
	Expected    interface{} `json:"expected"`     // Expected value
	Description string      `json:"description"`  // Assertion description
}

// Constraint represents a general constraint type
type Constraint struct {
	Type        string                 `json:"type"`         // Constraint type
	Expression  string                 `json:"expression"`   // Constraint expression
	Message     string                 `json:"message"`      // Error message
	Severity    string                 `json:"severity"`     // Constraint severity
	Parameters  map[string]interface{} `json:"parameters"`   // Constraint parameters
}

// ConditionExample represents an example of a condition
type ConditionExample struct {
	Description string                 `json:"description"`  // Example description
	Parameters  map[string]interface{} `json:"parameters"`   // Parameter values
	Input       map[string]interface{} `json:"input"`        // Example input
	Expected    bool                   `json:"expected"`     // Expected result
	Context     string                 `json:"context"`      // Example context
}

// TemplateInstantiationRequest represents a request to instantiate a template
type TemplateInstantiationRequest struct {
	TemplateID      string                 `json:"template_id"`       // Template to instantiate
	Name            string                 `json:"name"`              // Policy name
	Parameters      map[string]interface{} `json:"parameters"`        // Parameter values
	Scope           *PolicyScope           `json:"scope"`             // Policy scope
	Priority        *int                   `json:"priority"`          // Policy priority
	Category        string                 `json:"category"`          // Policy category
	Tags            []string               `json:"tags"`              // Policy tags
	Owner           string                 `json:"owner"`             // Policy owner
	Validate        bool                   `json:"validate"`          // Whether to validate
	DryRun          bool                   `json:"dry_run"`           // Whether dry run
	TestCases       []string               `json:"test_cases"`        // Test cases to run
	Metadata        map[string]interface{} `json:"metadata"`          // Additional metadata
}

// TemplateInstantiationResult represents the result of template instantiation
type TemplateInstantiationResult struct {
	Success         bool                      `json:"success"`           // Whether successful
	Policy          *Policy                   `json:"policy"`            // Generated policy
	ValidationResult *PolicyValidationResult  `json:"validation_result"` // Validation result
	TestResults     []TemplateTestResult      `json:"test_results"`      // Test results
	Warnings        []string                  `json:"warnings"`          // Warnings
	Errors          []string                  `json:"errors"`            // Errors
	Recommendations []string                  `json:"recommendations"`   // Recommendations
	ExecutionTime   time.Duration             `json:"execution_time"`    // Execution time
	Metadata        map[string]interface{}    `json:"metadata"`          // Result metadata
}

// TemplateTestResult represents the result of a template test
type TemplateTestResult struct {
	TestCaseID      string                 `json:"test_case_id"`      // Test case ID
	Name            string                 `json:"name"`              // Test name
	Passed          bool                   `json:"passed"`            // Whether passed
	Results         []AssertionResult      `json:"results"`           // Assertion results
	ExecutionTime   time.Duration          `json:"execution_time"`    // Execution time
	Error           string                 `json:"error,omitempty"`   // Error message
	Details         map[string]interface{} `json:"details"`           // Additional details
}

// AssertionResult represents the result of a test assertion
type AssertionResult struct {
	Assertion   TestAssertion   `json:"assertion"`    // The assertion
	Passed      bool            `json:"passed"`       // Whether passed
	Actual      interface{}     `json:"actual"`       // Actual value
	Expected    interface{}     `json:"expected"`     // Expected value
	Message     string          `json:"message"`      // Result message
	Details     string          `json:"details"`      // Additional details
}

// PolicyTemplateManagerInterface defines the interface for template management
type PolicyTemplateManagerInterface interface {
	// Template CRUD operations
	CreateTemplate(template *PolicyTemplate) error
	GetTemplate(templateID string) (*PolicyTemplate, error)
	UpdateTemplate(template *PolicyTemplate) error
	DeleteTemplate(templateID string) error
	ListTemplates(filters *TemplateListFilters) ([]*PolicyTemplate, error)
	
	// Template categories and discovery
	GetTemplatesByCategory(category TemplateCategory) ([]*PolicyTemplate, error)
	SearchTemplates(query string, filters *TemplateSearchFilters) ([]*PolicyTemplate, error)
	GetTemplateRecommendations(context *TemplateRecommendationContext) ([]*PolicyTemplate, error)
	
	// Template instantiation
	InstantiateTemplate(request *TemplateInstantiationRequest) (*TemplateInstantiationResult, error)
	ValidateTemplateParameters(templateID string, parameters map[string]interface{}) (*ParameterValidationResult, error)
	PreviewTemplateInstantiation(request *TemplateInstantiationRequest) (*Policy, error)
	
	// Template testing and validation
	TestTemplate(templateID string, testCases []string) ([]TemplateTestResult, error)
	ValidateTemplate(template *PolicyTemplate) (*TemplateValidationResult, error)
	CheckTemplateCompatibility(templateID string, platformVersion string) (*CompatibilityCheckResult, error)
	
	// Template import/export
	ExportTemplate(templateID string, format string) ([]byte, error)
	ImportTemplate(data []byte, format string) (*PolicyTemplate, error)
	ExportTemplateBundle(templateIDs []string, format string) ([]byte, error)
	ImportTemplateBundle(data []byte, format string) ([]*PolicyTemplate, error)
	
	// Template metrics and analytics
	GetTemplateUsageMetrics(templateID string) (*TemplateUsageMetrics, error)
	GetTemplateSuccessRate(templateID string) (float64, error)
	UpdateTemplateRating(templateID string, rating float64) error
	
	// Template versioning
	CreateTemplateVersion(templateID string, changes []TemplateChange) (*PolicyTemplate, error)
	GetTemplateVersions(templateID string) ([]*PolicyTemplate, error)
	CompareTemplateVersions(version1ID, version2ID string) (*TemplateVersionComparison, error)
	
	// Template collections and packages
	CreateTemplateCollection(collection *TemplateCollection) error
	GetTemplateCollection(collectionID string) (*TemplateCollection, error)
	ListTemplateCollections() ([]*TemplateCollection, error)
}

// TemplateListFilters represents filters for listing templates
type TemplateListFilters struct {
	Categories        []TemplateCategory   `json:"categories,omitempty"`
	Status            []TemplateStatus     `json:"status,omitempty"`
	Maturity          []TemplateMaturity   `json:"maturity,omitempty"`
	SupportLevel      []TemplateSupportLevel `json:"support_level,omitempty"`
	Tags              []string             `json:"tags,omitempty"`
	Author            string               `json:"author,omitempty"`
	Organization      string               `json:"organization,omitempty"`
	MinRating         *float64             `json:"min_rating,omitempty"`
	CreatedAfter      *time.Time           `json:"created_after,omitempty"`
	CreatedBefore     *time.Time           `json:"created_before,omitempty"`
	UpdatedAfter      *time.Time           `json:"updated_after,omitempty"`
	UpdatedBefore     *time.Time           `json:"updated_before,omitempty"`
	Limit             int                  `json:"limit,omitempty"`
	Offset            int                  `json:"offset,omitempty"`
	SortBy            string               `json:"sort_by,omitempty"`
	SortOrder         string               `json:"sort_order,omitempty"`
}

// TemplateSearchFilters represents filters for searching templates
type TemplateSearchFilters struct {
	TemplateListFilters
	FullTextSearch    bool     `json:"full_text_search"`
	SearchFields      []string `json:"search_fields,omitempty"`
	BoostFields       map[string]float64 `json:"boost_fields,omitempty"`
	FuzzySearch       bool     `json:"fuzzy_search"`
	MinScore          float64  `json:"min_score"`
}

// TemplateRecommendationContext represents context for template recommendations
type TemplateRecommendationContext struct {
	Organization        string                 `json:"organization"`
	Industry            string                 `json:"industry"`
	ComplianceFrameworks []string              `json:"compliance_frameworks"`
	UseCase             string                 `json:"use_case"`
	SecurityRequirements []string              `json:"security_requirements"`
	ExistingPolicies    []string              `json:"existing_policies"`
	PlatformVersion     string                `json:"platform_version"`
	UserRole            string                `json:"user_role"`
	Experience          string                `json:"experience"`
	Preferences         map[string]interface{} `json:"preferences"`
}

// ParameterValidationResult represents parameter validation result
type ParameterValidationResult struct {
	Valid           bool                    `json:"valid"`
	Errors          []ParameterValidationError `json:"errors,omitempty"`
	Warnings        []ParameterValidationWarning `json:"warnings,omitempty"`
	Suggestions     []ParameterSuggestion   `json:"suggestions,omitempty"`
	ComputedValues  map[string]interface{}  `json:"computed_values,omitempty"`
}

// ParameterValidationError represents a parameter validation error
type ParameterValidationError struct {
	Parameter   string `json:"parameter"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// ParameterValidationWarning represents a parameter validation warning
type ParameterValidationWarning struct {
	Parameter   string `json:"parameter"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// ParameterSuggestion represents a parameter suggestion
type ParameterSuggestion struct {
	Parameter   string      `json:"parameter"`
	Suggestion  string      `json:"suggestion"`
	Value       interface{} `json:"value,omitempty"`
	Reason      string      `json:"reason"`
}

// TemplateValidationResult represents template validation result
type TemplateValidationResult struct {
	Valid               bool                      `json:"valid"`
	TemplateErrors      []TemplateValidationError `json:"template_errors,omitempty"`
	ParameterErrors     []ParameterValidationError `json:"parameter_errors,omitempty"`
	SchemaErrors        []SchemaValidationError   `json:"schema_errors,omitempty"`
	CompatibilityIssues []CompatibilityIssue      `json:"compatibility_issues,omitempty"`
	Warnings            []string                  `json:"warnings,omitempty"`
	Suggestions         []string                  `json:"suggestions,omitempty"`
	TestResults         []TemplateTestResult      `json:"test_results,omitempty"`
}

// TemplateValidationError represents a template validation error
type TemplateValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// SchemaValidationError represents a schema validation error
type SchemaValidationError struct {
	SchemaPath  string `json:"schema_path"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
}

// CompatibilityIssue represents a compatibility issue
type CompatibilityIssue struct {
	Component   string `json:"component"`
	Issue       string `json:"issue"`
	Severity    string `json:"severity"`
	Workaround  string `json:"workaround,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

// CompatibilityCheckResult represents compatibility check result
type CompatibilityCheckResult struct {
	Compatible      bool                  `json:"compatible"`
	PlatformVersion string                `json:"platform_version"`
	Issues          []CompatibilityIssue  `json:"issues,omitempty"`
	MissingFeatures []string              `json:"missing_features,omitempty"`
	Recommendations []string              `json:"recommendations,omitempty"`
	UpgradeRequired bool                  `json:"upgrade_required"`
	MinimumVersion  string                `json:"minimum_version,omitempty"`
}

// TemplateUsageMetrics represents usage metrics for a template
type TemplateUsageMetrics struct {
	TemplateID        string                `json:"template_id"`
	TotalUsage        int64                 `json:"total_usage"`
	MonthlyUsage      int64                 `json:"monthly_usage"`
	WeeklyUsage       int64                 `json:"weekly_usage"`
	DailyUsage        int64                 `json:"daily_usage"`
	UniqueUsers       int64                 `json:"unique_users"`
	SuccessfulDeploys int64                 `json:"successful_deploys"`
	FailedDeploys     int64                 `json:"failed_deploys"`
	SuccessRate       float64               `json:"success_rate"`
	AverageRating     float64               `json:"average_rating"`
	UsageTrends       []TemplateUsageTrend  `json:"usage_trends"`
	TopParameters     []ParameterUsageStats `json:"top_parameters"`
	UserSegments      []UserSegmentStats    `json:"user_segments"`
	LastUsed          *time.Time            `json:"last_used,omitempty"`
}

// TemplateUsageTrend represents usage trend data
type TemplateUsageTrend struct {
	Timestamp   time.Time `json:"timestamp"`
	Usage       int64     `json:"usage"`
	UniqueUsers int       `json:"unique_users"`
	SuccessRate float64   `json:"success_rate"`
}

// ParameterUsageStats represents parameter usage statistics
type ParameterUsageStats struct {
	Parameter       string                 `json:"parameter"`
	UsageCount      int64                  `json:"usage_count"`
	UniqueValues    int                    `json:"unique_values"`
	TopValues       []ParameterValueStats  `json:"top_values"`
	AverageValue    interface{}            `json:"average_value,omitempty"`
	ValidationErrors int64                 `json:"validation_errors"`
}

// ParameterValueStats represents statistics for parameter values
type ParameterValueStats struct {
	Value interface{} `json:"value"`
	Count int64       `json:"count"`
	Percentage float64 `json:"percentage"`
}

// UserSegmentStats represents user segment statistics
type UserSegmentStats struct {
	Segment     string  `json:"segment"`
	UserCount   int     `json:"user_count"`
	Usage       int64   `json:"usage"`
	SuccessRate float64 `json:"success_rate"`
}

// TemplateChange represents a change in a template version
type TemplateChange struct {
	Type        string      `json:"type"`         // Change type
	Field       string      `json:"field"`        // Changed field
	OldValue    interface{} `json:"old_value"`    // Previous value
	NewValue    interface{} `json:"new_value"`    // New value
	Description string      `json:"description"`  // Change description
	Impact      string      `json:"impact"`       // Change impact
}

// TemplateVersionComparison represents comparison between template versions
type TemplateVersionComparison struct {
	Version1        string                   `json:"version1"`
	Version2        string                   `json:"version2"`
	Changes         []TemplateChange         `json:"changes"`
	Summary         TemplateComparisonSummary `json:"summary"`
	ImpactAnalysis  string                   `json:"impact_analysis"`
	Recommendations []string                 `json:"recommendations"`
}

// TemplateComparisonSummary represents summary of template comparison
type TemplateComparisonSummary struct {
	TotalChanges        int                  `json:"total_changes"`
	ChangesByType       map[string]int       `json:"changes_by_type"`
	BreakingChanges     int                  `json:"breaking_changes"`
	NewFeatures         int                  `json:"new_features"`
	BugFixes            int                  `json:"bug_fixes"`
	ParameterChanges    int                  `json:"parameter_changes"`
	BackwardCompatible  bool                 `json:"backward_compatible"`
	UpgradeComplexity   string               `json:"upgrade_complexity"`
}

// TemplateCollection represents a collection of related templates
type TemplateCollection struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Category        string                 `json:"category"`
	Templates       []string               `json:"templates"`        // Template IDs
	Dependencies    []string               `json:"dependencies"`     // Collection dependencies
	Prerequisites   []string               `json:"prerequisites"`    // Prerequisites
	InstallOrder    []string               `json:"install_order"`    // Installation order
	Author          string                 `json:"author"`
	Version         string                 `json:"version"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Tags            []string               `json:"tags"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ===== REAL-TIME ALERT SYSTEM =====

// AlertType represents different types of alerts
type AlertType string

const (
	AlertTypePolicyViolation    AlertType = "policy_violation"
	AlertTypeSecurityIncident   AlertType = "security_incident"
	AlertTypePerformanceDegraded AlertType = "performance_degraded"
	AlertTypeSystemError        AlertType = "system_error"
	AlertTypeQuotaExceeded      AlertType = "quota_exceeded"
	AlertTypeAuthFailure        AlertType = "auth_failure"
	AlertTypeDataBreach         AlertType = "data_breach"
	AlertTypeRateLimitExceeded  AlertType = "rate_limit_exceeded"
	AlertTypeTenantIssue        AlertType = "tenant_issue"
	AlertTypeHealthCheck        AlertType = "health_check"
	AlertTypeConfigChange       AlertType = "config_change"
	AlertTypeProviderFailure    AlertType = "provider_failure"
)

// AlertSeverity represents alert severity levels
type AlertSeverity string

const (
	AlertSeverityCritical AlertSeverity = "critical"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityInfo     AlertSeverity = "info"
)

// AlertStatus represents the current status of an alert
type AlertStatus string

const (
	AlertStatusActive       AlertStatus = "active"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusSuppressed   AlertStatus = "suppressed"
	AlertStatusEscalated    AlertStatus = "escalated"
)

// NotificationChannel represents different notification channels
type NotificationChannel string

const (
	NotificationChannelEmail    NotificationChannel = "email"
	NotificationChannelWebhook  NotificationChannel = "webhook"
	NotificationChannelSlack    NotificationChannel = "slack"
	NotificationChannelSMS      NotificationChannel = "sms"
	NotificationChannelPagerDuty NotificationChannel = "pagerduty"
	NotificationChannelMSTeams  NotificationChannel = "msteams"
	NotificationChannelDiscord  NotificationChannel = "discord"
)

// Alert represents a system alert
type Alert struct {
	ID          string                 `json:"id"`
	Type        AlertType              `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	Status      AlertStatus            `json:"status"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Tags        map[string]string      `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	
	// Timing information
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	FirstOccurredAt time.Time  `json:"first_occurred_at"`
	LastOccurredAt  time.Time  `json:"last_occurred_at"`
	
	// Escalation information
	EscalationLevel int         `json:"escalation_level"`
	EscalatedAt     *time.Time  `json:"escalated_at,omitempty"`
	NextEscalation  *time.Time  `json:"next_escalation,omitempty"`
	
	// Tracking information
	OccurrenceCount int    `json:"occurrence_count"`
	AcknowledgedBy  string `json:"acknowledged_by,omitempty"`
	ResolvedBy      string `json:"resolved_by,omitempty"`
	AssignedTo      string `json:"assigned_to,omitempty"`
	
	// Related information
	RelatedAlerts   []string               `json:"related_alerts,omitempty"`
	TenantID        string                 `json:"tenant_id,omitempty"`
	PolicyID        string                 `json:"policy_id,omitempty"`
	AuditEventID    string                 `json:"audit_event_id,omitempty"`
	CorrelationID   string                 `json:"correlation_id,omitempty"`
	
	// Notification tracking
	NotificationsSent []NotificationRecord `json:"notifications_sent,omitempty"`
}

// NotificationRecord tracks sent notifications
type NotificationRecord struct {
	Channel     NotificationChannel `json:"channel"`
	Recipient   string              `json:"recipient"`
	SentAt      time.Time           `json:"sent_at"`
	Status      string              `json:"status"` // sent, failed, pending
	AttemptNumber int               `json:"attempt_number"`
	ErrorMessage  string            `json:"error_message,omitempty"`
}

// AlertRule defines rules for generating alerts
type AlertRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Type        AlertType              `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	
	// Conditions
	Conditions    AlertConditions        `json:"conditions"`
	Tags          map[string]string      `json:"tags"`
	TenantScope   []string               `json:"tenant_scope,omitempty"`   // Empty = all tenants
	
	// Timing configuration
	EvaluationInterval   time.Duration `json:"evaluation_interval"`
	SuppressRepeats      bool          `json:"suppress_repeats"`
	SuppressionWindow    time.Duration `json:"suppression_window"`
	AutoResolveTimeout   time.Duration `json:"auto_resolve_timeout"`
	
	// Escalation configuration
	EscalationEnabled    bool                    `json:"escalation_enabled"`
	EscalationLevels     []AlertEscalationLevel  `json:"escalation_levels"`
	
	// Notification configuration
	NotificationChannels []NotificationConfig    `json:"notification_channels"`
	
	// Metadata
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	CreatedBy    string    `json:"created_by"`
	LastModified string    `json:"last_modified"`
}

// AlertConditions defines conditions for triggering alerts
type AlertConditions struct {
	// Event-based conditions
	EventType        string                 `json:"event_type,omitempty"`
	EventSeverity    string                 `json:"event_severity,omitempty"`
	EventSource      string                 `json:"event_source,omitempty"`
	EventTags        map[string]string      `json:"event_tags,omitempty"`
	
	// Metric-based conditions
	MetricName       string                 `json:"metric_name,omitempty"`
	MetricThreshold  float64                `json:"metric_threshold,omitempty"`
	ComparisonOp     string                 `json:"comparison_op,omitempty"` // gt, lt, eq, gte, lte
	MetricWindow     time.Duration          `json:"metric_window,omitempty"`
	
	// Pattern-based conditions
	MessagePattern   string                 `json:"message_pattern,omitempty"`
	TitlePattern     string                 `json:"title_pattern,omitempty"`
	
	// Frequency conditions
	MinOccurrences   int                    `json:"min_occurrences,omitempty"`
	TimeWindow       time.Duration          `json:"time_window,omitempty"`
	
	// Complex conditions
	CustomCondition  string                 `json:"custom_condition,omitempty"` // CEL expression
	Dependencies     []string               `json:"dependencies,omitempty"`     // Other rule IDs
	
	// Context conditions
	BusinessHours    bool                   `json:"business_hours,omitempty"`
	WeekdaysOnly     bool                   `json:"weekdays_only,omitempty"`
	ExcludedTimeRanges []TimeRange          `json:"excluded_time_ranges,omitempty"`
}

// TimeRange represents a time range for scheduling
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// AlertEscalationLevel defines escalation configuration
type AlertEscalationLevel struct {
	Level               int                 `json:"level"`
	DelayFromPrevious   time.Duration       `json:"delay_from_previous"`
	NotificationChannels []NotificationConfig `json:"notification_channels"`
	RequiredAcknowledgment bool             `json:"required_acknowledgment"`
	AutoEscalate        bool                `json:"auto_escalate"`
	EscalationMessage   string              `json:"escalation_message"`
}

// NotificationConfig defines notification channel configuration
type NotificationConfig struct {
	Channel     NotificationChannel    `json:"channel"`
	Enabled     bool                   `json:"enabled"`
	Recipients  []string               `json:"recipients"`
	Template    string                 `json:"template,omitempty"`
	Config      map[string]interface{} `json:"config,omitempty"`
	
	// Rate limiting
	RateLimit    int           `json:"rate_limit,omitempty"`    // Max notifications per period
	RatePeriod   time.Duration `json:"rate_period,omitempty"`   // Rate limiting period
	
	// Retry configuration
	MaxRetries   int           `json:"max_retries,omitempty"`
	RetryDelay   time.Duration `json:"retry_delay,omitempty"`
	
	// Filtering
	SeverityFilter []AlertSeverity `json:"severity_filter,omitempty"`
	TypeFilter     []AlertType     `json:"type_filter,omitempty"`
}

// AlertAggregationRule defines how to aggregate similar alerts
type AlertAggregationRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	
	// Grouping criteria
	GroupByFields   []string          `json:"group_by_fields"`
	GroupByTags     []string          `json:"group_by_tags"`
	
	// Aggregation settings
	TimeWindow      time.Duration     `json:"time_window"`
	MaxAlerts       int               `json:"max_alerts"`
	AggregateTitle  string            `json:"aggregate_title"`
	AggregateDescription string       `json:"aggregate_description"`
	
	// Conditions
	ApplyToTypes    []AlertType       `json:"apply_to_types"`
	ApplyToSeverities []AlertSeverity `json:"apply_to_severities"`
	
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// AlertSuppression defines alert suppression rules
type AlertSuppression struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	
	// Suppression criteria
	AlertTypes      []AlertType       `json:"alert_types,omitempty"`
	AlertSeverities []AlertSeverity   `json:"alert_severities,omitempty"`
	Sources         []string          `json:"sources,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	TenantIDs       []string          `json:"tenant_ids,omitempty"`
	
	// Time-based suppression
	Schedule        AlertSchedule     `json:"schedule,omitempty"`
	
	// Conditions
	Conditions      AlertConditions   `json:"conditions,omitempty"`
	
	// Metadata
	Reason          string            `json:"reason"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	CreatedBy       string            `json:"created_by"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
}

// AlertSchedule defines time-based scheduling
type AlertSchedule struct {
	TimeZone        string      `json:"timezone"`
	DaysOfWeek      []int       `json:"days_of_week"`      // 0=Sunday, 1=Monday, etc.
	StartTime       string      `json:"start_time"`        // HH:MM format
	EndTime         string      `json:"end_time"`          // HH:MM format
	ExcludedDates   []time.Time `json:"excluded_dates,omitempty"`
	IncludedDates   []time.Time `json:"included_dates,omitempty"`
}

// AlertMetrics contains alert system metrics
type AlertMetrics struct {
	TotalAlerts         int64                        `json:"total_alerts"`
	ActiveAlerts        int64                        `json:"active_alerts"`
	ResolvedAlerts      int64                        `json:"resolved_alerts"`
	AcknowledgedAlerts  int64                        `json:"acknowledged_alerts"`
	EscalatedAlerts     int64                        `json:"escalated_alerts"`
	SuppressedAlerts    int64                        `json:"suppressed_alerts"`
	
	// By severity
	AlertsBySeverity    map[AlertSeverity]int64      `json:"alerts_by_severity"`
	
	// By type
	AlertsByType        map[AlertType]int64          `json:"alerts_by_type"`
	
	// Timing metrics
	AverageResponseTime time.Duration                `json:"average_response_time"`
	AverageResolutionTime time.Duration              `json:"average_resolution_time"`
	MedianResponseTime  time.Duration                `json:"median_response_time"`
	MedianResolutionTime time.Duration               `json:"median_resolution_time"`
	
	// Notification metrics
	NotificationsSent   int64                        `json:"notifications_sent"`
	NotificationsFailed int64                        `json:"notifications_failed"`
	NotificationsByChannel map[NotificationChannel]int64 `json:"notifications_by_channel"`
	
	// Performance metrics
	AlertProcessingLatency time.Duration             `json:"alert_processing_latency"`
	RuleEvaluationLatency  time.Duration             `json:"rule_evaluation_latency"`
	
	// Health metrics
	LastUpdate          time.Time                    `json:"last_update"`
	SystemHealth        string                       `json:"system_health"`
	QueueDepth          int                          `json:"queue_depth"`
	ProcessingErrors    int64                        `json:"processing_errors"`
}

// AlertStatistics provides detailed alert statistics
type AlertStatistics struct {
	Period              string                       `json:"period"`
	GeneratedAt         time.Time                    `json:"generated_at"`
	
	// Overview stats
	TotalAlerts         int                          `json:"total_alerts"`
	NewAlerts           int                          `json:"new_alerts"`
	ResolvedAlerts      int                          `json:"resolved_alerts"`
	OngoingAlerts       int                          `json:"ongoing_alerts"`
	
	// Response time analytics
	AverageAckTime      time.Duration                `json:"average_ack_time"`
	AverageResolutionTime time.Duration              `json:"average_resolution_time"`
	P95AckTime          time.Duration                `json:"p95_ack_time"`
	P95ResolutionTime   time.Duration                `json:"p95_resolution_time"`
	
	// Distribution analytics
	AlertsByHour        map[int]int                  `json:"alerts_by_hour"`
	AlertsByDay         map[string]int               `json:"alerts_by_day"`
	AlertsBySeverity    map[AlertSeverity]int        `json:"alerts_by_severity"`
	AlertsByType        map[AlertType]int            `json:"alerts_by_type"`
	AlertsBySource      map[string]int               `json:"alerts_by_source"`
	AlertsByTenant      map[string]int               `json:"alerts_by_tenant"`
	
	// Top issues
	TopAlertTypes       []AlertTypeCount             `json:"top_alert_types"`
	TopAlertSources     []AlertSourceCount           `json:"top_alert_sources"`
	MostActiveRules     []AlertRuleStats             `json:"most_active_rules"`
	
	// SLA metrics
	SLACompliance       float64                      `json:"sla_compliance"`
	TargetAckTime       time.Duration                `json:"target_ack_time"`
	TargetResolutionTime time.Duration               `json:"target_resolution_time"`
	
	// Trend analysis
	AlertTrend          string                       `json:"alert_trend"` // increasing, decreasing, stable
	TrendPercentage     float64                      `json:"trend_percentage"`
	
	// Escalation stats
	EscalatedAlerts     int                          `json:"escalated_alerts"`
	EscalationRate      float64                      `json:"escalation_rate"`
	AvgEscalationTime   time.Duration                `json:"avg_escalation_time"`
}

// AlertTypeCount represents alert count by type
type AlertTypeCount struct {
	Type  AlertType `json:"type"`
	Count int       `json:"count"`
}

// AlertSourceCount represents alert count by source
type AlertSourceCount struct {
	Source string `json:"source"`
	Count  int    `json:"count"`
}

// AlertRuleStats represents statistics for an alert rule
type AlertRuleStats struct {
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	AlertCount  int       `json:"alert_count"`
	LastTriggered time.Time `json:"last_triggered"`
	AvgSeverity string    `json:"avg_severity"`
}

// AlertContextData provides additional context for alerts
type AlertContextData struct {
	SystemState         map[string]interface{} `json:"system_state,omitempty"`
	RelatedEvents       []string               `json:"related_events,omitempty"`
	RecentChanges       []string               `json:"recent_changes,omitempty"`
	AffectedResources   []string               `json:"affected_resources,omitempty"`
	SimilarAlerts       []string               `json:"similar_alerts,omitempty"`
	RecommendedActions  []string               `json:"recommended_actions,omitempty"`
	DocumentationLinks  []string               `json:"documentation_links,omitempty"`
	EscalationContacts  []string               `json:"escalation_contacts,omitempty"`
}

// AlertManager interface defines alert management operations
type AlertManager interface {
	// Alert lifecycle
	CreateAlert(alert *Alert) error
	UpdateAlert(alertID string, updates map[string]interface{}) error
	AcknowledgeAlert(alertID, acknowledgedBy string) error
	ResolveAlert(alertID, resolvedBy, resolution string) error
	EscalateAlert(alertID string) error
	SuppressAlert(alertID string, duration time.Duration, reason string) error
	
	// Alert retrieval
	GetAlert(alertID string) (*Alert, error)
	ListAlerts(filters AlertFilters) ([]*Alert, error)
	GetActiveAlerts() ([]*Alert, error)
	GetAlertsByTenant(tenantID string) ([]*Alert, error)
	GetAlertsByType(alertType AlertType) ([]*Alert, error)
	GetAlertsBySeverity(severity AlertSeverity) ([]*Alert, error)
	
	// Alert rules management
	CreateAlertRule(rule *AlertRule) error
	UpdateAlertRule(ruleID string, rule *AlertRule) error
	DeleteAlertRule(ruleID string) error
	GetAlertRule(ruleID string) (*AlertRule, error)
	ListAlertRules() ([]*AlertRule, error)
	EnableAlertRule(ruleID string) error
	DisableAlertRule(ruleID string) error
	
	// Alert aggregation
	CreateAggregationRule(rule *AlertAggregationRule) error
	UpdateAggregationRule(ruleID string, rule *AlertAggregationRule) error
	DeleteAggregationRule(ruleID string) error
	ListAggregationRules() ([]*AlertAggregationRule, error)
	
	// Alert suppression
	CreateSuppression(suppression *AlertSuppression) error
	UpdateSuppression(suppressionID string, suppression *AlertSuppression) error
	DeleteSuppression(suppressionID string) error
	ListSuppressions() ([]*AlertSuppression, error)
	
	// Notification management
	SendNotification(alert *Alert, channel NotificationChannel, recipients []string) error
	GetNotificationHistory(alertID string) ([]NotificationRecord, error)
	TestNotificationChannel(channel NotificationChannel, config NotificationConfig) error
	
	// Analytics and reporting
	GetAlertMetrics() (*AlertMetrics, error)
	GetAlertStatistics(period string) (*AlertStatistics, error)
	GetAlertTrends(duration time.Duration) (map[string]interface{}, error)
	
	// Real-time operations
	StartRealTimeProcessing() error
	StopRealTimeProcessing() error
	GetProcessingStatus() (map[string]interface{}, error)
	
	// Health and monitoring
	GetHealth() map[string]interface{}
	GetMetrics() map[string]interface{}
	
	// Shutdown
	Shutdown(ctx context.Context) error
}

// AlertFilters defines filters for alert queries
type AlertFilters struct {
	Types       []AlertType       `json:"types,omitempty"`
	Severities  []AlertSeverity   `json:"severities,omitempty"`
	Statuses    []AlertStatus     `json:"statuses,omitempty"`
	Sources     []string          `json:"sources,omitempty"`
	TenantIDs   []string          `json:"tenant_ids,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	
	// Time filters
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	UpdatedAfter  *time.Time `json:"updated_after,omitempty"`
	UpdatedBefore *time.Time `json:"updated_before,omitempty"`
	
	// Search filters
	SearchQuery   string `json:"search_query,omitempty"`
	TitleContains string `json:"title_contains,omitempty"`
	
	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
	
	// Sorting
	SortBy    string `json:"sort_by,omitempty"`    // created_at, updated_at, severity, etc.
	SortOrder string `json:"sort_order,omitempty"` // asc, desc
}

// NotificationProvider interface for different notification channels
type NotificationProvider interface {
	SendNotification(alert *Alert, config NotificationConfig) error
	ValidateConfig(config NotificationConfig) error
	GetSupportedFeatures() []string
	GetName() string
	HealthCheck() error
}

// ===== END REAL-TIME ALERT SYSTEM =====

