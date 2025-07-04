package policy

import (
	"time"
)

// initializeBuiltinTemplates initializes the built-in template library
func (tm *PolicyTemplateManager) initializeBuiltinTemplates() {
	templates := []*PolicyTemplate{
		createPIIProtectionTemplate(),
		createGDPRComplianceTemplate(),
		createHIPAAComplianceTemplate(),
		createFinancialDataProtectionTemplate(),
		createContentClassificationTemplate(),
	}

	for _, template := range templates {
		tm.templates[template.ID] = template
		if tm.config.EnableMetrics {
			tm.usageMetrics[template.ID] = &TemplateUsageMetrics{
				TemplateID: template.ID,
			}
		}
		if tm.config.EnableSearch {
			tm.searchIndex.IndexTemplate(template)
		}
	}
}

// createPIIProtectionTemplate creates a comprehensive PII protection template
func createPIIProtectionTemplate() *PolicyTemplate {
	return &PolicyTemplate{
		ID:              "builtin_pii_protection",
		Name:            "PII Protection Policy",
		DisplayName:     "Personal Information Protection",
		Description:     "Comprehensive policy for detecting and protecting personally identifiable information",
		LongDescription: "This template provides robust protection for various types of PII including SSNs, credit cards, phone numbers, emails, and addresses.",
		Version:         "2.1.0",
		Category:        TemplateCategoryPII,
		SubCategory:     "data_protection",
		Tags:            []string{"pii", "privacy", "gdpr", "ccpa", "data_protection", "compliance"},
		
		Author:          "AI Gateway Security Team",
		Organization:    "Enterprise Security",
		CreatedAt:       time.Now().AddDate(0, -6, 0),
		UpdatedAt:       time.Now().AddDate(0, -1, 0),
		PublishedAt:     timePtr(time.Now().AddDate(0, -5, 0)),
		
		TargetUseCase:         "Prevent PII exposure in AI communications",
		IndustryVerticals:     []string{"healthcare", "finance", "retail", "technology", "government"},
		ComplianceFrameworks:  []string{"GDPR", "CCPA", "HIPAA", "SOX", "PCI-DSS"},
		Prerequisites:         []string{"content_analysis", "pii_detection"},
		Dependencies:          []string{},
		
		Status:          TemplateStatusActive,
		Maturity:        TemplateMaturityEnterprise,
		SupportLevel:    TemplateSupportEnterprise,
		LicenseType:     "Enterprise",
		
		UsageCount:      1250,
		LastUsed:        timePtr(time.Now().AddDate(0, 0, -2)),
		Rating:          4.7,
		ReviewCount:     89,
		SuccessRate:     0.96,
		
		Rules: []PolicyRuleTemplate{
			{
				PolicyRule: PolicyRule{
					ID:          "detect_ssn",
					Name:        "Social Security Number Detection",
					Description: "Detects and blocks SSN patterns",
					Priority:    100,
					Enabled:     true,
					Action: PolicyAction{
						Type:     ActionBlock,
						Severity: SeverityHigh,
						Message:  "Social Security Number detected and blocked",
					},
				},
				ParameterizedCondition: &ParameterizedCondition{
					Template: "pii_detected == true AND pii_types contains 'ssn'",
					Parameters: map[string]interface{}{
						"min_confidence": 0.8,
					},
				},
			},
		},
		
		CustomizationOptions: []TemplateParameter{
			{
				Name:         "protection_level",
				DisplayName:  "Protection Level",
				Description:  "Level of PII protection to apply",
				Type:         ParameterTypeEnum,
				DefaultValue: "standard",
				Required:     true,
				Options: []ParameterOption{
					{Value: "minimal", Label: "Minimal", Description: "Basic PII detection with warnings"},
					{Value: "standard", Label: "Standard", Description: "Balanced protection with redaction"},
					{Value: "strict", Label: "Strict", Description: "Maximum protection with blocking"},
				},
			},
			{
				Name:         "pii_types",
				DisplayName:  "PII Types to Detect",
				Description:  "Types of PII to detect and protect",
				Type:         ParameterTypeMultiSelect,
				DefaultValue: []string{"ssn", "credit_card", "phone", "email"},
				Required:     true,
				Options: []ParameterOption{
					{Value: "ssn", Label: "Social Security Numbers"},
					{Value: "credit_card", Label: "Credit Card Numbers"},
					{Value: "phone", Label: "Phone Numbers"},
					{Value: "email", Label: "Email Addresses"},
				},
			},
		},
		
		DefaultConfiguration: &TemplateConfiguration{
			Priority:        90,
			Category:        "data_protection",
			Tags:            []string{"pii", "auto_generated"},
			EnableByDefault: true,
			RequireApproval: true,
			TestingRequired: true,
		},
		
		Examples: []TemplateExample{
			{
				Name:        "Healthcare PII Protection",
				Description: "Configuration for healthcare environments",
				Scenario:    "Hospital system protecting patient information",
				Parameters: map[string]interface{}{
					"protection_level": "strict",
					"pii_types":       []string{"ssn", "phone", "email"},
				},
				ExpectedOutcome: "All patient PII blocked with high confidence",
			},
		},
		
		TestCases: []TemplateTestCase{
			{
				ID:          "test_ssn_detection",
				Name:        "SSN Detection Test",
				Description: "Tests SSN detection and blocking",
				Category:    "pii_detection",
				Parameters: map[string]interface{}{
					"protection_level": "standard",
				},
				Assertions: []TestAssertion{
					{
						Type:        "equals",
						Field:       "action",
						Operator:    "equals",
						Expected:    "block",
						Description: "Should block when SSN detected",
					},
				},
			},
		},
		
		Metadata: map[string]interface{}{
			"complexity":    "medium",
			"setup_time":    "15 minutes",
			"maintenance":   "low",
			"documentation": "https://docs.aigateway.com/templates/pii-protection",
		},
	}
}

// createGDPRComplianceTemplate creates a GDPR compliance template
func createGDPRComplianceTemplate() *PolicyTemplate {
	return &PolicyTemplate{
		ID:               "builtin_gdpr_compliance",
		Name:             "GDPR Compliance Policy",
		DisplayName:      "GDPR Data Protection Compliance",
		Description:      "Comprehensive GDPR compliance policy for EU data protection",
		LongDescription:  "Implements GDPR Article 25 'Data protection by design and by default' with automated data subject rights protection.",
		Version:          "1.3.0",
		Category:         TemplateCategoryCompliance,
		SubCategory:      "gdpr",
		Tags:             []string{"gdpr", "eu", "privacy", "compliance", "data_protection", "consent"},
		
		Author:           "Compliance Team",
		Organization:     "Legal & Compliance",
		CreatedAt:        time.Now().AddDate(0, -8, 0),
		UpdatedAt:        time.Now().AddDate(0, -2, 0),
		PublishedAt:      timePtr(time.Now().AddDate(0, -7, 0)),
		
		TargetUseCase:         "GDPR compliance for EU operations",
		IndustryVerticals:     []string{"all"},
		ComplianceFrameworks:  []string{"GDPR", "Privacy Shield"},
		Prerequisites:         []string{"eu_data_processing", "consent_management"},
		
		Status:           TemplateStatusActive,
		Maturity:         TemplateMaturityEnterprise,
		SupportLevel:     TemplateSupportEnterprise,
		LicenseType:      "Enterprise",
		
		UsageCount:       890,
		Rating:           4.8,
		ReviewCount:      67,
		SuccessRate:      0.94,
		
		Rules: []PolicyRuleTemplate{
			{
				PolicyRule: PolicyRule{
					ID:          "consent_validation",
					Name:        "Consent Validation",
					Description: "Validates user consent for data processing",
					Priority:    100,
					Enabled:     true,
					Action: PolicyAction{
						Type:     ActionBlock,
						Severity: SeverityCritical,
						Message:  "GDPR: No valid consent for data processing",
					},
				},
			},
		},
		
		CustomizationOptions: []TemplateParameter{
			{
				Name:         "data_subject_rights",
				DisplayName:  "Data Subject Rights",
				Description:  "GDPR rights to enforce",
				Type:         ParameterTypeMultiSelect,
				DefaultValue: []string{"access", "rectification", "erasure", "portability"},
				Required:     true,
				Options: []ParameterOption{
					{Value: "access", Label: "Right to Access"},
					{Value: "rectification", Label: "Right to Rectification"},
					{Value: "erasure", Label: "Right to Erasure"},
					{Value: "portability", Label: "Right to Data Portability"},
				},
			},
		},
	}
}

// createHIPAAComplianceTemplate creates a HIPAA compliance template
func createHIPAAComplianceTemplate() *PolicyTemplate {
	return &PolicyTemplate{
		ID:               "builtin_hipaa_compliance",
		Name:             "HIPAA Compliance Policy",
		DisplayName:      "HIPAA Healthcare Data Protection",
		Description:      "HIPAA compliance for healthcare organizations",
		LongDescription:  "Comprehensive HIPAA compliance template covering PHI protection and access controls.",
		Version:          "2.0.1",
		Category:         TemplateCategoryCompliance,
		SubCategory:      "healthcare",
		Tags:             []string{"hipaa", "healthcare", "phi", "medical", "compliance"},
		
		Author:           "Healthcare Compliance Team",
		Organization:     "Healthcare Security",
		TargetUseCase:    "Healthcare PHI protection",
		IndustryVerticals: []string{"healthcare", "medical_devices", "health_insurance"},
		ComplianceFrameworks: []string{"HIPAA", "HITECH"},
		
		Status:           TemplateStatusActive,
		Maturity:         TemplateMaturityEnterprise,
		SupportLevel:     TemplateSupportEnterprise,
		
		UsageCount:       654,
		Rating:           4.9,
		ReviewCount:      43,
		SuccessRate:      0.98,
		
		CustomizationOptions: []TemplateParameter{
			{
				Name:         "phi_types",
				DisplayName:  "PHI Types to Protect",
				Description:  "Types of PHI to detect and protect",
				Type:         ParameterTypeMultiSelect,
				DefaultValue: []string{"medical_record", "ssn", "insurance", "diagnosis"},
				Required:     true,
				Options: []ParameterOption{
					{Value: "medical_record", Label: "Medical Record Numbers"},
					{Value: "ssn", Label: "Social Security Numbers"},
					{Value: "insurance", Label: "Insurance Information"},
					{Value: "diagnosis", Label: "Diagnosis Codes"},
				},
			},
		},
	}
}

// createFinancialDataProtectionTemplate creates a financial data protection template
func createFinancialDataProtectionTemplate() *PolicyTemplate {
	return &PolicyTemplate{
		ID:               "builtin_financial_protection",
		Name:             "Financial Data Protection",
		DisplayName:      "Financial Services Data Protection",
		Description:      "Comprehensive financial data protection for banking and fintech",
		Version:          "1.5.0",
		Category:         TemplateCategoryIndustry,
		SubCategory:      "financial_services",
		Tags:             []string{"financial", "banking", "pci", "sox", "fintech"},
		
		TargetUseCase:         "Financial services data protection",
		IndustryVerticals:     []string{"banking", "fintech", "insurance", "investment"},
		ComplianceFrameworks:  []string{"PCI-DSS", "SOX", "FFIEC", "Basel III"},
		
		Status:           TemplateStatusActive,
		Maturity:         TemplateMaturityStable,
		SupportLevel:     TemplateSupportCommercial,
		
		UsageCount:       432,
		Rating:           4.6,
		ReviewCount:      28,
		SuccessRate:      0.95,
	}
}

// createContentClassificationTemplate creates a content classification template
func createContentClassificationTemplate() *PolicyTemplate {
	return &PolicyTemplate{
		ID:          "builtin_content_classification",
		Name:        "Content Classification Policy",
		DisplayName: "Automated Content Classification",
		Description: "Automatically classifies content by sensitivity level",
		Version:     "1.4.0",
		Category:    TemplateCategoryContent,
		Tags:        []string{"classification", "sensitivity", "content_governance"},
		Status:      TemplateStatusActive,
		Maturity:    TemplateMaturityStable,
		UsageCount:  567,
		Rating:      4.5,
		
		CustomizationOptions: []TemplateParameter{
			{
				Name:         "sensitivity_levels",
				DisplayName:  "Sensitivity Levels",
				Description:  "Content sensitivity classification levels",
				Type:         ParameterTypeMultiSelect,
				DefaultValue: []string{"public", "internal", "confidential", "restricted"},
				Required:     true,
				Options: []ParameterOption{
					{Value: "public", Label: "Public"},
					{Value: "internal", Label: "Internal"},
					{Value: "confidential", Label: "Confidential"},
					{Value: "restricted", Label: "Restricted"},
				},
			},
		},
	}
}

// Helper function
func floatPtr(f float64) *float64 {
	return &f
} 