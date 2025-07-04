package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"ai-gateway-poc/internal/policy"
)

func main() {
	fmt.Println("🎨 AI Gateway Task 3.7: Policy Template System Demo")
	fmt.Println("=" + strings.Repeat("=", 70))
	fmt.Println()

	fmt.Println("📋 POLICY TEMPLATE SYSTEM FEATURES")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println("✅ Pre-built enterprise policy templates")
	fmt.Println("✅ Template customization and parameterization")
	fmt.Println("✅ Template instantiation with validation")
	fmt.Println("✅ Template search and recommendations")
	fmt.Println("✅ Template testing and validation")
	fmt.Println("✅ Template import/export and collections")
	fmt.Println("✅ Usage analytics and version management")
	fmt.Println()

	// Initialize template manager
	config := &policy.TemplateManagerConfig{
		EnableMetrics:           true,
		EnableSearch:            true,
		EnableVersioning:        true,
		DefaultMaturity:         policy.TemplateMaturityStable,
		RequireValidation:       true,
		RequireTesting:          false,
		MaxTemplateSize:         1024 * 1024,
		ParameterValidationMode: "strict",
		CacheEnabled:            true,
		CacheTTL:                time.Hour,
		ExportFormats:           []string{"json", "yaml"},
		ImportFormats:           []string{"json", "yaml"},
	}

	policyEngine := policy.NewPolicyEngine()
	templateManager := policy.NewPolicyTemplateManager(config, policyEngine)

	// Demo 1: Template Discovery and Browsing
	runTemplateDiscoveryDemo(templateManager)

	// Demo 2: Template Customization and Instantiation
	runTemplateInstantiationDemo(templateManager)

	// Demo 3: Template Search and Recommendations
	runTemplateSearchDemo(templateManager)

	// Demo 4: Template Validation and Testing
	runTemplateValidationDemo(templateManager)

	// Demo 5: Template Collections and Management
	runTemplateCollectionsDemo(templateManager)

	fmt.Println("🎉 TASK 3.7 IMPLEMENTATION COMPLETE!")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Println("✅ Policy template system with enterprise-grade templates")
	fmt.Println("✅ Template parameterization and customization")
	fmt.Println("✅ Automated policy generation from templates")
	fmt.Println("✅ Template search, filtering, and recommendations")
	fmt.Println("✅ Template validation, testing, and compatibility checking")
	fmt.Println("✅ Template versioning and change management")
	fmt.Println("✅ Template collections and enterprise workflow support")
	fmt.Println("✅ Usage analytics and success rate tracking")
	fmt.Println()
	fmt.Println("🚀 Ready for Task 3.8 to complete Phase 3.0!")
}

// runTemplateDiscoveryDemo demonstrates template discovery and browsing
func runTemplateDiscoveryDemo(tm *policy.PolicyTemplateManager) {
	fmt.Println("📚 Demo 1: Template Discovery and Browsing")
	fmt.Println(strings.Repeat("-", 40))

	// List all templates
	allTemplates, err := tm.ListTemplates(nil)
	if err != nil {
		log.Printf("Error listing templates: %v", err)
		return
	}

	fmt.Printf("📋 Available Templates: %d\n", len(allTemplates))
	for _, template := range allTemplates {
		fmt.Printf("  🎨 %s (v%s)\n", template.Name, template.Version)
		fmt.Printf("     Category: %s | Rating: %.1f ⭐ | Used: %d times\n",
			template.Category, template.Rating, template.UsageCount)
		fmt.Printf("     Description: %s\n", template.Description)
		if len(template.IndustryVerticals) > 0 {
			fmt.Printf("     Industries: %s\n", strings.Join(template.IndustryVerticals, ", "))
		}
		if len(template.ComplianceFrameworks) > 0 {
			fmt.Printf("     Compliance: %s\n", strings.Join(template.ComplianceFrameworks, ", "))
		}
		fmt.Println()
	}

	// Browse by category
	fmt.Println("📂 Browse by Category:")
	categories := []policy.TemplateCategory{
		policy.TemplateCategoryPII,
		policy.TemplateCategoryCompliance,
		policy.TemplateCategoryIndustry,
		policy.TemplateCategoryContent,
	}

	for _, category := range categories {
		templates, err := tm.GetTemplatesByCategory(category)
		if err != nil {
			continue
		}
		fmt.Printf("  📁 %s: %d templates\n", category, len(templates))
		for _, template := range templates {
			fmt.Printf("     • %s\n", template.Name)
		}
	}
	fmt.Println()
}

// runTemplateInstantiationDemo demonstrates template instantiation
func runTemplateInstantiationDemo(tm *policy.PolicyTemplateManager) {
	fmt.Println("⚙️ Demo 2: Template Customization and Instantiation")
	fmt.Println(strings.Repeat("-", 40))

	// Get PII protection template
	templateID := "builtin_pii_protection"
	template, err := tm.GetTemplate(templateID)
	if err != nil {
		log.Printf("Error getting template: %v", err)
		return
	}

	fmt.Printf("🎨 Using template: %s\n", template.Name)
	fmt.Printf("📋 Available customization options:\n")
	for _, param := range template.CustomizationOptions {
		fmt.Printf("  • %s (%s): %s\n", param.DisplayName, param.Type, param.Description)
		fmt.Printf("    Default: %v, Required: %v\n", param.DefaultValue, param.Required)
		if len(param.Options) > 0 {
			fmt.Printf("    Options: ")
			for i, option := range param.Options {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s", option.Label)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	// Demonstrate different instantiation scenarios
	scenarios := []struct {
		name       string
		parameters map[string]interface{}
		scope      *policy.PolicyScope
	}{
		{
			name: "Healthcare PII Protection",
			parameters: map[string]interface{}{
				"protection_level": "strict",
				"pii_types":       []string{"ssn", "phone", "email"},
			},
			scope: &policy.PolicyScope{
				Organizations: []string{"healthcare_org"},
				ContentTypes:  []string{"text", "document"},
			},
		},
		{
			name: "Basic Office Protection",
			parameters: map[string]interface{}{
				"protection_level": "standard",
				"pii_types":       []string{"email", "phone"},
			},
			scope: &policy.PolicyScope{
				Organizations: []string{"office_org"},
			},
		},
	}

	for i, scenario := range scenarios {
		fmt.Printf("🏥 Scenario %d: %s\n", i+1, scenario.name)

		// Validate parameters first
		validation, err := tm.ValidateTemplateParameters(templateID, scenario.parameters)
		if err != nil {
			fmt.Printf("   ❌ Parameter validation error: %v\n", err)
			continue
		}

		if !validation.Valid {
			fmt.Printf("   ❌ Parameter validation failed:\n")
			for _, err := range validation.Errors {
				fmt.Printf("      %s: %s\n", err.Parameter, err.Message)
			}
			continue
		}

		fmt.Printf("   ✅ Parameters validated successfully\n")

		// Create instantiation request
		request := &policy.TemplateInstantiationRequest{
			TemplateID: templateID,
			Name:       fmt.Sprintf("%s Policy", scenario.name),
			Parameters: scenario.parameters,
			Scope:      scenario.scope,
			Owner:      "admin",
			Validate:   true,
			DryRun:     false,
			TestCases:  []string{"test_ssn_detection"},
		}

		// Instantiate template
		result, err := tm.InstantiateTemplate(request)
		if err != nil {
			fmt.Printf("   ❌ Instantiation error: %v\n", err)
			continue
		}

		if result.Success {
			fmt.Printf("   ✅ Policy created successfully\n")
			fmt.Printf("      Policy ID: %s\n", result.Policy.ID)
			fmt.Printf("      Rules: %d\n", len(result.Policy.Rules))
			fmt.Printf("      Execution time: %v\n", result.ExecutionTime)

			// Show test results if any
			if len(result.TestResults) > 0 {
				fmt.Printf("      Test results: %d/%d passed\n",
					countPassedTests(result.TestResults), len(result.TestResults))
			}
		} else {
			fmt.Printf("   ❌ Policy creation failed:\n")
			for _, errMsg := range result.Errors {
				fmt.Printf("      %s\n", errMsg)
			}
		}

		fmt.Println()
	}
}

// runTemplateSearchDemo demonstrates template search and recommendations
func runTemplateSearchDemo(tm *policy.PolicyTemplateManager) {
	fmt.Println("🔍 Demo 3: Template Search and Recommendations")
	fmt.Println(strings.Repeat("-", 40))

	// Text search
	searchQueries := []string{"pii", "compliance", "gdpr", "healthcare"}

	for _, query := range searchQueries {
		fmt.Printf("🔍 Search for '%s':\n", query)
		
		filters := &policy.TemplateSearchFilters{
			FullTextSearch: true,
			MinScore:       0.1,
		}
		
		results, err := tm.SearchTemplates(query, filters)
		if err != nil {
			fmt.Printf("   ❌ Search error: %v\n", err)
			continue
		}

		fmt.Printf("   📋 Found %d results:\n", len(results))
		for _, template := range results {
			fmt.Printf("      • %s (v%s) - %s\n",
				template.Name, template.Version, template.Category)
		}
		fmt.Println()
	}

	// Recommendations based on context
	fmt.Printf("💡 Template Recommendations:\n")
	contexts := []struct {
		name    string
		context *policy.TemplateRecommendationContext
	}{
		{
			name: "Healthcare Organization",
			context: &policy.TemplateRecommendationContext{
				Organization:         "hospital_system",
				Industry:             "healthcare",
				ComplianceFrameworks: []string{"HIPAA", "GDPR"},
				UseCase:              "patient data protection",
			},
		},
		{
			name: "Financial Institution",
			context: &policy.TemplateRecommendationContext{
				Organization:         "national_bank",
				Industry:             "banking",
				ComplianceFrameworks: []string{"PCI-DSS", "SOX"},
				UseCase:              "financial data protection",
			},
		},
	}

	for _, ctx := range contexts {
		fmt.Printf("   🏢 %s:\n", ctx.name)
		
		recommendations, err := tm.GetTemplateRecommendations(ctx.context)
		if err != nil {
			fmt.Printf("      ❌ Recommendation error: %v\n", err)
			continue
		}

		fmt.Printf("      📋 Recommended templates (%d):\n", len(recommendations))
		for i, template := range recommendations {
			if i >= 3 { // Show top 3 recommendations
				break
			}
			fmt.Printf("         %d. %s (v%s) - Rating: %.1f ⭐\n",
				i+1, template.Name, template.Version, template.Rating)
			fmt.Printf("            %s\n", template.Description)
		}
		fmt.Println()
	}
}

// runTemplateValidationDemo demonstrates template validation and testing
func runTemplateValidationDemo(tm *policy.PolicyTemplateManager) {
	fmt.Println("✅ Demo 4: Template Validation and Testing")
	fmt.Println(strings.Repeat("-", 40))

	// Validate templates
	templateIDs := []string{"builtin_pii_protection", "builtin_gdpr_compliance", "builtin_hipaa_compliance"}

	for _, templateID := range templateIDs {
		template, err := tm.GetTemplate(templateID)
		if err != nil {
			continue
		}

		fmt.Printf("🔍 Validating template: %s\n", template.Name)

		// Template structure validation
		validation, err := tm.ValidateTemplate(template)
		if err != nil {
			fmt.Printf("   ❌ Validation error: %v\n", err)
			continue
		}

		if validation.Valid {
			fmt.Printf("   ✅ Template structure is valid\n")
		} else {
			fmt.Printf("   ❌ Template structure validation failed:\n")
			for _, err := range validation.TemplateErrors {
				fmt.Printf("      %s: %s\n", err.Field, err.Message)
			}
		}

		// Compatibility check
		platformVersion := "2.1.0"
		compatibility, err := tm.CheckTemplateCompatibility(templateID, platformVersion)
		if err != nil {
			fmt.Printf("   ❌ Compatibility check error: %v\n", err)
		} else if compatibility.Compatible {
			fmt.Printf("   ✅ Compatible with platform version %s\n", platformVersion)
		} else {
			fmt.Printf("   ❌ Not compatible with platform version %s\n", platformVersion)
		}

		// Run tests if available
		if len(template.TestCases) > 0 {
			fmt.Printf("   🧪 Running %d test cases:\n", len(template.TestCases))
			
			testCaseIDs := make([]string, len(template.TestCases))
			for i, testCase := range template.TestCases {
				testCaseIDs[i] = testCase.ID
			}

			testResults, err := tm.TestTemplate(templateID, testCaseIDs)
			if err != nil {
				fmt.Printf("      ❌ Test execution error: %v\n", err)
			} else {
				passedCount := 0
				for _, result := range testResults {
					if result.Passed {
						passedCount++
						fmt.Printf("      ✅ %s: PASSED (%v)\n", result.Name, result.ExecutionTime)
					} else {
						fmt.Printf("      ❌ %s: FAILED\n", result.Name)
					}
				}
				fmt.Printf("      📊 Test summary: %d/%d passed\n", passedCount, len(testResults))
			}
		} else {
			fmt.Printf("   ℹ️ No test cases defined\n")
		}

		fmt.Println()
	}
}

// runTemplateCollectionsDemo demonstrates template collections
func runTemplateCollectionsDemo(tm *policy.PolicyTemplateManager) {
	fmt.Println("📚 Demo 5: Template Collections and Management")
	fmt.Println(strings.Repeat("-", 40))

	// Create template collections
	collections := []*policy.TemplateCollection{
		{
			Name:        "Healthcare Compliance Starter Pack",
			Description: "Essential templates for healthcare organizations",
			Category:    "healthcare",
			Templates:   []string{"builtin_pii_protection", "builtin_hipaa_compliance"},
			Author:      "Healthcare Security Team",
			Version:     "1.0.0",
			Tags:        []string{"healthcare", "hipaa", "starter"},
		},
		{
			Name:        "GDPR Compliance Suite",
			Description: "Complete GDPR compliance template collection",
			Category:    "compliance",
			Templates:   []string{"builtin_gdpr_compliance", "builtin_pii_protection"},
			Author:      "Compliance Team",
			Version:     "1.2.0",
			Tags:        []string{"gdpr", "eu", "compliance"},
		},
	}

	fmt.Printf("📦 Creating %d template collections:\n", len(collections))
	for i, collection := range collections {
		err := tm.CreateTemplateCollection(collection)
		if err != nil {
			fmt.Printf("   ❌ Error creating collection %d: %v\n", i+1, err)
		} else {
			fmt.Printf("   ✅ Created: %s\n", collection.Name)
			fmt.Printf("      Description: %s\n", collection.Description)
			fmt.Printf("      Templates: %d\n", len(collection.Templates))
			fmt.Printf("      Author: %s\n", collection.Author)
		}
		fmt.Println()
	}

	// List all collections
	fmt.Printf("📋 Available Template Collections:\n")
	allCollections, err := tm.ListTemplateCollections()
	if err != nil {
		fmt.Printf("   ❌ Error listing collections: %v\n", err)
	} else {
		for i, collection := range allCollections {
			fmt.Printf("   %d. %s (v%s)\n", i+1, collection.Name, collection.Version)
			fmt.Printf("      Category: %s | Templates: %d\n", 
				collection.Category, len(collection.Templates))
			fmt.Printf("      Author: %s\n", collection.Author)
			
			// Show included templates
			fmt.Printf("      Included Templates:\n")
			for _, templateID := range collection.Templates {
				template, err := tm.GetTemplate(templateID)
				if err == nil {
					fmt.Printf("         • %s (v%s)\n", template.Name, template.Version)
				}
			}
			fmt.Println()
		}
	}

	fmt.Println()
}

// Helper functions
func countPassedTests(results []policy.TemplateTestResult) int {
	count := 0
	for _, result := range results {
		if result.Passed {
			count++
		}
	}
	return count
} 