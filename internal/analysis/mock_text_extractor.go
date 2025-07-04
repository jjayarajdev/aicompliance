package analysis

import (
	"context"
	"strings"
	"time"

	"ai-gateway-poc/internal/logging"
)

// MockTextExtractor implements TextExtractor for testing and demonstration
type MockTextExtractor struct {
	logger *logging.Logger
}

// GetSupportedTypes returns supported file types
func (e *MockTextExtractor) GetSupportedTypes() []string {
	return []string{
		"text/plain",
		"text/csv",
		"text/html",
		"application/pdf",
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"*", // Wildcard for demonstration
	}
}

// ExtractText extracts text from file data
func (e *MockTextExtractor) ExtractText(ctx context.Context, data []byte, filename string) (*TextExtractionResult, error) {
	start := time.Now()
	
	// Simulate processing time
	time.Sleep(time.Millisecond * 100)
	
	// Mock text extraction based on file type
	ext := strings.ToLower(getFileExtension(filename))
	extractedText := e.generateMockText(ext, len(data))
	
	// Calculate mock statistics
	wordCount := len(strings.Fields(extractedText))
	charCount := len(extractedText)
	
	result := &TextExtractionResult{
		ExtractedText:  extractedText,
		Extractor:      "mock",
		Confidence:     0.95,
		ProcessingTime: time.Since(start),
		WordCount:      wordCount,
		CharacterCount: charCount,
		Language:       "en",
		Metadata: map[string]interface{}{
			"file_extension": ext,
			"file_size":      len(data),
			"extraction_method": "mock_simulation",
		},
	}
	
	return result, nil
}

// IsHealthy returns the health status
func (e *MockTextExtractor) IsHealthy() bool {
	return true
}

// generateMockText generates realistic mock text based on file type
func (e *MockTextExtractor) generateMockText(extension string, fileSize int) string {
	switch extension {
	case ".pdf":
		return e.generatePDFText(fileSize)
	case ".doc", ".docx":
		return e.generateDocumentText(fileSize)
	case ".xls", ".xlsx":
		return e.generateSpreadsheetText(fileSize)
	case ".ppt", ".pptx":
		return e.generatePresentationText(fileSize)
	case ".txt":
		return e.generatePlainText(fileSize)
	case ".csv":
		return e.generateCSVText(fileSize)
	case ".html":
		return e.generateHTMLText(fileSize)
	default:
		return e.generateGenericText(fileSize)
	}
}

// generatePDFText generates mock PDF content
func (e *MockTextExtractor) generatePDFText(fileSize int) string {
	baseText := `CONFIDENTIAL BUSINESS REPORT

Executive Summary:
This quarterly financial report contains proprietary business information including revenue data, customer analytics, and strategic planning initiatives.

Financial Performance:
- Q3 Revenue: $15.2M (15% growth YoY)
- Customer Acquisition: 2,847 new clients
- Profit Margin: 28.5%

Key Metrics:
- Customer Satisfaction: 89%
- Employee Count: 1,247
- Market Share: 12.3%

Strategic Initiatives:
Our roadmap includes expansion into European markets and development of new AI-powered solutions. Patent applications filed for three innovative technologies.

Contact Information:
- CFO: sarah.johnson@company.com
- Phone: (555) 123-4567
- Legal: legal@company.com

CONFIDENTIAL - Internal Use Only`

	// Scale content based on file size
	if fileSize > 100000 { // Large file
		return baseText + "\n\n" + strings.Repeat("Additional detailed financial analysis and market research data. ", 50)
	} else if fileSize > 10000 { // Medium file
		return baseText + "\n\nAdditional quarterly data and performance metrics included."
	}
	return baseText
}

// generateDocumentText generates mock Word document content
func (e *MockTextExtractor) generateDocumentText(fileSize int) string {
	baseText := `Strategic Planning Document

Company Policy Update - Confidential

1. Introduction
This document outlines new strategic initiatives for the upcoming fiscal year.

2. Market Analysis
Customer data indicates strong growth potential in emerging markets. User analytics reveal engagement patterns across all demographic segments.

3. Financial Projections
Quarterly budget allocation:
- Marketing: $5M
- R&D: $8M
- Operations: $12M

4. Risk Assessment
Potential regulatory changes may impact compliance requirements. Legal review required for all new partnerships.

5. Team Structure
Project leads:
- John Smith (j.smith@company.com)
- Lisa Chen (l.chen@company.com)

This document contains proprietary information and trade secrets.`

	if fileSize > 50000 {
		return baseText + "\n\n" + strings.Repeat("Detailed implementation plans and technical specifications. ", 30)
	}
	return baseText
}

// generateSpreadsheetText generates mock Excel content
func (e *MockTextExtractor) generateSpreadsheetText(fileSize int) string {
	return `Customer Database - Restricted Access

Customer_ID,Name,Email,Revenue,Status
C001,TechCorp Inc,contact@techcorp.com,$250000,Active
C002,Global Solutions,info@globalsol.com,$180000,Active
C003,Innovation Labs,team@innovlabs.com,$320000,Pending

Financial Summary:
Total Revenue: $2,847,000
Customer Count: 147
Average Deal Size: $19,367

Quarterly Performance:
Q1: $680K
Q2: $720K
Q3: $756K
Q4: $691K (projected)

This spreadsheet contains confidential customer data and financial information.`
}

// generatePresentationText generates mock PowerPoint content
func (e *MockTextExtractor) generatePresentationText(fileSize int) string {
	return `Business Strategy Presentation

Slide 1: Company Overview
Leading provider of innovative solutions with strong market position.

Slide 2: Financial Highlights
- Revenue Growth: 25% YoY
- Profit Margin: 18.5%
- Customer Retention: 94%

Slide 3: Market Opportunities
Expansion into AI and machine learning markets shows significant potential.

Slide 4: Strategic Partnerships
Negotiations ongoing with TechCorp Inc and Innovation Labs LLC.

Slide 5: Intellectual Property
Patent portfolio includes 12 approved patents and 8 pending applications.

Slide 6: Team & Contacts
CEO: executive@company.com
CTO: technology@company.com

CONFIDENTIAL - Do Not Distribute`
}

// generatePlainText generates mock plain text content
func (e *MockTextExtractor) generatePlainText(fileSize int) string {
	return `Internal Memo - Confidential

TO: All Department Heads
FROM: Management Team
DATE: Current
RE: Strategic Initiative Updates

Please review the quarterly performance data and provide feedback on resource allocation for the upcoming fiscal year.

Key Discussion Points:
1. Customer acquisition strategies
2. Technology roadmap priorities
3. Compliance and regulatory updates

Financial targets for next quarter include 15% revenue growth and expansion into new geographic markets.

Contact information:
- Project Manager: pm@company.com
- Legal Counsel: legal@company.com

This communication contains proprietary business information.`
}

// generateCSVText generates mock CSV content
func (e *MockTextExtractor) generateCSVText(fileSize int) string {
	return `Employee_ID,Name,Department,Salary,Email,Phone
E001,John Doe,Engineering,$85000,john.doe@company.com,(555) 123-4567
E002,Jane Smith,Marketing,$75000,jane.smith@company.com,(555) 234-5678
E003,Mike Johnson,Finance,$90000,mike.j@company.com,(555) 345-6789
E004,Sarah Wilson,Legal,$95000,sarah.w@company.com,(555) 456-7890

Department Budgets:
Engineering: $2.5M
Marketing: $1.8M
Finance: $1.2M
Legal: $800K

This file contains sensitive employee and financial data.`
}

// generateHTMLText generates mock HTML content
func (e *MockTextExtractor) generateHTMLText(fileSize int) string {
	return `Company Intranet - Internal Portal

Welcome to the Internal Communication System

Latest News:
- Q3 financial results exceed expectations
- New strategic partnership with TechCorp announced
- Employee satisfaction survey results: 91% positive

Quick Links:
- Employee Directory
- Financial Reports
- Policy Documents
- Contact Information

Department Updates:
Engineering: New product development on track
Marketing: Customer acquisition campaign launched
Finance: Budget planning for next fiscal year

Contact Support: support@company.com
Emergency: security@company.com

INTERNAL USE ONLY - Authorized Personnel`
}

// generateGenericText generates generic mock text
func (e *MockTextExtractor) generateGenericText(fileSize int) string {
	return `Document Content Analysis

This is a generic document containing various types of business information that may include financial data, customer information, strategic planning details, and other proprietary content.

The analysis system will scan for:
- Personally Identifiable Information (PII)
- Financial and business data
- Intellectual property references
- Legal and compliance content

Contact: analysis@company.com for questions.

Content classification and security assessment will be performed automatically.`
}

// getFileExtension extracts file extension from filename
func getFileExtension(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return "." + parts[len(parts)-1]
	}
	return ""
} 