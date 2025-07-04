package analysis

import (
	"context"
	"math/rand"
	"strings"
	"time"

	"ai-gateway-poc/internal/logging"
)

// MockOCREngine implements OCREngine for testing and demonstration
type MockOCREngine struct {
	logger *logging.Logger
}

// ExtractTextFromImage simulates OCR text extraction from images
func (o *MockOCREngine) ExtractTextFromImage(ctx context.Context, imageData []byte, filename string) (*OCRResult, error) {
	start := time.Now()
	
	// Simulate OCR processing time
	time.Sleep(time.Millisecond * time.Duration(200+rand.Intn(300)))
	
	// Generate mock OCR text based on image characteristics
	extractedText := o.generateOCRText(len(imageData), filename)
	
	result := &OCRResult{
		ExtractedText:  extractedText,
		Confidence:     0.85 + rand.Float64()*0.15,
		ProcessingTime: time.Since(start),
		Engine:         "mock_ocr",
		Language:       "en",
		WordCount:      len(strings.Fields(extractedText)),
		BoundingBoxes:  o.generateBoundingBoxes(extractedText),
	}
	
	return result, nil
}

// GetSupportedFormats returns supported image formats
func (o *MockOCREngine) GetSupportedFormats() []string {
	return []string{
		"image/jpeg", "image/png", "image/gif", 
		"image/bmp", "image/tiff", "image/webp",
	}
}

// IsHealthy returns the health status
func (o *MockOCREngine) IsHealthy() bool {
	return true
}

// generateOCRText creates realistic OCR text output
func (o *MockOCREngine) generateOCRText(imageSize int, filename string) string {
	// Simulate different types of documents
	filename = strings.ToLower(filename)
	
	if strings.Contains(filename, "invoice") || strings.Contains(filename, "receipt") {
		return o.generateInvoiceText()
	} else if strings.Contains(filename, "contract") || strings.Contains(filename, "agreement") {
		return o.generateContractText()
	} else if strings.Contains(filename, "id") || strings.Contains(filename, "license") {
		return o.generateIDText()
	} else if strings.Contains(filename, "report") || strings.Contains(filename, "memo") {
		return o.generateReportText()
	}
	
	// Default document text
	return o.generateGenericDocumentText(imageSize)
}

// generateInvoiceText creates mock invoice OCR output
func (o *MockOCREngine) generateInvoiceText() string {
	return `INVOICE #INV-2024-001

TechCorp Solutions Inc
123 Business Avenue
Tech City, TC 12345
Phone: (555) 123-4567
Email: billing@techcorp.com

Bill To:
Global Enterprises LLC
456 Corporate Drive
Business City, BC 67890

Date: 2024-07-01
Due Date: 2024-07-31

Description                Qty    Rate      Amount
Software License          1      $5,000    $5,000.00
Support Services          12     $250      $3,000.00
Implementation            1      $2,500    $2,500.00

                          Subtotal: $10,500.00
                          Tax (8%): $840.00
                          Total: $11,340.00

Payment Terms: Net 30 days
Account Number: 1234567890123456

CONFIDENTIAL - Business Transaction`
}

// generateContractText creates mock contract OCR output
func (o *MockOCREngine) generateContractText() string {
	return `SOFTWARE LICENSE AGREEMENT

This Agreement is entered into between TechCorp Inc ("Licensor") and Client Company ("Licensee").

1. GRANT OF LICENSE
Licensor hereby grants to Licensee a non-exclusive license to use the proprietary software.

2. CONFIDENTIALITY
All information contained herein is confidential and proprietary trade secrets.

3. FINANCIAL TERMS
License Fee: $50,000 annually
Support Fee: $15,000 annually

4. CONTACT INFORMATION
Legal Department: legal@techcorp.com
Account Manager: Sarah Johnson (s.johnson@techcorp.com)
Phone: (555) 987-6543

5. COMPLIANCE
This agreement is subject to regulatory compliance requirements and industry standards.

Customer ID: C-789123
Contract ID: CNT-2024-045

CONFIDENTIAL AND PROPRIETARY`
}

// generateIDText creates mock ID document OCR output
func (o *MockOCREngine) generateIDText() string {
	return `DRIVER LICENSE

State of Technology
DL 123456789

John Michael Smith
123 Main Street
Tech City, TC 12345

DOB: 01/15/1985
Sex: M
Eyes: BRN
Height: 5'10"

Class: C
Expires: 01/15/2029
Phone: (555) 123-4567

Restrictions: None

This is an official government document containing personal identifying information.`
}

// generateReportText creates mock report OCR output  
func (o *MockOCREngine) generateReportText() string {
	return `QUARTERLY BUSINESS REPORT - CONFIDENTIAL

Executive Summary:
Financial performance shows strong growth with quarterly revenue of $15.2M representing 15% year-over-year increase.

Key Performance Indicators:
- Customer Satisfaction: 89%
- Employee Retention: 94%
- Market Share Growth: 2.3%

Strategic Initiatives:
1. Digital transformation projects
2. Customer data analytics platform
3. Intellectual property development

Financial Highlights:
Revenue: $15,200,000
Profit Margin: 28.5%
Customer Count: 2,847

Contact Information:
CFO: financial@company.com
CEO: executive@company.com

This document contains proprietary business information and trade secrets.`
}

// generateGenericDocumentText creates generic OCR output
func (o *MockOCREngine) generateGenericDocumentText(imageSize int) string {
	baseText := `DOCUMENT SCAN RESULT

This document contains business information that has been extracted using optical character recognition technology.

Content may include:
- Financial data and performance metrics
- Customer information and analytics
- Strategic planning documents
- Legal agreements and contracts
- Employee records and personnel data

For questions contact: support@company.com
Security classification: Internal Use Only`

	// Add more content for larger images
	if imageSize > 500000 { // Large image
		return baseText + `

Additional Content Detected:
- Multiple email addresses identified
- Phone numbers and contact information
- Financial amounts and calculations
- Personal identifying information (PII)
- Confidential business data

Detailed analysis and classification recommended for security assessment.`
	}
	
	return baseText
}

// generateBoundingBoxes creates mock bounding box coordinates
func (o *MockOCREngine) generateBoundingBoxes(text string) []BoundingBox {
	words := strings.Fields(text)
	boxes := []BoundingBox{}
	
	// Generate sample bounding boxes for first few words
	x, y := 50, 100
	for i, word := range words {
		if i >= 10 { // Limit to first 10 words for demo
			break
		}
		
		width := len(word) * 12 // Approximate character width
		height := 20
		
		box := BoundingBox{
			Text:       word,
			Confidence: 0.8 + rand.Float64()*0.2,
			X:          x,
			Y:          y,
			Width:      width,
			Height:     height,
		}
		
		boxes = append(boxes, box)
		
		// Move to next position
		x += width + 10
		if x > 500 { // Line wrap
			x = 50
			y += 30
		}
	}
	
	return boxes
} 