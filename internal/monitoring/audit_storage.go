package monitoring

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ===== FILE STORAGE IMPLEMENTATION =====

// FileAuditStorage implements AuditStorage using file-based storage
type FileAuditStorage struct {
	config          *FileStorageConfig
	currentFile     *os.File
	currentWriter   *bufio.Writer
	currentFileSize int64
	mu              sync.RWMutex
	closed          bool
}

// FileStorageConfig configures file-based audit storage
type FileStorageConfig struct {
	BaseDirectory    string        `json:"base_directory"`
	FilePrefix       string        `json:"file_prefix"`
	FileExtension    string        `json:"file_extension"`
	MaxFileSize      int64         `json:"max_file_size"`
	MaxFiles         int           `json:"max_files"`
	CompressOldFiles bool          `json:"compress_old_files"`
	SyncInterval     time.Duration `json:"sync_interval"`
	CreateDirs       bool          `json:"create_dirs"`
	FilePermissions  os.FileMode   `json:"file_permissions"`
}

// NewFileAuditStorage creates a new file-based audit storage
func NewFileAuditStorage(config *FileStorageConfig) (*FileAuditStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("file storage config is required")
	}
	
	// Set defaults
	if config.BaseDirectory == "" {
		config.BaseDirectory = "./audit_logs"
	}
	if config.FilePrefix == "" {
		config.FilePrefix = "audit"
	}
	if config.FileExtension == "" {
		config.FileExtension = ".log"
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = 30 // Keep 30 files by default
	}
	if config.SyncInterval == 0 {
		config.SyncInterval = time.Second * 30
	}
	if config.FilePermissions == 0 {
		config.FilePermissions = 0644
	}
	
	// Create base directory if it doesn't exist
	if config.CreateDirs {
		if err := os.MkdirAll(config.BaseDirectory, 0755); err != nil {
			return nil, fmt.Errorf("failed to create base directory: %w", err)
		}
	}
	
	storage := &FileAuditStorage{
		config: config,
	}
	
	// Initialize current file
	if err := storage.rotateFile(); err != nil {
		return nil, fmt.Errorf("failed to initialize storage file: %w", err)
	}
	
	// Start sync goroutine
	go storage.syncLoop()
	
	return storage, nil
}

// Store stores an audit event
func (fas *FileAuditStorage) Store(event *AuditEvent) error {
	if fas.closed {
		return fmt.Errorf("storage is closed")
	}
	
	// Serialize event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}
	
	// Add newline
	data = append(data, '\n')
	
	fas.mu.Lock()
	defer fas.mu.Unlock()
	
	// Check if we need to rotate the file
	if fas.currentFileSize+int64(len(data)) > fas.config.MaxFileSize {
		if err := fas.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate audit file: %w", err)
		}
	}
	
	// Write to current file
	n, err := fas.currentWriter.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}
	
	fas.currentFileSize += int64(n)
	
	return nil
}

// Query queries audit events based on filters
func (fas *FileAuditStorage) Query(filters *AuditQueryFilters) ([]*AuditEvent, error) {
	if fas.closed {
		return nil, fmt.Errorf("storage is closed")
	}
	
	// Get all audit files
	files, err := fas.getAuditFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to get audit files: %w", err)
	}
	
	var events []*AuditEvent
	eventCount := 0
	
	// Process files in reverse chronological order (newest first)
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		
		// Check if we've reached the limit
		if filters.Limit > 0 && eventCount >= filters.Limit {
			break
		}
		
		fileEvents, err := fas.queryFile(file, filters)
		if err != nil {
			// Log error but continue with other files
			continue
		}
		
		for _, event := range fileEvents {
			// Apply offset
			if filters.Offset > 0 && eventCount < filters.Offset {
				eventCount++
				continue
			}
			
			// Check limit
			if filters.Limit > 0 && len(events) >= filters.Limit {
				break
			}
			
			events = append(events, event)
			eventCount++
		}
	}
	
	// Sort events if needed
	if filters.SortBy != "" {
		fas.sortEvents(events, filters.SortBy, filters.SortOrder)
	}
	
	return events, nil
}

// Count counts audit events matching filters
func (fas *FileAuditStorage) Count(filters *AuditQueryFilters) (int64, error) {
	if fas.closed {
		return 0, fmt.Errorf("storage is closed")
	}
	
	// Get all audit files
	files, err := fas.getAuditFiles()
	if err != nil {
		return 0, fmt.Errorf("failed to get audit files: %w", err)
	}
	
	var count int64
	
	for _, file := range files {
		fileCount, err := fas.countFile(file, filters)
		if err != nil {
			// Log error but continue with other files
			continue
		}
		count += fileCount
	}
	
	return count, nil
}

// Archive archives old audit logs
func (fas *FileAuditStorage) Archive(olderThan time.Time) error {
	if fas.closed {
		return fmt.Errorf("storage is closed")
	}
	
	files, err := fas.getAuditFiles()
	if err != nil {
		return fmt.Errorf("failed to get audit files: %w", err)
	}
	
	for _, file := range files {
		// Check file modification time
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		
		if info.ModTime().Before(olderThan) && !strings.HasSuffix(file, ".gz") {
			// Compress the file
			if err := fas.compressFile(file); err != nil {
				// Log error but continue
				continue
			}
		}
	}
	
	return nil
}

// Delete deletes old audit logs
func (fas *FileAuditStorage) Delete(olderThan time.Time) error {
	if fas.closed {
		return fmt.Errorf("storage is closed")
	}
	
	files, err := fas.getAuditFiles()
	if err != nil {
		return fmt.Errorf("failed to get audit files: %w", err)
	}
	
	for _, file := range files {
		// Check file modification time
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		
		if info.ModTime().Before(olderThan) {
			// Delete the file
			if err := os.Remove(file); err != nil {
				// Log error but continue
				continue
			}
		}
	}
	
	return nil
}

// Close closes the audit storage
func (fas *FileAuditStorage) Close() error {
	fas.mu.Lock()
	defer fas.mu.Unlock()
	
	fas.closed = true
	
	if fas.currentWriter != nil {
		fas.currentWriter.Flush()
	}
	
	if fas.currentFile != nil {
		return fas.currentFile.Close()
	}
	
	return nil
}

// ===== PRIVATE METHODS =====

// rotateFile rotates the current audit file
func (fas *FileAuditStorage) rotateFile() error {
	// Close current file
	if fas.currentWriter != nil {
		fas.currentWriter.Flush()
	}
	if fas.currentFile != nil {
		fas.currentFile.Close()
	}
	
	// Create new file name with timestamp
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("%s_%s%s", fas.config.FilePrefix, timestamp, fas.config.FileExtension)
	filePath := filepath.Join(fas.config.BaseDirectory, fileName)
	
	// Create new file
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fas.config.FilePermissions)
	if err != nil {
		return err
	}
	
	fas.currentFile = file
	fas.currentWriter = bufio.NewWriter(file)
	fas.currentFileSize = 0
	
	// Clean up old files
	go fas.cleanupOldFiles()
	
	return nil
}

// syncLoop periodically syncs the current file
func (fas *FileAuditStorage) syncLoop() {
	ticker := time.NewTicker(fas.config.SyncInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		fas.mu.RLock()
		if fas.closed {
			fas.mu.RUnlock()
			return
		}
		
		if fas.currentWriter != nil {
			fas.currentWriter.Flush()
		}
		if fas.currentFile != nil {
			fas.currentFile.Sync()
		}
		fas.mu.RUnlock()
	}
}

// getAuditFiles gets all audit files in chronological order
func (fas *FileAuditStorage) getAuditFiles() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(fas.config.BaseDirectory, fas.config.FilePrefix+"_*"))
	if err != nil {
		return nil, err
	}
	
	// Sort files chronologically
	sort.Strings(files)
	
	return files, nil
}

// queryFile queries events from a specific file
func (fas *FileAuditStorage) queryFile(filename string, filters *AuditQueryFilters) ([]*AuditEvent, error) {
	var file io.ReadCloser
	var err error
	
	// Check if file is compressed
	if strings.HasSuffix(filename, ".gz") {
		gzFile, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer gzFile.Close()
		
		file, err = gzip.NewReader(gzFile)
		if err != nil {
			return nil, err
		}
	} else {
		file, err = os.Open(filename)
		if err != nil {
			return nil, err
		}
	}
	defer file.Close()
	
	var events []*AuditEvent
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// Skip invalid lines
			continue
		}
		
		// Apply filters
		if fas.matchesFilters(&event, filters) {
			events = append(events, &event)
		}
	}
	
	return events, scanner.Err()
}

// countFile counts events in a specific file
func (fas *FileAuditStorage) countFile(filename string, filters *AuditQueryFilters) (int64, error) {
	var file io.ReadCloser
	var err error
	
	// Check if file is compressed
	if strings.HasSuffix(filename, ".gz") {
		gzFile, err := os.Open(filename)
		if err != nil {
			return 0, err
		}
		defer gzFile.Close()
		
		file, err = gzip.NewReader(gzFile)
		if err != nil {
			return 0, err
		}
	} else {
		file, err = os.Open(filename)
		if err != nil {
			return 0, err
		}
	}
	defer file.Close()
	
	var count int64
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			// Skip invalid lines
			continue
		}
		
		// Apply filters
		if fas.matchesFilters(&event, filters) {
			count++
		}
	}
	
	return count, scanner.Err()
}

// matchesFilters checks if an event matches the given filters
func (fas *FileAuditStorage) matchesFilters(event *AuditEvent, filters *AuditQueryFilters) bool {
	if filters == nil {
		return true
	}
	
	// Time range filters
	if filters.StartTime != nil && event.Timestamp.Before(*filters.StartTime) {
		return false
	}
	if filters.EndTime != nil && event.Timestamp.After(*filters.EndTime) {
		return false
	}
	
	// Category filter
	if len(filters.Categories) > 0 {
		matched := false
		for _, cat := range filters.Categories {
			if event.Category == cat {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Type filter
	if len(filters.Types) > 0 {
		matched := false
		for _, typ := range filters.Types {
			if event.Type == typ {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Severity filter
	if len(filters.Severities) > 0 {
		matched := false
		for _, sev := range filters.Severities {
			if event.Severity == sev {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Outcome filter
	if len(filters.Outcomes) > 0 {
		matched := false
		for _, out := range filters.Outcomes {
			if event.Outcome == out {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// User ID filter
	if len(filters.UserIDs) > 0 {
		matched := false
		for _, userID := range filters.UserIDs {
			if event.UserID == userID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Tenant ID filter
	if len(filters.TenantIDs) > 0 {
		matched := false
		for _, tenantID := range filters.TenantIDs {
			if event.TenantID == tenantID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Client IP filter
	if len(filters.ClientIPs) > 0 {
		matched := false
		for _, ip := range filters.ClientIPs {
			if event.ClientIP == ip {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Source filter
	if len(filters.Sources) > 0 {
		matched := false
		for _, source := range filters.Sources {
			if event.Source == source {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Component filter
	if len(filters.Components) > 0 {
		matched := false
		for _, component := range filters.Components {
			if event.Component == component {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	
	// Search text filter (simple contains search)
	if filters.SearchText != "" {
		searchLower := strings.ToLower(filters.SearchText)
		eventJSON, _ := json.Marshal(event)
		eventText := strings.ToLower(string(eventJSON))
		if !strings.Contains(eventText, searchLower) {
			return false
		}
	}
	
	return true
}

// sortEvents sorts events based on the given criteria
func (fas *FileAuditStorage) sortEvents(events []*AuditEvent, sortBy, sortOrder string) {
	if sortBy == "" {
		sortBy = "timestamp"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}
	
	ascending := sortOrder == "asc"
	
	sort.Slice(events, func(i, j int) bool {
		var less bool
		
		switch sortBy {
		case "timestamp":
			less = events[i].Timestamp.Before(events[j].Timestamp)
		case "severity":
			severityOrder := map[AuditSeverity]int{
				SeverityLow:      1,
				SeverityMedium:   2,
				SeverityHigh:     3,
				SeverityCritical: 4,
			}
			less = severityOrder[events[i].Severity] < severityOrder[events[j].Severity]
		case "category":
			less = string(events[i].Category) < string(events[j].Category)
		case "type":
			less = string(events[i].Type) < string(events[j].Type)
		case "source":
			less = events[i].Source < events[j].Source
		case "component":
			less = events[i].Component < events[j].Component
		default:
			// Default to timestamp
			less = events[i].Timestamp.Before(events[j].Timestamp)
		}
		
		if ascending {
			return less
		}
		return !less
	})
}

// compressFile compresses a file using gzip
func (fas *FileAuditStorage) compressFile(filename string) error {
	// Open source file
	srcFile, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	
	// Create compressed file
	compressedFile := filename + ".gz"
	dstFile, err := os.Create(compressedFile)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	
	// Create gzip writer
	gzWriter := gzip.NewWriter(dstFile)
	defer gzWriter.Close()
	
	// Copy data
	_, err = io.Copy(gzWriter, srcFile)
	if err != nil {
		os.Remove(compressedFile) // Clean up on error
		return err
	}
	
	// Remove original file
	return os.Remove(filename)
}

// cleanupOldFiles removes old audit files beyond the retention limit
func (fas *FileAuditStorage) cleanupOldFiles() {
	files, err := fas.getAuditFiles()
	if err != nil {
		return
	}
	
	// Keep only the most recent files
	if len(files) > fas.config.MaxFiles {
		oldFiles := files[:len(files)-fas.config.MaxFiles]
		for _, file := range oldFiles {
			// Compress before deletion if configured
			if fas.config.CompressOldFiles && !strings.HasSuffix(file, ".gz") {
				fas.compressFile(file)
			} else {
				os.Remove(file)
			}
		}
	}
}

// ===== IN-MEMORY STORAGE IMPLEMENTATION =====

// MemoryAuditStorage implements AuditStorage using in-memory storage (for testing)
type MemoryAuditStorage struct {
	events []*AuditEvent
	mu     sync.RWMutex
	closed bool
}

// NewMemoryAuditStorage creates a new in-memory audit storage
func NewMemoryAuditStorage() *MemoryAuditStorage {
	return &MemoryAuditStorage{
		events: make([]*AuditEvent, 0),
	}
}

// Store stores an audit event in memory
func (mas *MemoryAuditStorage) Store(event *AuditEvent) error {
	if mas.closed {
		return fmt.Errorf("storage is closed")
	}
	
	mas.mu.Lock()
	defer mas.mu.Unlock()
	
	// Create a copy to avoid issues with concurrent access
	eventCopy := *event
	mas.events = append(mas.events, &eventCopy)
	
	return nil
}

// Query queries audit events from memory
func (mas *MemoryAuditStorage) Query(filters *AuditQueryFilters) ([]*AuditEvent, error) {
	if mas.closed {
		return nil, fmt.Errorf("storage is closed")
	}
	
	mas.mu.RLock()
	defer mas.mu.RUnlock()
	
	var results []*AuditEvent
	
	for _, event := range mas.events {
		if mas.matchesFilters(event, filters) {
			// Create a copy to avoid issues with concurrent access
			eventCopy := *event
			results = append(results, &eventCopy)
		}
	}
	
	// Apply sorting
	if filters != nil && filters.SortBy != "" {
		mas.sortEvents(results, filters.SortBy, filters.SortOrder)
	}
	
	// Apply offset and limit
	if filters != nil {
		start := 0
		if filters.Offset > 0 {
			start = filters.Offset
		}
		
		end := len(results)
		if filters.Limit > 0 && start+filters.Limit < end {
			end = start + filters.Limit
		}
		
		if start < len(results) {
			results = results[start:end]
		} else {
			results = []*AuditEvent{}
		}
	}
	
	return results, nil
}

// Count counts audit events in memory
func (mas *MemoryAuditStorage) Count(filters *AuditQueryFilters) (int64, error) {
	if mas.closed {
		return 0, fmt.Errorf("storage is closed")
	}
	
	mas.mu.RLock()
	defer mas.mu.RUnlock()
	
	var count int64
	
	for _, event := range mas.events {
		if mas.matchesFilters(event, filters) {
			count++
		}
	}
	
	return count, nil
}

// Archive archives events (no-op for memory storage)
func (mas *MemoryAuditStorage) Archive(olderThan time.Time) error {
	// No-op for memory storage
	return nil
}

// Delete deletes old events from memory
func (mas *MemoryAuditStorage) Delete(olderThan time.Time) error {
	if mas.closed {
		return fmt.Errorf("storage is closed")
	}
	
	mas.mu.Lock()
	defer mas.mu.Unlock()
	
	var filtered []*AuditEvent
	for _, event := range mas.events {
		if event.Timestamp.After(olderThan) {
			filtered = append(filtered, event)
		}
	}
	
	mas.events = filtered
	return nil
}

// Close closes the memory storage
func (mas *MemoryAuditStorage) Close() error {
	mas.mu.Lock()
	defer mas.mu.Unlock()
	
	mas.closed = true
	mas.events = nil
	
	return nil
}

// matchesFilters and sortEvents implementations are the same as FileAuditStorage
func (mas *MemoryAuditStorage) matchesFilters(event *AuditEvent, filters *AuditQueryFilters) bool {
	// Use the same implementation as FileAuditStorage
	fas := &FileAuditStorage{}
	return fas.matchesFilters(event, filters)
}

func (mas *MemoryAuditStorage) sortEvents(events []*AuditEvent, sortBy, sortOrder string) {
	// Use the same implementation as FileAuditStorage
	fas := &FileAuditStorage{}
	fas.sortEvents(events, sortBy, sortOrder)
} 