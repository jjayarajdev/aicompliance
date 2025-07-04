package database

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

// Migration represents a database migration
type Migration struct {
	Version     string
	Description string
	SQL         string
	Applied     bool
	AppliedAt   *time.Time
}

// Migrator handles database migrations
type Migrator struct {
	db     *sqlx.DB
	logger *logrus.Logger
}

// NewMigrator creates a new database migrator
func NewMigrator(db *sqlx.DB, logger *logrus.Logger) *Migrator {
	if logger == nil {
		logger = logrus.New()
	}

	return &Migrator{
		db:     db,
		logger: logger,
	}
}

// InitMigrationTable creates the migration table if it doesn't exist
func (m *Migrator) InitMigrationTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			checksum VARCHAR(64) NOT NULL
		)
	`

	if _, err := m.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	m.logger.Info("Migration table initialized")
	return nil
}

// LoadMigrationsFromEmbedded loads migrations from embedded filesystem
func (m *Migrator) LoadMigrationsFromEmbedded(migrationFS fs.FS, migrationDir string) ([]Migration, error) {
	var migrations []Migration

	err := fs.WalkDir(migrationFS, migrationDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// If the directory doesn't exist, that's not an error - just return empty migrations
			if path == migrationDir {
				return nil
			}
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}

		// Extract version and description from filename
		// Expected format: {version}_{description}.sql
		filename := d.Name()
		nameWithoutExt := strings.TrimSuffix(filename, ".sql")
		
		// Must contain at least one underscore
		if !strings.Contains(nameWithoutExt, "_") {
			m.logger.WithField("filename", filename).Warn("Skipping migration file with invalid name format")
			return nil
		}
		
		parts := strings.SplitN(nameWithoutExt, "_", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			m.logger.WithField("filename", filename).Warn("Skipping migration file with invalid name format")
			return nil
		}
		
		// Version should be numeric (digits only)
		version := parts[0]
		for _, char := range version {
			if char < '0' || char > '9' {
				m.logger.WithField("filename", filename).Warn("Skipping migration file with non-numeric version")
				return nil
			}
		}
		description := strings.ReplaceAll(parts[1], "_", " ")

		// Read migration content
		content, err := fs.ReadFile(migrationFS, path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", path, err)
		}

		migrations = append(migrations, Migration{
			Version:     version,
			Description: description,
			SQL:         string(content),
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to load migrations: %w", err)
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	m.logger.WithField("count", len(migrations)).Info("Loaded migrations from embedded filesystem")
	return migrations, nil
}

// LoadMigrationsFromDirectory loads migrations from filesystem directory
func (m *Migrator) LoadMigrationsFromDirectory(migrationDir string) ([]Migration, error) {
	var migrations []Migration

	files, err := filepath.Glob(filepath.Join(migrationDir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob migration files: %w", err)
	}

	for _, file := range files {
		// Extract version and description from filename
		filename := filepath.Base(file)
		parts := strings.SplitN(strings.TrimSuffix(filename, ".sql"), "_", 2)
		if len(parts) != 2 {
			m.logger.WithField("filename", filename).Warn("Skipping migration file with invalid name format")
			continue
		}

		version := parts[0]
		description := strings.ReplaceAll(parts[1], "_", " ")

		// Read migration content
		content, err := fs.ReadFile(nil, file)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		migrations = append(migrations, Migration{
			Version:     version,
			Description: description,
			SQL:         string(content),
		})
	}

	// Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	m.logger.WithField("count", len(migrations)).Info("Loaded migrations from directory")
	return migrations, nil
}

// GetAppliedMigrations returns list of applied migrations
func (m *Migrator) GetAppliedMigrations(ctx context.Context) (map[string]Migration, error) {
	query := `
		SELECT version, description, applied_at
		FROM schema_migrations
		ORDER BY version
	`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]Migration)
	for rows.Next() {
		var migration Migration
		if err := rows.Scan(&migration.Version, &migration.Description, &migration.AppliedAt); err != nil {
			return nil, fmt.Errorf("failed to scan migration row: %w", err)
		}
		migration.Applied = true
		applied[migration.Version] = migration
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating migration rows: %w", err)
	}

	return applied, nil
}

// Migrate applies all pending migrations
func (m *Migrator) Migrate(ctx context.Context, migrations []Migration) error {
	// Get applied migrations
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Find pending migrations
	var pending []Migration
	for _, migration := range migrations {
		if _, exists := applied[migration.Version]; !exists {
			pending = append(pending, migration)
		}
	}

	if len(pending) == 0 {
		m.logger.Info("No pending migrations")
		return nil
	}

	m.logger.WithField("count", len(pending)).Info("Applying pending migrations")

	// Apply each pending migration in a transaction
	for _, migration := range pending {
		if err := m.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.Version, err)
		}
	}

	m.logger.Info("All migrations applied successfully")
	return nil
}

// applyMigration applies a single migration in a transaction
func (m *Migrator) applyMigration(ctx context.Context, migration Migration) error {
	m.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Info("Applying migration")

	// Start transaction
	tx, err := m.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback() // Will be ignored if transaction is committed

	// Execute migration SQL
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record migration as applied
	recordQuery := `
		INSERT INTO schema_migrations (version, description, checksum)
		VALUES ($1, $2, $3)
	`
	checksum := calculateChecksum(migration.SQL)
	if _, err := tx.ExecContext(ctx, recordQuery, migration.Version, migration.Description, checksum); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration transaction: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Info("Migration applied successfully")

	return nil
}

// Status returns the current migration status
func (m *Migrator) Status(ctx context.Context, migrations []Migration) ([]Migration, error) {
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get applied migrations: %w", err)
	}

	var status []Migration
	for _, migration := range migrations {
		if appliedMigration, exists := applied[migration.Version]; exists {
			migration.Applied = true
			migration.AppliedAt = appliedMigration.AppliedAt
		}
		status = append(status, migration)
	}

	return status, nil
}

// Rollback rolls back the last N migrations
func (m *Migrator) Rollback(ctx context.Context, steps int) error {
	if steps <= 0 {
		return fmt.Errorf("invalid rollback steps: %d", steps)
	}

	// Get applied migrations in reverse order
	query := `
		SELECT version, description
		FROM schema_migrations
		ORDER BY version DESC
		LIMIT $1
	`

	rows, err := m.db.QueryContext(ctx, query, steps)
	if err != nil {
		return fmt.Errorf("failed to query migrations for rollback: %w", err)
	}
	defer rows.Close()

	var toRollback []Migration
	for rows.Next() {
		var migration Migration
		if err := rows.Scan(&migration.Version, &migration.Description); err != nil {
			return fmt.Errorf("failed to scan migration row: %w", err)
		}
		toRollback = append(toRollback, migration)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating migration rows: %w", err)
	}

	if len(toRollback) == 0 {
		m.logger.Info("No migrations to rollback")
		return nil
	}

	m.logger.WithField("count", len(toRollback)).Warn("Rolling back migrations")

	// Rollback each migration
	for _, migration := range toRollback {
		if err := m.rollbackMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to rollback migration %s: %w", migration.Version, err)
		}
	}

	m.logger.Info("Rollback completed successfully")
	return nil
}

// rollbackMigration rolls back a single migration
func (m *Migrator) rollbackMigration(ctx context.Context, migration Migration) error {
	m.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Warn("Rolling back migration")

	// Start transaction
	tx, err := m.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Remove migration record
	deleteQuery := `DELETE FROM schema_migrations WHERE version = $1`
	if _, err := tx.ExecContext(ctx, deleteQuery, migration.Version); err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rollback transaction: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Warn("Migration rolled back successfully")

	return nil
}

// calculateChecksum calculates a simple checksum for migration content
func calculateChecksum(content string) string {
	// For simplicity, we'll use a basic hash
	// In production, you might want to use SHA-256
	hash := uint32(0)
	for _, char := range content {
		hash = hash*31 + uint32(char)
	}
	return fmt.Sprintf("%x", hash)
} 