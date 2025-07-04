package database

import (
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMigrator(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)
	assert.NotNil(t, migrator)
	assert.Equal(t, logger, migrator.logger)
	assert.Nil(t, migrator.db)
}

func TestMigrator_LoadMigrationsFromEmbedded(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	// Create a test filesystem
	testFS := fstest.MapFS{
		"migrations/001_create_users_table.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(255));"),
		},
		"migrations/002_add_email_column.sql": &fstest.MapFile{
			Data: []byte("ALTER TABLE users ADD COLUMN email VARCHAR(255);"),
		},
		"migrations/invalid_name.sql": &fstest.MapFile{
			Data: []byte("-- This file has invalid name format"),
		},
		"migrations/README.md": &fstest.MapFile{
			Data: []byte("# Migrations"),
		},
	}

	migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
	require.NoError(t, err)

	// Should load 2 valid migrations (ignore invalid_name.sql and README.md)
	assert.Len(t, migrations, 2)

	// Check first migration
	assert.Equal(t, "001", migrations[0].Version)
	assert.Equal(t, "create users table", migrations[0].Description)
	assert.Contains(t, migrations[0].SQL, "CREATE TABLE users")

	// Check second migration
	assert.Equal(t, "002", migrations[1].Version)
	assert.Equal(t, "add email column", migrations[1].Description)
	assert.Contains(t, migrations[1].SQL, "ALTER TABLE users")

	// Migrations should be sorted by version
	assert.True(t, migrations[0].Version < migrations[1].Version)
}

func TestMigrator_LoadMigrationsFromEmbedded_EmptyDirectory(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	// Empty filesystem
	testFS := fstest.MapFS{}

	migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
	require.NoError(t, err)
	assert.Empty(t, migrations)
}

func TestMigrator_LoadMigrationsFromEmbedded_InvalidDirectory(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	testFS := fstest.MapFS{}

	// For non-existent directories, we should get empty migrations, not an error
	migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "nonexistent")
	assert.NoError(t, err)
	assert.Empty(t, migrations)
}

func TestMigration_Sorting(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	// Create migrations in non-sequential order
	testFS := fstest.MapFS{
		"migrations/010_later_migration.sql": &fstest.MapFile{
			Data: []byte("-- Later migration"),
		},
		"migrations/001_first_migration.sql": &fstest.MapFile{
			Data: []byte("-- First migration"),
		},
		"migrations/005_middle_migration.sql": &fstest.MapFile{
			Data: []byte("-- Middle migration"),
		},
	}

	migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
	require.NoError(t, err)

	// Should be sorted by version
	assert.Len(t, migrations, 3)
	assert.Equal(t, "001", migrations[0].Version)
	assert.Equal(t, "005", migrations[1].Version)
	assert.Equal(t, "010", migrations[2].Version)
}

func TestMigration_DescriptionFormatting(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	testFS := fstest.MapFS{
		"migrations/001_create_user_profile_table.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE user_profiles (id SERIAL);"),
		},
		"migrations/002_add_foreign_key_constraint.sql": &fstest.MapFile{
			Data: []byte("ALTER TABLE user_profiles ADD CONSTRAINT fk_user;"),
		},
	}

	migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
	require.NoError(t, err)

	assert.Len(t, migrations, 2)
	
	// Underscores should be converted to spaces
	assert.Equal(t, "create user profile table", migrations[0].Description)
	assert.Equal(t, "add foreign key constraint", migrations[1].Description)
}

func TestCalculateChecksum(t *testing.T) {
	tests := []struct {
		name     string
		content1 string
		content2 string
		same     bool
	}{
		{
			name:     "identical content",
			content1: "CREATE TABLE users (id SERIAL);",
			content2: "CREATE TABLE users (id SERIAL);",
			same:     true,
		},
		{
			name:     "different content",
			content1: "CREATE TABLE users (id SERIAL);",
			content2: "CREATE TABLE posts (id SERIAL);",
			same:     false,
		},
		{
			name:     "empty content",
			content1: "",
			content2: "",
			same:     true,
		},
		{
			name:     "whitespace sensitive",
			content1: "CREATE TABLE users (id SERIAL);",
			content2: "CREATE TABLE users ( id SERIAL );",
			same:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checksum1 := calculateChecksum(tt.content1)
			checksum2 := calculateChecksum(tt.content2)

			if tt.same {
				assert.Equal(t, checksum1, checksum2)
			} else {
				assert.NotEqual(t, checksum1, checksum2)
			}

			// Checksums should be valid hex strings
			assert.Regexp(t, "^[0-9a-f]+$", checksum1)
			assert.Regexp(t, "^[0-9a-f]+$", checksum2)
		})
	}
}

func TestMigration_Structure(t *testing.T) {
	migration := Migration{
		Version:     "001",
		Description: "create users table",
		SQL:         "CREATE TABLE users (id SERIAL);",
		Applied:     false,
		AppliedAt:   nil,
	}

	assert.Equal(t, "001", migration.Version)
	assert.Equal(t, "create users table", migration.Description)
	assert.Contains(t, migration.SQL, "CREATE TABLE")
	assert.False(t, migration.Applied)
	assert.Nil(t, migration.AppliedAt)

	// Test with applied migration
	now := time.Now()
	migration.Applied = true
	migration.AppliedAt = &now

	assert.True(t, migration.Applied)
	assert.NotNil(t, migration.AppliedAt)
	assert.Equal(t, now, *migration.AppliedAt)
}

func TestMigrator_NilLogger(t *testing.T) {
	// Should handle nil logger gracefully
	migrator := NewMigrator(nil, nil)
	assert.NotNil(t, migrator)
	assert.NotNil(t, migrator.logger)
}

// Benchmark tests
func BenchmarkCalculateChecksum(b *testing.B) {
	content := `
		CREATE TABLE users (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX idx_users_email ON users(email);
		CREATE INDEX idx_users_created_at ON users(created_at);
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateChecksum(content)
	}
}

func BenchmarkMigrator_LoadMigrationsFromEmbedded(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	// Create a test filesystem with multiple migrations
	testFS := fstest.MapFS{}
	for i := 1; i <= 100; i++ {
		filename := fmt.Sprintf("migrations/%03d_migration_%d.sql", i, i)
		testFS[filename] = &fstest.MapFile{
			Data: []byte(fmt.Sprintf("-- Migration %d\nCREATE TABLE table_%d (id SERIAL);", i, i)),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Integration-style tests (without actual database)
func TestMigrator_WorkflowWithoutDB(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	// Test the workflow without actual database connections
	testFS := fstest.MapFS{
		"migrations/001_create_users.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE users (id SERIAL PRIMARY KEY);"),
		},
		"migrations/002_create_posts.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE posts (id SERIAL PRIMARY KEY, user_id INTEGER);"),
		},
	}

	// Load migrations
	migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
	require.NoError(t, err)
	assert.Len(t, migrations, 2)

	// All migrations should initially be unapplied
	for _, migration := range migrations {
		assert.False(t, migration.Applied)
		assert.Nil(t, migration.AppliedAt)
	}

	// Test checksum calculation
	for _, migration := range migrations {
		checksum := calculateChecksum(migration.SQL)
		assert.NotEmpty(t, checksum)
	}
}

func TestMigrator_InvalidFilenames(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	migrator := NewMigrator(nil, logger)

	tests := []struct {
		name     string
		filename string
		shouldLoad bool
	}{
		{
			name:     "valid filename",
			filename: "001_create_users.sql",
			shouldLoad: true,
		},
		{
			name:     "missing version",
			filename: "_create_users.sql",
			shouldLoad: false,
		},
		{
			name:     "missing description",
			filename: "001_.sql",
			shouldLoad: false,
		},
		{
			name:     "no underscore",
			filename: "001create_users.sql",
			shouldLoad: false,
		},
		{
			name:     "multiple underscores in description",
			filename: "001_create_user_profile_table.sql",
			shouldLoad: true,
		},
		{
			name:     "non-sql file",
			filename: "001_create_users.txt",
			shouldLoad: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFS := fstest.MapFS{
				"migrations/" + tt.filename: &fstest.MapFile{
					Data: []byte("CREATE TABLE test (id SERIAL);"),
				},
			}

			migrations, err := migrator.LoadMigrationsFromEmbedded(testFS, "migrations")
			require.NoError(t, err)

			if tt.shouldLoad {
				assert.Len(t, migrations, 1)
			} else {
				assert.Empty(t, migrations)
			}
		})
	}
} 