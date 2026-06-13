package db

import (
	"fmt"
	"sort"
	"time"

	"github.com/h0tak88r/AutoAR/internal/logger"
)

// Migration represents a single schema migration.
type Migration struct {
	ID   string // unique identifier, e.g. "001", "002"
	Name string // human-readable name
	Up   string // SQL to apply the migration
}

// migrationRegistry holds all migrations in order.
// Add new migrations here — the runner applies them atomically.
var migrationRegistry = []Migration{
	{
		ID:   "001",
		Name: "create_schema_migrations_table",
		Up: `CREATE TABLE IF NOT EXISTS schema_migrations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMP NOT NULL
		);`,
	},
	{
		ID:   "002",
		Name: "add_scan_artifacts_module_category",
		Up: `DO $$ BEGIN
			ALTER TABLE scan_artifacts ADD COLUMN IF NOT EXISTS module TEXT;
		EXCEPTION WHEN duplicate_column THEN END; $$;
		DO $$ BEGIN
			ALTER TABLE scan_artifacts ADD COLUMN IF NOT EXISTS category TEXT;
		EXCEPTION WHEN duplicate_column THEN END; $$;`,
	},
	{
		ID:   "003",
		Name: "add_subdomains_techs_cnames",
		Up: `DO $$ BEGIN
			ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS techs TEXT DEFAULT '';
		EXCEPTION WHEN duplicate_column THEN END; $$;
		DO $$ BEGIN
			ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS cnames TEXT DEFAULT '';
		EXCEPTION WHEN duplicate_column THEN END; $$;`,
	},
	{
		ID:   "004",
		Name: "add_scan_result_url",
		Up: `DO $$ BEGIN
			ALTER TABLE scans ADD COLUMN IF NOT EXISTS result_url TEXT;
		EXCEPTION WHEN duplicate_column THEN END; $$;`,
	},
	{
		ID:   "005",
		Name: "unique_scan_artifacts",
		Up: `CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_artifacts_scan_r2_key_uniq
			ON scan_artifacts(scan_id, r2_key);`,
	},
}

// RunMigrations applies all pending migrations atomically.
// Safe to call on every startup — already-applied migrations are skipped.
func RunMigrations() error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return fmt.Errorf("migration: db init: %w", err)
		}
	}

	initMu.Lock()
	defer initMu.Unlock()
	return runMigrationsLocked()
}

// runMigrationsLocked applies pending migrations. Caller must hold initMu.
func runMigrationsLocked() error {
	if dbInstance == nil {
		return nil
	}

	// Ensure schema_migrations table exists (SQLite-compatible)
	if err := dbInstance.execMigrationsDDL(); err != nil {
		return fmt.Errorf("migration: create tracking table: %w", err)
	}

	// Load applied migration IDs
	applied, err := dbInstance.loadAppliedMigrationIDs()
	if err != nil {
		return fmt.Errorf("migration: load applied: %w", err)
	}

	// Sort migration registry by ID
	sorted := make([]Migration, len(migrationRegistry))
	copy(sorted, migrationRegistry)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	// Apply pending migrations
	for _, m := range sorted {
		if applied[m.ID] {
			continue
		}

		logger.GetLogger().Infof("[MIGRATION] Applying %s: %s", m.ID, m.Name)
		start := time.Now()

		if err := dbInstance.execMigrationSQL(m.Up); err != nil {
			return fmt.Errorf("migration %s (%s) failed: %w", m.ID, m.Name, err)
		}

		if err := dbInstance.recordMigrationApplied(m.ID, m.Name); err != nil {
			return fmt.Errorf("migration %s: record failed: %w", m.ID, err)
		}

		logger.GetLogger().Infof("[MIGRATION] %s applied in %v", m.ID, time.Since(start))
	}

	return nil
}

// execMigrationsDDL creates the schema_migrations tracking table using raw SQL
// that works on both PostgreSQL and SQLite.
func execMigrationsDDL() error {
	// Use the global facade — it handles dialect internally
	initMu.Lock()
	defer initMu.Unlock()
	return dbInstance.execMigrationsDDL()
}

// applyMigration executes a migration's SQL using the global DB facade.
func applyMigration(m Migration) error {
	initMu.Lock()
	defer initMu.Unlock()
	return dbInstance.execMigrationSQL(m.Up)
}

// loadAppliedMigrations returns a set of already-applied migration IDs.
func loadAppliedMigrations() (map[string]bool, error) {
	initMu.Lock()
	defer initMu.Unlock()
	return dbInstance.loadAppliedMigrationIDs()
}

// recordMigration inserts a migration record after successful application.
func recordMigration(m Migration) error {
	initMu.Lock()
	defer initMu.Unlock()
	return dbInstance.recordMigrationApplied(m.ID, m.Name)
}

// RegisterMigration adds a migration at runtime (for plugins or test fixtures).
func RegisterMigration(id, name, upSQL string) {
	migrationRegistry = append(migrationRegistry, Migration{
		ID:   id,
		Name: name,
		Up:   upSQL,
	})
}
