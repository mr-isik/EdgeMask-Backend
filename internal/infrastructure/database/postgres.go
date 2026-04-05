package database

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver for database/sql
	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// ensurePoolerParams appends pgx simple-protocol mode and connection timeout
// so it works correctly with Supabase Transaction Pooler (port 6543).
func ensurePoolerParams(databaseURL string) string {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return databaseURL
	}
	q := u.Query()
	if !q.Has("default_query_exec_mode") {
		q.Set("default_query_exec_mode", "simple_protocol")
	}
	if !q.Has("sslmode") && !strings.Contains(databaseURL, "sslmode=") {
		q.Set("sslmode", "require")
	}
	if !q.Has("connect_timeout") {
		q.Set("connect_timeout", "10")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Connect opens a connection pool to PostgreSQL using the pgx driver.
// Designed to work with Supabase Transaction Pooler (port 6543).
func Connect(databaseURL string) (*sqlx.DB, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is not set")
	}

	connStr := ensurePoolerParams(databaseURL)
	logger.Info("Connecting to database...")

	db, err := sqlx.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Connection pool settings optimized for Supabase pooler
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	// Verify the connection with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed (is Supabase project active?): %w", err)
	}

	logger.Info("Connected to PostgreSQL (Supabase)")
	return db, nil
}

// RunMigrations reads and applies SQL files in the specified directory
// using a raw pgx connection with simple protocol for multi-statement support.
func RunMigrations(databaseURL string, migrationsDir string) error {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("Migrations directory '", migrationsDir, "' not found. Skipping migrations.")
			return nil
		}
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			files = append(files, entry.Name())
		}
	}

	sort.Strings(files)

	if len(files) == 0 {
		return nil
	}

	connStr := ensurePoolerParams(databaseURL)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		return fmt.Errorf("migration connection failed: %w", err)
	}
	defer conn.Close(ctx)

	for _, file := range files {
		path := filepath.Join(migrationsDir, file)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		logger.Info("Executing migration: ", file)
		// PgConn().Exec uses the simple protocol — handles multi-statement SQL
		mrr := conn.PgConn().Exec(ctx, string(content))
		_, err = mrr.ReadAll()
		if err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}
	}

	logger.Info("All migrations executed successfully")
	return nil
}

