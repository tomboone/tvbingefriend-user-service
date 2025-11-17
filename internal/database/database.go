package database

import (
	"database/sql"
	"fmt"
	"log"
	"tvbingefriend-user-service/internal/config"

	_ "github.com/go-sql-driver/mysql"
)

func Connect(cfg *config.Config) (*sql.DB, error) {
	// Build connection string from config
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		cfg.DBUser,
		cfg.DBPassword,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.DBMaxOpenConns)
	db.SetMaxIdleConns(cfg.DBMaxIdleConns)
	db.SetConnMaxLifetime(cfg.DBConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.DBConnMaxIdleTime)

	// Log pool configuration
	log.Printf("Database pool configured: MaxOpen=%d, MaxIdle=%d, ConnMaxLifetime=%v, ConnMaxIdleTime=%v",
		cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime, cfg.DBConnMaxIdleTime)

	return db, nil
}

func Initialize(db *sql.DB) error {
	// Create users table
	usersTable := `
    CREATE TABLE IF NOT EXISTS users (
       id VARCHAR(36) PRIMARY KEY,
       username VARCHAR(255) UNIQUE NOT NULL,
       email VARCHAR(255) UNIQUE NOT NULL,
       password_hash VARCHAR(255) NOT NULL,
       email_verified BOOLEAN DEFAULT FALSE NOT NULL,
       verify_token VARCHAR(64) DEFAULT NULL,
       reset_token VARCHAR(255) DEFAULT NULL,
       reset_token_expiry TIMESTAMP DEFAULT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`

	_, err := db.Exec(usersTable)
	if err != nil {
		return err
	}

	// Create refresh_tokens table
	refreshTokensTable := `
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        revoked BOOLEAN DEFAULT FALSE NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_expires_at (expires_at)
    )`

	_, err = db.Exec(refreshTokensTable)
	return err
}
