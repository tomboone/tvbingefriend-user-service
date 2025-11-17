package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

func connectDB(config *Config) (*sql.DB, error) {
	// Build connection string from config
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		config.DBUser,
		config.DBPassword,
		config.DBHost,
		config.DBPort,
		config.DBName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.DBMaxOpenConns)
	db.SetMaxIdleConns(config.DBMaxIdleConns)
	db.SetConnMaxLifetime(config.DBConnMaxLifetime)
	db.SetConnMaxIdleTime(config.DBConnMaxIdleTime)

	// Log pool configuration
	log.Printf("Database pool configured: MaxOpen=%d, MaxIdle=%d, ConnMaxLifetime=%v, ConnMaxIdleTime=%v",
		config.DBMaxOpenConns, config.DBMaxIdleConns, config.DBConnMaxLifetime, config.DBConnMaxIdleTime)

	return db, nil
}

func initDB(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		email_verified BOOLEAN DEFAULT FALSE NOT NULL,
		verify_token VARCHAR(64) DEFAULT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(query)
	return err
}
