package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment string // "development" or "production"

	// Database configuration
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// JWT configuration
	JWTSecret              string
	AccessTokenExpiryMins  int
	RefreshTokenExpiryDays int

	// Server configuration
	ServerPort string

	// CORS configuration
	AllowedOrigin string

	// Database connection pool settings
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration
	DBConnMaxIdleTime time.Duration

	// Email settings
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	EmailFrom    string // e.g., "noreply@tvbingefriend.com"
	AppURL       string // e.g., "https://tvbingefriend.com" - for verification links
}

// getEnv reads an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt reads an environment variable as integer or returns a default value
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		fmt.Printf("Warning: Invalid integer for %s, using default %d\n", key, defaultValue)
		return defaultValue
	}

	return value
}

// getEnvAsDuration reads an environment variable and parses it as a duration, or returns a default
func getEnvAsDuration(key string, defaultVal time.Duration) time.Duration {
	valStr := os.Getenv(key)
	if valStr == "" {
		return defaultVal
	}

	val, err := time.ParseDuration(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}

func LoadConfig() (*Config, error) {
	config := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),

		// Database defaults (your local MySQL)
		DBHost:     getEnv("DB_HOST", "127.0.0.1"),
		DBPort:     getEnv("DB_PORT", "3306"),
		DBUser:     getEnv("DB_USER", "root"),
		DBPassword: getEnv("DB_PASSWORD", "root"),
		DBName:     getEnv("DB_NAME", "tvbf_user_service"),

		// JWT defaults
		JWTSecret:              getEnv("JWT_SECRET", "your-secret-key-change-this-in-production"),
		AccessTokenExpiryMins:  getEnvAsInt("ACCESS_TOKEN_EXPIRY_MINS", 15),
		RefreshTokenExpiryDays: getEnvAsInt("REFRESH_TOKEN_EXPIRY_DAYS", 7),

		// Server defaults
		ServerPort: getEnv("SERVER_PORT", "8080"),

		// CORS defaults
		AllowedOrigin: getEnv("ALLOWED_ORIGIN", "*"),

		// Database connection pool settings
		DBMaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
		DBConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		DBConnMaxIdleTime: getEnvAsDuration("DB_CONN_MAX_IDLE_TIME", 10*time.Minute),

		// Email settings
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     getEnvAsInt("SMTP_PORT", 587),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		EmailFrom:    getEnv("EMAIL_FROM", ""),
		AppURL:       getEnv("APP_URL", "http://localhost:3000"),
	}

	// Validate required fields
	if config.JWTSecret == "your-secret-key-change-this-in-production" {
		fmt.Println("WARNING: Using default JWT secret. Set JWT_SECRET environment variable in production!")
	}

	return config, nil
}
