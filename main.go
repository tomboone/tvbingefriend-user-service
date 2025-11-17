package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpSwagger "github.com/swaggo/http-swagger"
	_ "tvbingefriend-user-service/docs" // Import generated docs
)

// @title TV Binge Friend User Service API
// @version 1.0
// @description Authentication and user management API for TV Binge Friend application
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@tvbingefriend.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	fmt.Println("Configuration loaded successfully!")
	fmt.Printf("Server will run on port: %s\n", config.ServerPort)

	// Initialize structured logger
	logger := setupLogger(config)

	// Connect to database
	db, err := connectDB(config)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	logger.Info("starting user service",
		"port", config.ServerPort,
		"environment", config.Environment,
		"cors_origin", config.AllowedOrigin,
	)

	// Initialize database tables
	err = initDB(db)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	fmt.Println("Database connected and initialized successfully!")

	// Create rate limiters
	loginRateLimiter := NewRateLimiter(5, time.Minute)         // 5 attempts per minute
	registerRateLimiter := NewRateLimiter(3, time.Minute)      // 3 attempts per minute
	passwordResetRateLimiter := NewRateLimiter(3, time.Minute) // 3 attempts per minute

	// Create CORS middleware with config
	corsMiddleware := makeCorsMiddleware(config)

	// Set up HTTP routes with CORS and rate limiting on auth endpoints
	http.HandleFunc("/register", loggingMiddleware(logger, corsMiddleware(RateLimitMiddleware(registerRateLimiter, logger)(makeRegisterHandler(config, db, logger)))))
	http.HandleFunc("/login", loggingMiddleware(logger, corsMiddleware(RateLimitMiddleware(loginRateLimiter, logger)(makeLoginHandler(config, db, logger)))))
	http.HandleFunc("/verify", loggingMiddleware(logger, corsMiddleware(makeVerifyHandler(config, logger))))
	http.HandleFunc("/refresh", loggingMiddleware(logger, corsMiddleware(makeRefreshHandler(config, db, logger))))

	// Email verification endpoints
	http.HandleFunc("/verify-email", loggingMiddleware(logger, makeVerifyEmailHandler(db, logger)))
	http.HandleFunc("/resend-verification", loggingMiddleware(logger, corsMiddleware(makeResendVerificationHandler(config, db, logger))))

	// Password reset endpoints
	http.HandleFunc("/request-password-reset", loggingMiddleware(logger, corsMiddleware(RateLimitMiddleware(passwordResetRateLimiter, logger)(makeRequestPasswordResetHandler(config, db, logger, passwordResetRateLimiter)))))
	http.HandleFunc("/reset-password", loggingMiddleware(logger, corsMiddleware(makeResetPasswordHandler(config, db, logger))))

	// Account management endpoints
	http.HandleFunc("/delete-account", loggingMiddleware(logger, corsMiddleware(makeDeleteAccountHandler(config, db, logger))))

	// Profile management endpoints
	http.HandleFunc("/profile", loggingMiddleware(logger, corsMiddleware(makeGetProfileHandler(config, db, logger))))
	http.HandleFunc("/profile/username", loggingMiddleware(logger, corsMiddleware(makeUpdateUsernameHandler(config, db, logger))))
	http.HandleFunc("/profile/email", loggingMiddleware(logger, corsMiddleware(makeUpdateEmailHandler(config, db, logger))))
	http.HandleFunc("/profile/password", loggingMiddleware(logger, corsMiddleware(makeChangePasswordHandler(config, db, logger))))

	// Health check endpoint (no middleware needed)
	http.HandleFunc("/health", makeHealthHandler(db, logger))

	// Swagger documentation endpoint
	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Create HTTP server
	srv := &http.Server{
		Addr: ":" + config.ServerPort,
	}

	// Channel to listen for shutdown signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		logger.Info("server starting", "port", config.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-stop
	logger.Info("shutdown signal received, starting graceful shutdown")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown failed", "error", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		logger.Error("failed to close database", "error", err)
	}

	logger.Info("server stopped gracefully")
}
