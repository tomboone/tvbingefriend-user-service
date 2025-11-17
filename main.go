package main

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "tvbingefriend-user-service/docs" // Import generated docs
	"tvbingefriend-user-service/internal/config"
	"tvbingefriend-user-service/internal/database"
	"tvbingefriend-user-service/internal/handlers"
	"tvbingefriend-user-service/internal/logger"
	"tvbingefriend-user-service/internal/middleware"

	httpSwagger "github.com/swaggo/http-swagger"
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
	cfg, err := config.Load()
	if err != nil {
		stdlog.Fatal("Failed to load configuration:", err)
	}

	fmt.Println("Configuration loaded successfully!")
	fmt.Printf("Server will run on port: %s\n", cfg.ServerPort)

	// Initialize structured logger
	log := logger.Setup(cfg)

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		stdlog.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	log.Info("starting user service",
		"port", cfg.ServerPort,
		"environment", cfg.Environment,
		"cors_origin", cfg.AllowedOrigin,
	)

	// Initialize database tables
	err = database.Initialize(db)
	if err != nil {
		stdlog.Fatal("Failed to initialize database:", err)
	}

	fmt.Println("Database connected and initialized successfully!")

	// Create rate limiters
	loginRateLimiter := middleware.NewRateLimiter(5, time.Minute)         // 5 attempts per minute
	registerRateLimiter := middleware.NewRateLimiter(3, time.Minute)      // 3 attempts per minute
	passwordResetRateLimiter := middleware.NewRateLimiter(3, time.Minute) // 3 attempts per minute

	// Create CORS middleware with config
	corsMiddleware := middleware.MakeCorsMiddleware(cfg)

	// Set up HTTP routes with CORS and rate limiting on auth endpoints
	http.HandleFunc("/register", middleware.LoggingMiddleware(log, corsMiddleware(middleware.RateLimitMiddleware(registerRateLimiter, log)(handlers.MakeRegisterHandler(cfg, db, log)))))
	http.HandleFunc("/login", middleware.LoggingMiddleware(log, corsMiddleware(middleware.RateLimitMiddleware(loginRateLimiter, log)(handlers.MakeLoginHandler(cfg, db, log)))))
	http.HandleFunc("/verify", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeVerifyHandler(cfg, log))))
	http.HandleFunc("/refresh", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeRefreshHandler(cfg, db, log))))

	// Email verification endpoints
	http.HandleFunc("/verify-email", middleware.LoggingMiddleware(log, handlers.MakeVerifyEmailHandler(db, log)))
	http.HandleFunc("/resend-verification", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeResendVerificationHandler(cfg, db, log))))

	// Password reset endpoints
	http.HandleFunc("/request-password-reset", middleware.LoggingMiddleware(log, corsMiddleware(middleware.RateLimitMiddleware(passwordResetRateLimiter, log)(handlers.MakeRequestPasswordResetHandler(cfg, db, log, passwordResetRateLimiter)))))
	http.HandleFunc("/reset-password", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeResetPasswordHandler(cfg, db, log))))

	// Account management endpoints
	http.HandleFunc("/delete-account", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeDeleteAccountHandler(cfg, db, log))))

	// Profile management endpoints
	http.HandleFunc("/profile", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeGetProfileHandler(cfg, db, log))))
	http.HandleFunc("/profile/username", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeUpdateUsernameHandler(cfg, db, log))))
	http.HandleFunc("/profile/email", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeUpdateEmailHandler(cfg, db, log))))
	http.HandleFunc("/profile/password", middleware.LoggingMiddleware(log, corsMiddleware(handlers.MakeChangePasswordHandler(cfg, db, log))))

	// Health check endpoint (no middleware needed)
	http.HandleFunc("/health", handlers.MakeHealthHandler(db, log))

	// Swagger documentation endpoint
	http.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Create HTTP server
	srv := &http.Server{
		Addr: ":" + cfg.ServerPort,
	}

	// Channel to listen for shutdown signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Info("server starting", "port", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-stop
	log.Info("shutdown signal received, starting graceful shutdown")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("server shutdown failed", "error", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		log.Error("failed to close database", "error", err)
	}

	log.Info("server stopped gracefully")
}
