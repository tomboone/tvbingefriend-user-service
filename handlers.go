package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func makeRegisterHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// All the handleRegister code goes here
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req RegisterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate username
		err = validateUsername(req.Username)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}

		// Validate email
		err = validateEmail(req.Email)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}

		// Validate password
		err = validatePassword(req.Password)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}

		// Generate verification token
		verifyToken, err := GenerateSecureToken()
		if err != nil {
			logger.Error("failed to generate verification token", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to create account"})
			return
		}

		// Register the user with verification token
		user, err := registerUser(db, req.Username, req.Email, req.Password, verifyToken)
		if err != nil {
			// Log the actual error with context
			logger.Error("failed to register user",
				"error", err,
				"username", req.Username,
				"email", req.Email,
			)

			// Check if it's a duplicate key error
			if strings.Contains(err.Error(), "Duplicate entry") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict) // 409

				// Determine if it's username or email duplicate
				if strings.Contains(err.Error(), "username") {
					json.NewEncoder(w).Encode(ErrorResponse{Error: "Username already exists"})
				} else {
					json.NewEncoder(w).Encode(ErrorResponse{Error: "Email already exists"})
				}
				return
			}

			// For other errors, return generic message but log the details
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError) // 500
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to register user"})
			return
		}

		// Send verification email asynchronously (don't block registration)
		go func() {
			if err := sendVerificationEmail(config, logger, req.Email, req.Username, verifyToken); err != nil {
				logger.Error("failed to send verification email", "error", err, "user_id", user.ID)
			}
		}()

		// Generate tokens
		accessToken, err := generateAccessToken(config, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate access token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate access token"})
			return
		}

		refreshToken, err := generateRefreshToken(config, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate refresh token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate refresh token"})
			return
		}

		logger.Info("user registered",
			"user_id", user.ID,
			"username", user.Username,
		)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	}
}

func makeLoginHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req LoginRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate inputs are not empty
		if strings.TrimSpace(req.Username) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "username cannot be empty"})
			return
		}

		if req.Password == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "password cannot be empty"})
			return
		}

		// Authenticate user
		user, emailVerified, err := authenticateUser(db, req.Username, req.Password)
		if err != nil {
			logger.Error("authentication error", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Authentication failed"})
			return
		}

		if user == nil {
			// Invalid credentials - use generic message to prevent user enumeration
			logger.Warn("failed login attempt", "username", req.Username)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid username or password"})
			return
		}

		// Check if email is verified
		if !emailVerified {
			logger.Warn("login attempt with unverified email", "username", req.Username, "user_id", user.ID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden) // 403
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Please verify your email before logging in. Check your inbox for the verification link."})
			return
		}

		// Generate tokens
		accessToken, err := generateAccessToken(config, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate access token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate access token"})
			return
		}

		refreshToken, err := generateRefreshToken(config, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate refresh token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate refresh token"})
			return
		}

		logger.Info("user logged in",
			"user_id", user.ID,
			"username", user.Username,
		)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	}
}

func makeVerifyHandler(config *Config, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Missing authorization header"})
			return
		}

		// Expected format: "Bearer <token>"
		tokenString := ""
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			tokenString = strings.TrimSpace(authHeader[7:])
		}

		// Validate token is not empty
		if tokenString == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "token cannot be empty"})
			return
		}

		// Validate token
		claims, err := validateToken(config, tokenString)
		if err != nil {
			logger.Warn("token validation failed",
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid token"})
			return
		}

		// Return user info from token
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"user_id":  claims.UserID,
			"username": claims.Username,
		})
	}
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func makeRefreshHandler(config *Config, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RefreshRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate refresh token is not empty
		if strings.TrimSpace(req.RefreshToken) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "refresh_token cannot be empty"})
			return
		}

		claims, err := validateToken(config, req.RefreshToken)
		if err != nil {
			logger.Warn("refresh token validation failed",
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid refresh token"})
			return
		}

		// Generate new access token
		accessToken, err := generateAccessToken(config, claims.UserID, claims.Username)
		if err != nil {
			logger.Error("failed to generate new access token",
				"error", err,
				"user_id", claims.UserID,
				"username", claims.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to generate access token"})
			return
		}

		// Send response with new access token
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": accessToken,
		})
	}
}

// makeHealthHandler creates a handler for the health check endpoint
func makeHealthHandler(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check database connectivity
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := db.PingContext(ctx); err != nil {
			logger.Error("health check failed: database ping failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"unhealthy","database":"disconnected"}`))
			return
		}

		// All checks passed
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","database":"connected"}`))
	}
}

// makeVerifyEmailHandler creates a handler for email verification
func makeVerifyEmailHandler(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get token from query parameter
		token := r.URL.Query().Get("token")
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Verification token is required"})
			return
		}

		// Verify the token and mark email as verified
		query := `
			UPDATE users 
			SET email_verified = TRUE, verify_token = NULL 
			WHERE verify_token = ? AND email_verified = FALSE
		`

		result, err := db.Exec(query, token)
		if err != nil {
			logger.Error("failed to verify email", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to verify email"})
			return
		}

		// Check if any row was updated
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			logger.Error("failed to get rows affected", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to verify email"})
			return
		}

		if rowsAffected == 0 {
			// Token not found or already used
			logger.Warn("invalid or expired verification token", "token", token)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid or expired verification token"})
			return
		}

		logger.Info("email verified successfully", "token", token)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Email verified successfully",
		})
	}
}

// ResendVerificationRequest represents the request body for resending verification email
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// makeResendVerificationHandler creates a handler for resending verification emails
func makeResendVerificationHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ResendVerificationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
			return
		}

		// Validate email
		err = validateEmail(req.Email)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
			return
		}

		// Check if user exists and is not verified
		var userID, username string
		var emailVerified bool
		query := `SELECT id, username, email_verified FROM users WHERE email = ?`
		err = db.QueryRow(query, req.Email).Scan(&userID, &username, &emailVerified)
		if err != nil {
			if err == sql.ErrNoRows {
				// Don't reveal if email exists - return success anyway
				logger.Warn("resend verification attempted for non-existent email", "email", req.Email)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{
					"message": "If the email exists and is not verified, a verification email has been sent",
				})
				return
			}
			logger.Error("failed to query user", "error", err, "email", req.Email)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to resend verification email"})
			return
		}

		// If already verified, return success (don't reveal this info)
		if emailVerified {
			logger.Info("resend verification attempted for already verified email", "email", req.Email)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "If the email exists and is not verified, a verification email has been sent",
			})
			return
		}

		// Generate new verification token
		verifyToken, err := GenerateSecureToken()
		if err != nil {
			logger.Error("failed to generate verification token", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to resend verification email"})
			return
		}

		// Update user with new token
		updateQuery := `UPDATE users SET verify_token = ? WHERE id = ?`
		_, err = db.Exec(updateQuery, verifyToken, userID)
		if err != nil {
			logger.Error("failed to update verification token", "error", err, "user_id", userID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to resend verification email"})
			return
		}

		// Send verification email asynchronously
		go func() {
			if err := sendVerificationEmail(config, logger, req.Email, username, verifyToken); err != nil {
				logger.Error("failed to send verification email", "error", err, "user_id", userID)
			}
		}()

		logger.Info("verification email resent", "email", req.Email, "user_id", userID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If the email exists and is not verified, a verification email has been sent",
		})
	}
}

// makeRequestPasswordResetHandler handles password reset requests
func makeRequestPasswordResetHandler(config *Config, db *sql.DB, logger *slog.Logger, rateLimiter *RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req struct {
			Email string `json:"email"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate email
		if err := validateEmail(req.Email); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Rate limiting
		clientIP := extractIP(r.RemoteAddr)
		if !rateLimiter.Allow(clientIP) {
			logger.Warn("password reset rate limit exceeded", "ip", clientIP)
			http.Error(w, "Too many password reset requests. Please try again later.", http.StatusTooManyRequests)
			return
		}

		// Generate and store reset token
		err := GeneratePasswordResetToken(db, req.Email)
		if err != nil {
			logger.Error("failed to generate reset token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Send reset email asynchronously (don't block the request)
		go func() {
			// Query for token (we need it to send the email)
			var token string
			query := "SELECT reset_token FROM users WHERE email = ? AND reset_token IS NOT NULL"
			err := db.QueryRow(query, req.Email).Scan(&token)
			if err != nil {
				logger.Error("failed to retrieve reset token for email", "error", err)
				return
			}

			// Send the email
			if err := sendPasswordResetEmail(config, logger, req.Email, token); err != nil {
				logger.Error("failed to send password reset email", "error", err, "email", req.Email)
			}
		}()

		// Always return success (don't reveal if email exists)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If an account with that email exists, a password reset link has been sent.",
		})
	}
}

// makeResetPasswordHandler handles the actual password reset with token
func makeResetPasswordHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req struct {
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate inputs
		if req.Token == "" {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		if err := validatePassword(req.NewPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the reset token and get the email
		email, err := ValidateResetToken(db, req.Token)
		if err != nil {
			logger.Warn("invalid or expired reset token", "error", err)
			http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
			return
		}

		// Reset the password
		err = ResetPassword(db, email, req.NewPassword)
		if err != nil {
			logger.Error("failed to reset password", "error", err, "email", email)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("password reset successful", "email", email)

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Password reset successful. You can now log in with your new password.",
		})
	}
}

// makeDeleteAccountHandler handles account deletion requests
func makeDeleteAccountHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " prefix
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Validate token and extract claims
		claims, err := validateToken(config, tokenString)
		if err != nil {
			logger.Warn("invalid token for account deletion", "error", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req struct {
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate password provided
		if req.Password == "" {
			http.Error(w, "Password is required", http.StatusBadRequest)
			return
		}

		// Delete the account
		err = DeleteAccount(db, claims.UserID, req.Password)
		if err != nil {
			if err.Error() == "invalid password" {
				logger.Warn("account deletion failed: invalid password", "user_id", claims.UserID)
				http.Error(w, "Invalid password", http.StatusUnauthorized)
				return
			}
			logger.Error("failed to delete account", "error", err, "user_id", claims.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("account deleted successfully", "user_id", claims.UserID, "username", claims.Username)

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Account deleted successfully",
		})
	}
}

// makeGetProfileHandler returns a user's profile information
func makeGetProfileHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		// Validate token and extract claims
		claims, err := validateToken(config, tokenString)
		if err != nil {
			logger.Warn("invalid token for profile access", "error", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Get user profile
		user, err := GetUserProfile(db, claims.UserID)
		if err != nil {
			logger.Error("failed to get user profile", "error", err, "user_id", claims.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Return profile (don't include password_hash!)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":             user.ID,
			"username":       user.Username,
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"created_at":     user.CreatedAt,
		})
	}
}

// makeUpdateUsernameHandler updates a user's username
func makeUpdateUsernameHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(config, tokenString)
		if err != nil {
			logger.Warn("invalid token for username update", "error", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req struct {
			NewUsername string `json:"new_username"`
			Password    string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate inputs
		if err := validateUsername(req.NewUsername); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Password == "" {
			http.Error(w, "Password is required", http.StatusBadRequest)
			return
		}

		// Update username
		err = UpdateUsername(db, claims.UserID, req.NewUsername, req.Password)
		if err != nil {
			if err.Error() == "invalid password" {
				logger.Warn("username update failed: invalid password", "user_id", claims.UserID)
				http.Error(w, "Invalid password", http.StatusUnauthorized)
				return
			}
			if err.Error() == "username already taken" {
				http.Error(w, "Username already taken", http.StatusConflict)
				return
			}
			logger.Error("failed to update username", "error", err, "user_id", claims.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("username updated successfully", "user_id", claims.UserID, "new_username", req.NewUsername)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Username updated successfully",
		})
	}
}

// makeUpdateEmailHandler updates a user's email and triggers reverification
func makeUpdateEmailHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(config, tokenString)
		if err != nil {
			logger.Warn("invalid token for email update", "error", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req struct {
			NewEmail string `json:"new_email"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate inputs
		if err := validateEmail(req.NewEmail); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Password == "" {
			http.Error(w, "Password is required", http.StatusBadRequest)
			return
		}

		// Update email
		err = UpdateEmail(db, claims.UserID, req.NewEmail, req.Password)
		if err != nil {
			if err.Error() == "invalid password" {
				logger.Warn("email update failed: invalid password", "user_id", claims.UserID)
				http.Error(w, "Invalid password", http.StatusUnauthorized)
				return
			}
			if err.Error() == "email already taken" {
				http.Error(w, "Email already taken", http.StatusConflict)
				return
			}
			logger.Error("failed to update email", "error", err, "user_id", claims.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Send verification email asynchronously
		go func() {
			// Get the new verify token that was just created
			var verifyToken string
			query := "SELECT verify_token FROM users WHERE id = ?"
			err := db.QueryRow(query, claims.UserID).Scan(&verifyToken)
			if err != nil {
				logger.Error("failed to retrieve verification token after email update", "error", err, "user_id", claims.UserID)
				return
			}

			// Send verification email to new address
			if err := sendVerificationEmail(config, logger, req.NewEmail, claims.Username, verifyToken); err != nil {
				logger.Error("failed to send verification email for updated email", "error", err, "user_id", claims.UserID)
			}
		}()

		logger.Info("email updated successfully", "user_id", claims.UserID, "new_email", req.NewEmail)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Email updated successfully. Please check your new email to verify it.",
		})
	}
}

// makeChangePasswordHandler changes a user's password
func makeChangePasswordHandler(config *Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		claims, err := validateToken(config, tokenString)
		if err != nil {
			logger.Warn("invalid token for password change", "error", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate inputs
		if req.CurrentPassword == "" {
			http.Error(w, "Current password is required", http.StatusBadRequest)
			return
		}

		if err := validatePassword(req.NewPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Prevent setting the same password
		if req.CurrentPassword == req.NewPassword {
			http.Error(w, "New password must be different from current password", http.StatusBadRequest)
			return
		}

		// Change password
		err = ChangePassword(db, claims.UserID, req.CurrentPassword, req.NewPassword)
		if err != nil {
			if err.Error() == "invalid current password" {
				logger.Warn("password change failed: invalid current password", "user_id", claims.UserID)
				http.Error(w, "Invalid current password", http.StatusUnauthorized)
				return
			}
			logger.Error("failed to change password", "error", err, "user_id", claims.UserID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		logger.Info("password changed successfully", "user_id", claims.UserID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Password changed successfully",
		})
	}
}
