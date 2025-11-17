package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"tvbingefriend-user-service/internal/config"
	"tvbingefriend-user-service/internal/models"
	"tvbingefriend-user-service/internal/service"
	"tvbingefriend-user-service/internal/validation"
)

// @Summary Register a new user
// @Description Creates a new user account with email verification
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "Registration details"
// @Success 201 {object} models.TokenResponse
// @Failure 400 {object} models.ErrorResponse "Invalid request or validation failed"
// @Failure 409 {object} models.ErrorResponse "Username or email already exists"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /register [post]
func MakeRegisterHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req models.RegisterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate username
		err = validation.Username(req.Username)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: err.Error()})
			return
		}

		// Validate email
		err = validation.Email(req.Email)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: err.Error()})
			return
		}

		// Validate password
		err = validation.Password(req.Password)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: err.Error()})
			return
		}

		// Generate verification token
		verifyToken, err := service.GenerateSecureToken()
		if err != nil {
			logger.Error("failed to generate verification token", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to create account"})
			return
		}

		// Register the user with verification token
		user, err := service.RegisterUser(db, req.Username, req.Email, req.Password, verifyToken)
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
					json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Username already exists"})
				} else {
					json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Email already exists"})
				}
				return
			}

			// For other errors, return generic message but log the details
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError) // 500
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to register user"})
			return
		}

		// Send verification email asynchronously (don't block registration)
		go func() {
			if err := service.SendVerificationEmail(cfg, logger, req.Email, req.Username, verifyToken); err != nil {
				logger.Error("failed to send verification email", "error", err, "user_id", user.ID)
			}
		}()

		// Generate tokens
		accessToken, err := service.GenerateAccessToken(cfg, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate access token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to generate access token"})
			return
		}

		refreshToken, err := service.GenerateRefreshToken(cfg, db, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate refresh token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to generate refresh token"})
			return
		}

		logger.Info("user registered",
			"user_id", user.ID,
			"username", user.Username,
		)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	}
}

// @Summary Login user
// @Description Authenticates a user and returns JWT tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.TokenResponse
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Invalid credentials"
// @Failure 403 {object} models.ErrorResponse "Email not verified"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /login [post]
func MakeLoginHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req models.LoginRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate inputs are not empty
		if strings.TrimSpace(req.Username) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "username cannot be empty"})
			return
		}

		if req.Password == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "password cannot be empty"})
			return
		}

		// Authenticate user
		user, emailVerified, err := service.AuthenticateUser(db, req.Username, req.Password)
		if err != nil {
			logger.Error("authentication error", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Authentication failed"})
			return
		}

		if user == nil {
			// Invalid credentials - use generic message to prevent user enumeration
			logger.Warn("failed login attempt", "username", req.Username)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid username or password"})
			return
		}

		// Check if email is verified
		if !emailVerified {
			logger.Warn("login attempt with unverified email", "username", req.Username, "user_id", user.ID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden) // 403
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Please verify your email before logging in. Check your inbox for the verification link."})
			return
		}

		// Generate tokens
		accessToken, err := service.GenerateAccessToken(cfg, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate access token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to generate access token"})
			return
		}

		refreshToken, err := service.GenerateRefreshToken(cfg, db, user.ID, user.Username)
		if err != nil {
			logger.Error("failed to generate refresh token",
				"error", err,
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to generate refresh token"})
			return
		}

		logger.Info("user logged in",
			"user_id", user.ID,
			"username", user.Username,
		)

		// Send response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	}
}

// @Summary Verify JWT token
// @Description Validates an access token and returns user information
// @Tags Authentication
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} map[string]string "user_id and username"
// @Failure 401 {object} models.ErrorResponse "Missing or invalid token"
// @Router /verify [get]
// @Security BearerAuth
func MakeVerifyHandler(cfg *config.Config, logger *slog.Logger) http.HandlerFunc {
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
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Missing authorization header"})
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
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "token cannot be empty"})
			return
		}

		// Validate token
		claims, err := service.ValidateToken(cfg, tokenString)
		if err != nil {
			logger.Warn("token validation failed",
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid token"})
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

// @Summary Refresh access token
// @Description Exchanges a refresh token for new access and refresh tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.RefreshRequest true "Refresh token"
// @Success 200 {object} map[string]string "access_token and refresh_token"
// @Failure 400 {object} models.ErrorResponse "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Invalid or revoked refresh token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /refresh [post]
func MakeRefreshHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req models.RefreshRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate refresh token is not empty
		if strings.TrimSpace(req.RefreshToken) == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "refresh_token cannot be empty"})
			return
		}

		claims, err := service.ValidateToken(cfg, req.RefreshToken)
		if err != nil {
			logger.Warn("refresh token validation failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid refresh token"})
			return
		}

		// Check if token_id exists and is not revoked
		var revoked bool
		var expiresAt time.Time
		query := "SELECT revoked, expires_at FROM refresh_tokens WHERE id = ?"
		err = db.QueryRow(query, claims.TokenID).Scan(&revoked, &expiresAt)
		if err != nil {
			if err == sql.ErrNoRows {
				logger.Warn("refresh token not found in database", "token_id", claims.TokenID)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid refresh token"})
				return
			}
			logger.Error("database error checking refresh token", "error", err, "token_id", claims.TokenID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Internal server error"})
			return
		}

		// Check if token is revoked
		if revoked {
			logger.Warn("attempted use of revoked refresh token", "token_id", claims.TokenID, "user_id", claims.UserID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid refresh token"})
			return
		}

		// Check if token is expired (double-check beyond JWT validation)
		if time.Now().After(expiresAt) {
			logger.Warn("attempted use of expired refresh token", "token_id", claims.TokenID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid refresh token"})
			return
		}

		// Revoke the old token (one-time use)
		updateQuery := "UPDATE refresh_tokens SET revoked = TRUE WHERE id = ?"
		_, err = db.Exec(updateQuery, claims.TokenID)
		if err != nil {
			logger.Error("failed to revoke old refresh token", "error", err, "token_id", claims.TokenID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Internal server error"})
			return
		}

		// Generate new access token
		accessToken, err := service.GenerateAccessToken(cfg, claims.UserID, claims.Username)
		if err != nil {
			logger.Error("failed to generate new access token", "error", err, "user_id", claims.UserID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to generate access token"})
			return
		}

		// Generate NEW refresh token (rotation)
		newRefreshToken, err := service.GenerateRefreshToken(cfg, db, claims.UserID, claims.Username)
		if err != nil {
			logger.Error("failed to generate new refresh token", "error", err, "user_id", claims.UserID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to generate refresh token"})
			return
		}

		logger.Info("tokens refreshed successfully", "user_id", claims.UserID, "old_token_id", claims.TokenID)

		// Send response with BOTH new tokens
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
		})
	}
}
