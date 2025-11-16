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

		// Register the user
		user, err := registerUser(db, req.Username, req.Email, req.Password)
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
		user, err := authenticateUser(db, req.Username, req.Password)
		if err != nil {
			// Log the actual error with context (but be careful not to log passwords!)
			logger.Warn("authentication failed",
				"error", err,
				"username", req.Username,
			)

			// Always return the same generic message to avoid revealing if username exists
			// This prevents username enumeration attacks
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized) // 401 instead of 500
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid username or password"})
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid username or password"})
			return
		}

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
