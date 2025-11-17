package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"tvbingefriend-user-service/internal/config"
	"tvbingefriend-user-service/internal/service"
	"tvbingefriend-user-service/internal/validation"
)

// @Summary Get user profile
// @Description Returns the authenticated user's profile information
// @Tags Profile Management
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} models.ProfileResponse
// @Failure 401 {object} models.ErrorResponse "Invalid or missing token"
// @Failure 500 {string} string "Internal server error"
// @Router /profile [get]
// @Security BearerAuth
func MakeGetProfileHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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
		claims, err := service.ValidateToken(cfg, tokenString)
		if err != nil {
			logger.Warn("invalid token for profile access", "error", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Get user profile
		user, err := service.GetUserProfile(db, claims.UserID)
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

// @Summary Update username
// @Description Updates the authenticated user's username
// @Tags Profile Management
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param request body models.UpdateUsernameRequest true "New username and password"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} models.ErrorResponse "Invalid request or validation failed"
// @Failure 401 {object} models.ErrorResponse "Invalid token or password"
// @Failure 409 {string} string "Username already taken"
// @Failure 500 {string} string "Internal server error"
// @Router /profile/username [put]
// @Security BearerAuth
func MakeUpdateUsernameHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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

		claims, err := service.ValidateToken(cfg, tokenString)
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
		if err := validation.Username(req.NewUsername); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Password == "" {
			http.Error(w, "Password is required", http.StatusBadRequest)
			return
		}

		// Update username
		err = service.UpdateUsername(db, claims.UserID, req.NewUsername, req.Password)
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

// @Summary Update email
// @Description Updates the authenticated user's email address (requires re-verification)
// @Tags Profile Management
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param request body models.UpdateEmailRequest true "New email and password"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} models.ErrorResponse "Invalid request or validation failed"
// @Failure 401 {object} models.ErrorResponse "Invalid token or password"
// @Failure 409 {string} string "Email already taken"
// @Failure 500 {string} string "Internal server error"
// @Router /profile/email [put]
// @Security BearerAuth
func MakeUpdateEmailHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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

		claims, err := service.ValidateToken(cfg, tokenString)
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
		if err := validation.Email(req.NewEmail); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Password == "" {
			http.Error(w, "Password is required", http.StatusBadRequest)
			return
		}

		// Update email
		err = service.UpdateEmail(db, claims.UserID, req.NewEmail, req.Password)
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
			if err := service.SendVerificationEmail(cfg, logger, req.NewEmail, claims.Username, verifyToken); err != nil {
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

// @Summary Change password
// @Description Changes the authenticated user's password
// @Tags Profile Management
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param request body models.ChangePasswordRequest true "Current and new passwords"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} models.ErrorResponse "Invalid request or validation failed"
// @Failure 401 {object} models.ErrorResponse "Invalid token or current password"
// @Failure 500 {string} string "Internal server error"
// @Router /profile/password [put]
// @Security BearerAuth
func MakeChangePasswordHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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

		claims, err := service.ValidateToken(cfg, tokenString)
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

		if err := validation.Password(req.NewPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Prevent setting the same password
		if req.CurrentPassword == req.NewPassword {
			http.Error(w, "New password must be different from current password", http.StatusBadRequest)
			return
		}

		// Change password
		err = service.ChangePassword(db, claims.UserID, req.CurrentPassword, req.NewPassword)
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
