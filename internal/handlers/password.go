package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"tvbingefriend-user-service/internal/config"
	"tvbingefriend-user-service/internal/middleware"
	"tvbingefriend-user-service/internal/service"
	"tvbingefriend-user-service/internal/validation"
)

// @Summary Request password reset
// @Description Sends a password reset link to the user's email address
// @Tags Password Reset
// @Accept json
// @Produce json
// @Param request body models.PasswordResetRequest true "Email address"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} models.ErrorResponse "Invalid email format"
// @Failure 429 {string} string "Too many requests"
// @Failure 500 {string} string "Internal server error"
// @Router /request-password-reset [post]
func MakeRequestPasswordResetHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger, rateLimiter *middleware.RateLimiter) http.HandlerFunc {
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
		if err := validation.Email(req.Email); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Rate limiting
		clientIP := middleware.ExtractIP(r.RemoteAddr)
		if !rateLimiter.Allow(clientIP) {
			logger.Warn("password reset rate limit exceeded", "ip", clientIP)
			http.Error(w, "Too many password reset requests. Please try again later.", http.StatusTooManyRequests)
			return
		}

		// Generate and store reset token
		err := service.GeneratePasswordResetToken(db, req.Email)
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
			if err := service.SendPasswordResetEmail(cfg, logger, req.Email, token); err != nil {
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

// @Summary Reset password
// @Description Resets the user's password using a reset token
// @Tags Password Reset
// @Accept json
// @Produce json
// @Param request body models.ResetPasswordRequest true "Reset token and new password"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} models.ErrorResponse "Invalid token or password validation failed"
// @Failure 500 {string} string "Internal server error"
// @Router /reset-password [post]
func MakeResetPasswordHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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

		if err := validation.Password(req.NewPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Validate the reset token and get the email
		email, err := service.ValidateResetToken(db, req.Token)
		if err != nil {
			logger.Warn("invalid or expired reset token", "error", err)
			http.Error(w, "Invalid or expired reset token", http.StatusBadRequest)
			return
		}

		// Reset the password
		err = service.ResetPassword(db, email, req.NewPassword)
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
