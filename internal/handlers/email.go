package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"tvbingefriend-user-service/internal/config"
	"tvbingefriend-user-service/internal/models"
	"tvbingefriend-user-service/internal/service"
	"tvbingefriend-user-service/internal/validation"
)

// @Summary Verify email address
// @Description Verifies a user's email address using the verification token
// @Tags Email Verification
// @Produce json
// @Param token query string true "Email verification token"
// @Success 200 {object} map[string]string "Verification success message"
// @Failure 400 {object} models.ErrorResponse "Invalid or expired token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /verify-email [get]
func MakeVerifyEmailHandler(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Verification token is required"})
			return
		}

		query := `UPDATE users SET email_verified = TRUE, verify_token = NULL WHERE verify_token = ? AND email_verified = FALSE`
		result, err := db.Exec(query, token)
		if err != nil {
			logger.Error("failed to verify email", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to verify email"})
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			logger.Error("failed to get rows affected", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to verify email"})
			return
		}

		if rowsAffected == 0 {
			logger.Warn("invalid or expired verification token", "token", token)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid or expired verification token"})
			return
		}

		logger.Info("email verified successfully", "token", token)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
	}
}

// @Summary Resend verification email
// @Description Resends the email verification link to the user's email address
// @Tags Email Verification
// @Accept json
// @Produce json
// @Param request body models.ResendVerificationRequest true "Email address"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {object} models.ErrorResponse "Invalid email format"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /resend-verification [post]
func MakeResendVerificationHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req models.ResendVerificationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Invalid request body"})
			return
		}

		err = validation.Email(req.Email)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: err.Error()})
			return
		}

		var userID, username string
		var emailVerified bool
		query := `SELECT id, username, email_verified FROM users WHERE email = ?`
		err = db.QueryRow(query, req.Email).Scan(&userID, &username, &emailVerified)
		if err != nil {
			if err == sql.ErrNoRows {
				logger.Warn("resend verification attempted for non-existent email", "email", req.Email)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists and is not verified, a verification email has been sent"})
				return
			}
			logger.Error("failed to query user", "error", err, "email", req.Email)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to resend verification email"})
			return
		}

		if emailVerified {
			logger.Info("resend verification attempted for already verified email", "email", req.Email)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists and is not verified, a verification email has been sent"})
			return
		}

		verifyToken, err := service.GenerateSecureToken()
		if err != nil {
			logger.Error("failed to generate verification token", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to resend verification email"})
			return
		}

		updateQuery := `UPDATE users SET verify_token = ? WHERE id = ?`
		_, err = db.Exec(updateQuery, verifyToken, userID)
		if err != nil {
			logger.Error("failed to update verification token", "error", err, "user_id", userID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(models.ErrorResponse{Error: "Failed to resend verification email"})
			return
		}

		go func() {
			if err := service.SendVerificationEmail(cfg, logger, req.Email, username, verifyToken); err != nil {
				logger.Error("failed to send verification email", "error", err, "user_id", userID)
			}
		}()

		logger.Info("verification email resent", "email", req.Email, "user_id", userID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists and is not verified, a verification email has been sent"})
	}
}
