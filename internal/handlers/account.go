package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"tvbingefriend-user-service/internal/config"
	"tvbingefriend-user-service/internal/service"
)

// @Summary Delete account
// @Description Permanently deletes a user's account
// @Tags Account Management
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param request body models.DeleteAccountRequest true "Current password for confirmation"
// @Success 200 {object} map[string]string "Success message"
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {object} models.ErrorResponse "Invalid token or password"
// @Failure 500 {string} string "Internal server error"
// @Router /delete-account [delete]
// @Security BearerAuth
func MakeDeleteAccountHandler(cfg *config.Config, db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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
		claims, err := service.ValidateToken(cfg, tokenString)
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
		err = service.DeleteAccount(db, claims.UserID, req.Password)
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
