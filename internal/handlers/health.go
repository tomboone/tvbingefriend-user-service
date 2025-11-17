package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"time"
)

// @Summary Health check
// @Description Returns the health status of the service and database
// @Tags System
// @Produce json
// @Success 200 {object} map[string]string "status and database connection status"
// @Failure 503 {object} map[string]string "Service unavailable"
// @Router /health [get]
func MakeHealthHandler(db *sql.DB, logger *slog.Logger) http.HandlerFunc {
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
