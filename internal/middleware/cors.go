package middleware

import (
	"net/http"
	"strings"
	"tvbingefriend-user-service/internal/config"
)

func MakeCorsMiddleware(cfg *config.Config) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Parse allowed origins (comma-separated)
			allowedOrigins := strings.Split(cfg.AllowedOrigin, ",")
			for i := range allowedOrigins {
				allowedOrigins[i] = strings.TrimSpace(allowedOrigins[i])
			}

			// Get the request origin
			requestOrigin := r.Header.Get("Origin")

			// Determine which origin to allow
			allowedOrigin := ""
			for _, origin := range allowedOrigins {
				if origin == "*" {
					// Wildcard allows any origin
					allowedOrigin = "*"
					break
				}
				if origin == requestOrigin {
					// Exact match - use the request origin
					allowedOrigin = requestOrigin
					break
				}
			}

			// Set CORS headers
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			// Call the next handler
			next(w, r)
		}
	}
}
