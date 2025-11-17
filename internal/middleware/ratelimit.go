package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter tracks request attempts per IP address
type RateLimiter struct {
	attempts map[string][]time.Time // IP address -> slice of attempt timestamps
	mu       sync.Mutex             // Protects the map from concurrent access
	limit    int                    // Maximum number of attempts allowed
	window   time.Duration          // Time window for the limit (e.g., 1 minute)
}

// NewRateLimiter creates a new rate limiter with specified limit and time window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if a request from the given IP address should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Get existing attempts for this IP
	attempts := rl.attempts[ip]

	// Filter out attempts outside the time window
	validAttempts := []time.Time{}
	for _, t := range attempts {
		if t.After(cutoff) {
			validAttempts = append(validAttempts, t)
		}
	}

	// Check if we're under the limit
	if len(validAttempts) >= rl.limit {
		// Update map with cleaned attempts (for next time)
		rl.attempts[ip] = validAttempts
		return false // Rate limit exceeded
	}

	// Add this attempt and allow the request
	validAttempts = append(validAttempts, now)
	rl.attempts[ip] = validAttempts
	return true
}

// ExtractIP gets the IP address without the port from RemoteAddr
func ExtractIP(remoteAddr string) string {
	// RemoteAddr format is "IP:port" or "[IPv6]:port"
	// Split by last colon to handle both IPv4 and IPv6
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		ip := remoteAddr[:idx]
		// Remove brackets from IPv6 addresses
		ip = strings.Trim(ip, "[]")
		return ip
	}
	return remoteAddr
}

// RateLimitMiddleware creates middleware that applies rate limiting to a handler
func RateLimitMiddleware(rl *RateLimiter, logger *slog.Logger) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Extract IP address from request
			ip := ExtractIP(r.RemoteAddr)

			// Check if request is allowed
			if !rl.Allow(ip) {
				logger.Warn("Rate limit exceeded",
					"ip", ip,
					"path", r.URL.Path,
					"method", r.Method,
				)

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"Too many requests. Please try again later."}`))
				return
			}

			// Rate limit not exceeded, proceed to handler
			next(w, r)
		}
	}
}
