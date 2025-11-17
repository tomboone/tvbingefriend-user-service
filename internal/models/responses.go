package models

// TokenResponse represents the response containing JWT tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid request"`
}

// ProfileResponse represents the user profile data
type ProfileResponse struct {
	ID            string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Username      string `json:"username" example:"john_doe"`
	Email         string `json:"email" example:"john@example.com"`
	EmailVerified bool   `json:"email_verified" example:"true"`
	CreatedAt     string `json:"created_at" example:"2024-01-01T00:00:00Z"`
}
