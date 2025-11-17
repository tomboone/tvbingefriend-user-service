package models

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Username string `json:"username" example:"john_doe"`
	Email    string `json:"email" example:"john@example.com"`
	Password string `json:"password" example:"SecurePass123!"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Username string `json:"username" example:"john_doe"`
	Password string `json:"password" example:"SecurePass123!"`
}

// RefreshRequest represents the request body for token refresh
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ResendVerificationRequest represents the request body for resending verification email
type ResendVerificationRequest struct {
	Email string `json:"email" example:"john@example.com"`
}

// PasswordResetRequest represents the request body for requesting password reset
type PasswordResetRequest struct {
	Email string `json:"email" example:"john@example.com"`
}

// ResetPasswordRequest represents the request body for resetting password
type ResetPasswordRequest struct {
	Token       string `json:"token" example:"abc123token"`
	NewPassword string `json:"new_password" example:"NewSecurePass123!"`
}

// DeleteAccountRequest represents the request body for account deletion
type DeleteAccountRequest struct {
	Password string `json:"password" example:"SecurePass123!"`
}

// UpdateUsernameRequest represents the request body for updating username
type UpdateUsernameRequest struct {
	NewUsername string `json:"new_username" example:"jane_doe"`
	Password    string `json:"password" example:"SecurePass123!"`
}

// UpdateEmailRequest represents the request body for updating email
type UpdateEmailRequest struct {
	NewEmail string `json:"new_email" example:"newemail@example.com"`
	Password string `json:"password" example:"SecurePass123!"`
}

// ChangePasswordRequest represents the request body for changing password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" example:"OldPass123!"`
	NewPassword     string `json:"new_password" example:"NewSecurePass123!"`
}
