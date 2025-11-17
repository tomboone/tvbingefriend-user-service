package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func registerUser(db *sql.DB, username, email, password, verifyToken string) (*User, error) {
	// Generate a unique ID
	id := uuid.New().String()

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	query := `
		INSERT INTO users (id, username, email, password_hash, email_verified, verify_token, created_at)
		VALUES (?, ?, ?, ?, FALSE, ?, NOW())
	`

	_, err = db.Exec(query, id, username, email, hashedPassword, verifyToken)
	if err != nil {
		return nil, err
	}

	// Return the created user
	user := &User{
		ID:           id,
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
	}

	return user, nil
}

func getUserByUsername(db *sql.DB, username string) (*User, error) {
	var user User

	query := "SELECT id, username, email, password_hash FROM users WHERE username = ?"
	err := db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func authenticateUser(db *sql.DB, username, password string) (*User, bool, error) {
	var user User
	query := `SELECT id, username, email, password_hash, email_verified FROM users WHERE username = ?`
	err := db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.EmailVerified)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil // User not found
		}
		return nil, false, err // Database error
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, false, nil // Invalid password
	}

	// Return user and verification status
	return &user, user.EmailVerified, nil
}

// GeneratePasswordResetToken generates a secure reset token and stores it with expiry
func GeneratePasswordResetToken(db *sql.DB, email string) error {
	// Generate secure random token (reuse the same function from email.go)
	token, err := GenerateSecureToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Token expires in 1 hour
	expiry := time.Now().Add(1 * time.Hour)

	// Update user with reset token and expiry
	query := `UPDATE users 
	          SET reset_token = ?, reset_token_expiry = ? 
	          WHERE email = ?`

	result, err := db.Exec(query, token, expiry, email)
	if err != nil {
		return fmt.Errorf("failed to store reset token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// No user found with this email - but don't reveal this for security
		return nil
	}

	return nil
}

// ValidateResetToken checks if a reset token is valid and not expired
func ValidateResetToken(db *sql.DB, token string) (string, error) {
	var email string
	var expiry time.Time

	query := `SELECT email, reset_token_expiry 
	          FROM users 
	          WHERE reset_token = ?`

	err := db.QueryRow(query, token).Scan(&email, &expiry)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("invalid reset token")
		}
		return "", fmt.Errorf("database error: %w", err)
	}

	// Check if token has expired
	if time.Now().After(expiry) {
		return "", fmt.Errorf("reset token has expired")
	}

	return email, nil
}

// ResetPassword updates a user's password and clears the reset token
func ResetPassword(db *sql.DB, email string, newPassword string) error {
	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password and clear reset token
	query := `UPDATE users 
	          SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL 
	          WHERE email = ?`

	_, err = db.Exec(query, hashedPassword, email)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}
