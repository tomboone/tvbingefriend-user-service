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

// DeleteAccount deletes a user account after verifying their password
func DeleteAccount(db *sql.DB, userID string, password string) error {
	// First, get the user's password hash to verify
	var passwordHash string
	query := "SELECT password_hash FROM users WHERE id = ?"

	err := db.QueryRow(query, userID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Verify the password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	// Delete the user
	deleteQuery := "DELETE FROM users WHERE id = ?"
	result, err := db.Exec(deleteQuery, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check deletion: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetUserProfile retrieves a user's profile information by ID
func GetUserProfile(db *sql.DB, userID string) (*User, error) {
	var user User
	query := `SELECT id, username, email, email_verified, created_at 
	          FROM users 
	          WHERE id = ?`

	err := db.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.EmailVerified,
		&user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &user, nil
}

// UpdateUsername changes a user's username after verifying their password
func UpdateUsername(db *sql.DB, userID string, newUsername string, password string) error {
	// First, verify the user's password
	var passwordHash string
	query := "SELECT password_hash FROM users WHERE id = ?"

	err := db.QueryRow(query, userID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	// Check if new username is already taken
	var existingID string
	checkQuery := "SELECT id FROM users WHERE username = ? AND id != ?"
	err = db.QueryRow(checkQuery, newUsername, userID).Scan(&existingID)
	if err != sql.ErrNoRows {
		if err == nil {
			return fmt.Errorf("username already taken")
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Update the username
	updateQuery := "UPDATE users SET username = ? WHERE id = ?"
	_, err = db.Exec(updateQuery, newUsername, userID)
	if err != nil {
		return fmt.Errorf("failed to update username: %w", err)
	}

	return nil
}

// UpdateEmail changes a user's email and triggers new verification
func UpdateEmail(db *sql.DB, userID string, newEmail string, password string) error {
	// First, verify the user's password
	var passwordHash string
	query := "SELECT password_hash FROM users WHERE id = ?"

	err := db.QueryRow(query, userID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password")
	}

	// Check if new email is already taken
	var existingID string
	checkQuery := "SELECT id FROM users WHERE email = ? AND id != ?"
	err = db.QueryRow(checkQuery, newEmail, userID).Scan(&existingID)
	if err != sql.ErrNoRows {
		if err == nil {
			return fmt.Errorf("email already taken")
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Generate new verification token
	verifyToken, err := GenerateSecureToken()
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Update email and set email_verified to false with new token
	updateQuery := `UPDATE users 
	                SET email = ?, email_verified = FALSE, verify_token = ? 
	                WHERE id = ?`
	_, err = db.Exec(updateQuery, newEmail, verifyToken, userID)
	if err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}

	return nil
}

// ChangePassword updates a user's password after verifying their current password
func ChangePassword(db *sql.DB, userID string, currentPassword string, newPassword string) error {
	// First, verify the current password
	var passwordHash string
	query := "SELECT password_hash FROM users WHERE id = ?"

	err := db.QueryRow(query, userID).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("database error: %w", err)
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(currentPassword))
	if err != nil {
		return fmt.Errorf("invalid current password")
	}

	// Hash the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the password
	updateQuery := "UPDATE users SET password_hash = ? WHERE id = ?"
	_, err = db.Exec(updateQuery, newPasswordHash, userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}
