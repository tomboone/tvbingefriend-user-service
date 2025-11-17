package main

import (
	"database/sql"
	"errors"

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
