package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	TokenID  string `json:"token_id,omitempty"` // Only for refresh tokens
	jwt.RegisteredClaims
}

func generateAccessToken(config *Config, userID, username string) (string, error) {
	expirationTime := time.Now().Add(time.Duration(config.AccessTokenExpiryMins) * time.Minute)

	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func validateToken(config *Config, tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

func generateRefreshToken(config *Config, db *sql.DB, userID, username string) (string, error) {
	// Generate unique token ID
	tokenID := uuid.New().String()

	expirationTime := time.Now().Add(time.Duration(config.RefreshTokenExpiryDays) * 24 * time.Hour)

	claims := &Claims{
		UserID:   userID,
		Username: username,
		TokenID:  tokenID, // Add the token ID to JWT claims
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JWTSecret))
	if err != nil {
		return "", err
	}

	// Store token in database
	query := `INSERT INTO refresh_tokens (id, user_id, expires_at, revoked) 
              VALUES (?, ?, ?, FALSE)`
	_, err = db.Exec(query, tokenID, userID, expirationTime)
	if err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return tokenString, nil
}
