package main

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	minUsernameLength = 3
	maxUsernameLength = 50
	minPasswordLength = 8
	maxEmailLength    = 255
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func validateUsername(username string) error {
	// Trim whitespace
	username = strings.TrimSpace(username)

	// Check if empty
	if username == "" {
		return ValidationError{Field: "username", Message: "cannot be empty"}
	}

	// Check length
	if len(username) < minUsernameLength {
		return ValidationError{Field: "username", Message: fmt.Sprintf("must be at least %d characters", minUsernameLength)}
	}
	if len(username) > maxUsernameLength {
		return ValidationError{Field: "username", Message: fmt.Sprintf("must be at most %d characters", maxUsernameLength)}
	}

	// Check allowed characters (letters, numbers, underscore, hyphen)
	for _, char := range username {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return ValidationError{Field: "username", Message: "can only contain letters, numbers, underscore, and hyphen"}
		}
	}

	return nil
}

func validateEmail(email string) error {
	// Trim whitespace
	email = strings.TrimSpace(email)

	// Check if empty
	if email == "" {
		return ValidationError{Field: "email", Message: "cannot be empty"}
	}

	// Check length
	if len(email) > maxEmailLength {
		return ValidationError{Field: "email", Message: fmt.Sprintf("must be at most %d characters", maxEmailLength)}
	}

	// Check format with regex
	if !emailRegex.MatchString(email) {
		return ValidationError{Field: "email", Message: "invalid email format"}
	}

	return nil
}

func validatePassword(password string) error {
	// Don't trim password - whitespace might be intentional

	// Check if empty
	if password == "" {
		return ValidationError{Field: "password", Message: "cannot be empty"}
	}

	// Check minimum length
	if len(password) < minPasswordLength {
		return ValidationError{Field: "password", Message: fmt.Sprintf("must be at least %d characters", minPasswordLength)}
	}

	return nil
}
