package validation

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

type Error struct {
	Field   string
	Message string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func Username(username string) error {
	// Trim whitespace
	username = strings.TrimSpace(username)

	// Check if empty
	if username == "" {
		return Error{Field: "username", Message: "cannot be empty"}
	}

	// Check length
	if len(username) < minUsernameLength {
		return Error{Field: "username", Message: fmt.Sprintf("must be at least %d characters", minUsernameLength)}
	}
	if len(username) > maxUsernameLength {
		return Error{Field: "username", Message: fmt.Sprintf("must be at most %d characters", maxUsernameLength)}
	}

	// Check allowed characters (letters, numbers, underscore, hyphen)
	for _, char := range username {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '-') {
			return Error{Field: "username", Message: "can only contain letters, numbers, underscore, and hyphen"}
		}
	}

	return nil
}

func Email(email string) error {
	// Trim whitespace
	email = strings.TrimSpace(email)

	// Check if empty
	if email == "" {
		return Error{Field: "email", Message: "cannot be empty"}
	}

	// Check length
	if len(email) > maxEmailLength {
		return Error{Field: "email", Message: fmt.Sprintf("must be at most %d characters", maxEmailLength)}
	}

	// Check format with regex
	if !emailRegex.MatchString(email) {
		return Error{Field: "email", Message: "invalid email format"}
	}

	return nil
}

func Password(password string) error {
	// Don't trim password - whitespace might be intentional

	// Check if empty
	if password == "" {
		return Error{Field: "password", Message: "cannot be empty"}
	}

	// Check minimum length
	if len(password) < minPasswordLength {
		return Error{Field: "password", Message: fmt.Sprintf("must be at least %d characters", minPasswordLength)}
	}

	return nil
}
