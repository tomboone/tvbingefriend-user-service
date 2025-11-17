package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/smtp"
)

// generateVerificationToken creates a secure random token for email verification
func generateVerificationToken() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Convert to hex string (64 characters)
	return hex.EncodeToString(bytes), nil
}

// sendVerificationEmail sends an email with a verification link
func sendVerificationEmail(config *Config, logger *slog.Logger, toEmail, username, token string) error {
	// Construct verification URL
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", config.AppURL, token)

	// Email subject and body
	subject := "Verify Your TVBingeFriend Account"
	body := fmt.Sprintf(`
Hello %s,

Thank you for registering at TVBingeFriend!

Please verify your email address by clicking the link below:

%s

This link will expire in 24 hours.

If you didn't create this account, please ignore this email.

Best regards,
TVBingeFriend Team
`, username, verifyURL)

	// Construct email message
	message := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n",
		config.EmailFrom, toEmail, subject, body)

	// SMTP authentication
	auth := smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)

	// Send email
	addr := fmt.Sprintf("%s:%d", config.SMTPHost, config.SMTPPort)
	err := smtp.SendMail(addr, auth, config.EmailFrom, []string{toEmail}, []byte(message))
	if err != nil {
		logger.Error("failed to send verification email", "error", err, "to", toEmail)
		return err
	}

	logger.Info("verification email sent", "to", toEmail, "username", username)
	return nil
}
