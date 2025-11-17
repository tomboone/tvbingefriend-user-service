package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/smtp"
)

// GenerateSecureToken creates a secure random token for email verification
func GenerateSecureToken() (string, error) {
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
	body := fmt.Sprintf(`Hello %s,

Thank you for registering at TVBingeFriend!

Please verify your email address by clicking the link below:

%s

This link will expire in 24 hours.

If you didn't create this account, please ignore this email.

Best regards,
TVBingeFriend Team`, username, verifyURL)

	// Use the generic email sender
	return sendEmail(config, logger, toEmail, subject, body)
}

// sendPasswordResetEmail sends a password reset email with the reset token
func sendPasswordResetEmail(config *Config, logger *slog.Logger, toEmail, token string) error {
	// Construct reset link
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", config.AppURL, token)

	// Email subject and body
	subject := "Password Reset Request - TVBingeFriend"
	body := fmt.Sprintf(`Hello,

You requested to reset your password for TVBingeFriend.

Click the link below to reset your password (expires in 1 hour):
%s

If you didn't request this, please ignore this email.

Best regards,
TVBingeFriend Team`, resetLink)

	// Use the generic email sender
	return sendEmail(config, logger, toEmail, subject, body)
}

// sendEmail is a generic helper that sends an email via SMTP
func sendEmail(config *Config, logger *slog.Logger, toEmail, subject, body string) error {
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
		logger.Error("failed to send email", "error", err, "to", toEmail)
		return err
	}

	logger.Info("email sent successfully", "to", toEmail)
	return nil
}
