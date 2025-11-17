package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/smtp"
	"tvbingefriend-user-service/internal/config"
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

// SendVerificationEmail sends an email with a verification link
func SendVerificationEmail(cfg *config.Config, logger *slog.Logger, toEmail, username, token string) error {
	// Construct verification URL
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", cfg.AppURL, token)

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
	return sendEmail(cfg, logger, toEmail, subject, body)
}

// SendPasswordResetEmail sends a password reset email with the reset token
func SendPasswordResetEmail(cfg *config.Config, logger *slog.Logger, toEmail, token string) error {
	// Construct reset link
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", cfg.AppURL, token)

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
	return sendEmail(cfg, logger, toEmail, subject, body)
}

// sendEmail is a generic helper that sends an email via SMTP
func sendEmail(cfg *config.Config, logger *slog.Logger, toEmail, subject, body string) error {
	// Construct email message
	message := fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n",
		cfg.EmailFrom, toEmail, subject, body)

	// SMTP authentication
	auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)

	// Send email
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	err := smtp.SendMail(addr, auth, cfg.EmailFrom, []string{toEmail}, []byte(message))
	if err != nil {
		logger.Error("failed to send email", "error", err, "to", toEmail)
		return err
	}

	logger.Info("email sent successfully", "to", toEmail)
	return nil
}
