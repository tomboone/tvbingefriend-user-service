package main

import (
	"log/slog"
	"os"
)

// setupLogger creates and configures a structured logger based on the environment
func setupLogger(config *Config) *slog.Logger {
	var handler slog.Handler

	if config.Environment == "production" {
		// JSON format for production
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	} else {
		// Human-readable format for development
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}

	return slog.New(handler)
}
