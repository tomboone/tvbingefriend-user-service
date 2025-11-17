package logger

import (
	"log/slog"
	"os"
	"tvbingefriend-user-service/internal/config"
)

// Setup creates and configures a structured logger based on the environment
func Setup(cfg *config.Config) *slog.Logger {
	var handler slog.Handler

	if cfg.Environment == "production" {
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
