# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files first (for better layer caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
# CGO_ENABLED=0 creates a static binary (no C dependencies)
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service .

# Runtime stage
FROM alpine:latest

# Install CA certificates (needed for HTTPS requests if you add them later)
RUN apk --no-cache add ca-certificates

# Create a non-root user for security
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/auth-service .

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port (Container Apps will use this)
EXPOSE 8080

# Run the service
CMD ["./auth-service"]