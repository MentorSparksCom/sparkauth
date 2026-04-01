# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary with CGO disabled for scratch image
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

# Install CA certificates
RUN apk --no-cache add ca-certificates

# Copy the binary
COPY --from=builder /app/main /main

# Copy static files and templates
COPY --from=builder /app/static /static
COPY --from=builder /app/templates /templates

# Expose port (adjust if needed, based on your config)
EXPOSE 9000

# Run the binary
CMD ["/main"]