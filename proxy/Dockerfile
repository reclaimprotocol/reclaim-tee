FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set work directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./

# Build the proxy binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o proxy .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS connections
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/proxy .

# Copy default configuration
COPY proxy-config.json .

# Expose ports
EXPOSE 80 443 5000 8444

# Run the proxy
CMD ["./proxy"] 