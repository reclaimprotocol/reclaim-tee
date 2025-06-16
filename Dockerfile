# Build Image Stage
FROM golang:alpine AS app-builder
ENV CGO_ENABLED=1
RUN apk add --no-cache --update gcc g++
WORKDIR /usr/src/go-enclave-app
COPY . .
RUN go build -v -o /usr/local/bin/go-enclave-app main.go

# Release Image Stage
FROM alpine:latest AS app-container

COPY --from=app-builder /usr/local/bin/go-enclave-app /usr/local/bin/go-enclave-app
CMD ["/usr/local/bin/go-enclave-app"]