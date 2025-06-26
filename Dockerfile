# Build Image Stage
FROM golang:alpine AS builder
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
WORKDIR /src
COPY . .
RUN go build -a -installsuffix cgo -ldflags="-w -s" -ldflags="-extldflags=-static" -tags "enclave,netgo,osusergo" -o /bin/tee_t ./tee_t

# Release Image Stage  
FROM scratch AS app-container
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/tee_t /bin/tee_t
COPY --from=builder /src/.env /.env
CMD ["/bin/tee_t"]