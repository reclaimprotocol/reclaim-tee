# Build Image Stage
FROM golang:alpine AS builder
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
WORKDIR /src
COPY . .
RUN go build -a -installsuffix cgo -ldflags="-w -s" -tags "enclave,netgo,osusergo" -o /bin/tee_1 ./tee_1

# Release Image Stage  
FROM scratch AS app-container
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/tee_1 /bin/tee_1
COPY --from=builder /src/.env /.env
CMD ["/bin/tee_1"]