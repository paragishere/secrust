# Build Stage
FROM golang:1.25 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o secrust ./cmd

# Runtime Stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/secrust .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

EXPOSE 8080

CMD ["./secrust"]