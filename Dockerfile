FROM golang:1.25.5-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o rwaf ./cmd/server
RUN CGO_ENABLED=0 GOOS=linux go build -o log-consumer ./cmd/log-consumer

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/rwaf .
COPY --from=builder /app/log-consumer .
COPY configs/ ./configs/
COPY templates/ ./templates/

EXPOSE 8080

CMD ["./rwaf"]
