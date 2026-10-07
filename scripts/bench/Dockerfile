FROM golang:1.25.5-alpine AS build
WORKDIR /src
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /runner main.go readiness.go
FROM alpine:latest
COPY --from=build /runner /runner
ENTRYPOINT ["/runner"]
