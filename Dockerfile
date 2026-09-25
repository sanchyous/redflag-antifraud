FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/decision-api ./cmd/decision-api

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
RUN adduser -D -u 10001 app
COPY --from=build /out/decision-api /usr/local/bin/decision-api
USER app
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/decision-api"]
