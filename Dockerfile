FROM docker.io/golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -ldflags="-s -w" -o /out/com.eduardoramos.zoraxy.certwarden ./cmd/cert-sync

FROM scratch AS export
COPY --from=builder /out/com.eduardoramos.zoraxy.certwarden /
