FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o /certforge-connector .

FROM scratch
COPY --from=builder /certforge-connector /certforge-connector
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/certforge-connector"]
CMD ["-config", "/etc/certforge-connector/certforge-connector.yaml"]
