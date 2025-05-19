FROM golang:1.24@sha256:86b4cff66e04d41821a17cea30c1031ed53e2635e2be99ae0b4a7d69336b5063 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download && \
  CGO_ENABLED=0 go build -o /go/bin/app ./cmd/controller

FROM gcr.io/distroless/static
EXPOSE 8080 9090
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /go/bin/app /
ENTRYPOINT ["/app"]
