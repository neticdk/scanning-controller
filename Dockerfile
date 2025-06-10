FROM golang:1.24@sha256:db5d0afbfb4ab648af2393b92e87eaae9ad5e01132803d80caef91b5752d289c as build

WORKDIR /go/src/app
COPY . .

RUN go mod download && \
  CGO_ENABLED=0 go build -o /go/bin/app ./cmd/controller

FROM gcr.io/distroless/static@sha256:d9f9472a8f4541368192d714a995eb1a99bab1f7071fc8bde261d7eda3b667d8
EXPOSE 8080 9090
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /go/bin/app /
ENTRYPOINT ["/app"]
