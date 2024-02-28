FROM golang:1.21 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download && \
  CGO_ENABLED=0 go build -o /go/bin/app ./cmd/controller

FROM gcr.io/distroless/static
EXPOSE 8080 9090
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /go/bin/app /
ENTRYPOINT ["/app"]
