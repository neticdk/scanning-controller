FROM golang:1.24@sha256:10c131810f80a4802c49cab0961bbe18a16f4bb2fb99ef16deaa23e4246fc817 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download && \
  CGO_ENABLED=0 go build -o /go/bin/app ./cmd/controller

FROM gcr.io/distroless/static@sha256:b7b9a6953e7bed6baaf37329331051d7bdc1b99c885f6dbeb72d75b1baad54f9
EXPOSE 8080 9090
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /go/bin/app /
ENTRYPOINT ["/app"]
