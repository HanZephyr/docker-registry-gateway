# syntax=docker/dockerfile:1
FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/drg ./cmd/drg

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S drg && adduser -S -G drg drg
COPY --from=build /out/drg /usr/local/bin/drg
USER drg
ENTRYPOINT ["drg"]
CMD ["serve", "--config", "/etc/drg/drg.yaml"]
