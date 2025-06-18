FROM golang:1.23-alpine3.20 AS build_deps
ARG TARGETARCH

RUN apk add --no-cache git=2.45.3-r0

WORKDIR /workspace
ENV GO111MODULE=on

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:3.20
LABEL maintainer="ykachube <yury_kachubeyeu@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/ykachube/cert-manager-webhook-servercore"

RUN apk add --no-cache ca-certificates=20241121-r1

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
