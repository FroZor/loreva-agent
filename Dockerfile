FROM --platform=$BUILDPLATFORM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/loreva-agent ./cmd/loreva-agent

RUN mkdir -p /out/state

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/loreva-agent /loreva-agent
COPY --from=build --chown=65532:65532 /out/state /var/lib/loreva-agent

ENV LOREVA_STATE_DIR=/var/lib/loreva-agent

USER 65532:65532

ENTRYPOINT ["/loreva-agent"]
CMD ["start"]
