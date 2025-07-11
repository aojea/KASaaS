FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
ARG TARGETARCH
ARG GOARCH=${TARGETARCH} CGO_ENABLED=0

# cache go modules
WORKDIR /go/src/app
COPY go.mod go.sum .
RUN go mod download

# build
COPY . .
RUN go build -o /go/bin/kasaas ./cmd/kasaas

# copy binary onto base image
FROM gcr.io/distroless/base-debian12
COPY --from=builder --chown=root:root /go/bin/kasaas /kasaas
CMD ["/kasaas"]
