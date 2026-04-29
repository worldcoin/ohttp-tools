# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ohttp-probe .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /ohttp-probe /ohttp-probe
ENTRYPOINT ["/ohttp-probe"]
