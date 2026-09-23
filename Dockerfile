# BaturWhatsApi — static single-binary image
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/batur ./cmd/batur

FROM scratch
COPY --from=build /out/batur /batur
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8080
ENTRYPOINT ["/batur"]
CMD ["serve"]
