# Runtime image for authdiff. GoReleaser builds the static binary and places it
# in the build context (see .goreleaser.yml). To build by hand:
#
#   CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o authdiff ./cmd/authdiff
#   docker build -t authdiff .
#   docker run --rm -v "$PWD:/work" -w /work authdiff scan -c authdiff.yaml
FROM gcr.io/distroless/static-debian12:nonroot
COPY authdiff /usr/local/bin/authdiff
USER nonroot:nonroot
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/authdiff"]
CMD ["--help"]
