# Multi-stage build for minimal final image
FROM alpine:3.20 AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    autoconf \
    automake \
    libpcap-dev \
    pcre2-dev \
    libnet-dev

# Copy source code
WORKDIR /build
COPY . .

# Build ngrep
RUN ./configure --enable-ipv6 --enable-pcre2 --enable-tcpkill --prefix=/usr && \
    make && \
    make install DESTDIR=/install

# Final minimal image
FROM alpine:3.20

# Install only runtime dependencies
RUN apk add --no-cache \
    libpcap \
    pcre2 \
    libnet

# Copy built binary from builder
COPY --from=builder /install/usr/bin/ngrep /usr/bin/ngrep
COPY --from=builder /install/usr/share/man/man8/ngrep.8 /usr/share/man/man8/ngrep.8

# ngrep needs to run as root or with NET_CAP_RAW capability
# Alpine uses musl libc which is smaller than glibc
USER root

ENTRYPOINT ["/usr/bin/ngrep"]
CMD ["-h"]
