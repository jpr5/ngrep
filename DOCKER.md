# ngrep Docker Container

ngrep is available as a Docker container from GitHub Container Registry (GHCR).

## Quick Start

```bash
# Pull the latest image
docker pull ghcr.io/jpr5/ngrep:latest

# Run ngrep (requires NET_RAW capability for packet capture)
docker run --rm --net=host --cap-add=NET_RAW ghcr.io/jpr5/ngrep:latest -q 'GET|POST' tcp port 80
```

## Available Tags

- `latest` - Latest build from master branch
- `1.48`, `1.48.0` - Specific version tags
- `1` - Latest v1.x release
- `master` - Latest master branch build
- `master-<sha>` - Specific commit from master

## Usage Examples

### Basic HTTP Traffic Monitoring

```bash
docker run --rm --net=host --cap-add=NET_RAW \
  ghcr.io/jpr5/ngrep:latest \
  -q 'GET|POST' tcp port 80
```

### DNS Query Monitoring

```bash
docker run --rm --net=host --cap-add=NET_RAW \
  ghcr.io/jpr5/ngrep:latest \
  -q -W byline port 53
```

### Monitor Specific Interface

```bash
docker run --rm --net=host --cap-add=NET_RAW \
  ghcr.io/jpr5/ngrep:latest \
  -d eth0 -q '' tcp port 443
```

### Save to PCAP File

```bash
docker run --rm --net=host --cap-add=NET_RAW \
  -v $(pwd):/data \
  ghcr.io/jpr5/ngrep:latest \
  -O /data/capture.pcap -q '' port 80
```

### Read from PCAP File

```bash
docker run --rm \
  -v $(pwd):/data \
  ghcr.io/jpr5/ngrep:latest \
  -I /data/capture.pcap -q 'User-Agent'
```

## Network Modes

### Host Network (Recommended)

Use `--net=host` to capture traffic on the host's network interfaces:

```bash
docker run --rm --net=host --cap-add=NET_RAW ghcr.io/jpr5/ngrep:latest
```

**Pros**: Can see all host traffic, works with all interfaces  
**Cons**: Less isolation

### Bridge Network

Capture traffic within the container's network namespace:

```bash
docker run --rm --cap-add=NET_RAW ghcr.io/jpr5/ngrep:latest -d eth0
```

**Pros**: Better isolation  
**Cons**: Only sees container's own traffic

### Container Network

Monitor traffic from another container:

```bash
# Start a container
docker run -d --name web nginx

# Monitor its traffic
docker run --rm --net=container:web --cap-add=NET_RAW \
  ghcr.io/jpr5/ngrep:latest \
  -q '' port 80
```

## Required Capabilities

ngrep requires the `NET_RAW` capability to capture packets. You must run with:

```bash
--cap-add=NET_RAW
```

Or for full privileges (not recommended):

```bash
--privileged
```

## Building Locally

### Alpine-based (Default, Smallest)

```bash
# Clone the repository
git clone https://github.com/jpr5/ngrep.git
cd ngrep

# Build the Alpine-based image (~20-30MB)
docker build -t ngrep:local .

# Run it
docker run --rm --net=host --cap-add=NET_RAW ngrep:local --help
```

### Ubuntu-based (Alternative)

If you need glibc compatibility or prefer Ubuntu:

```bash
# Build the Ubuntu-based image (~100MB)
docker build -f Dockerfile.ubuntu -t ngrep:ubuntu .

# Run it
docker run --rm --net=host --cap-add=NET_RAW ngrep:ubuntu --help
```

**Size Comparison:**
- Alpine: ~20-30MB compressed, ~60MB uncompressed
- Ubuntu: ~100MB compressed, ~250MB uncompressed

## Multi-Architecture Support

The container is built for multiple architectures:

- `linux/amd64` (x86_64)
- `linux/arm64` (ARM64/aarch64)

Docker will automatically pull the correct image for your platform.

## Image Details

- **Base**: Alpine Linux 3.20
- **Size**: ~20-30MB (compressed)
- **C Library**: musl libc (smaller and more secure than glibc)
- **Runtime Dependencies**: libpcap, pcre2, libnet
- **Build**: Multi-stage for minimal final image
- **Architectures**: linux/amd64, linux/arm64

## Security Considerations

1. **Capabilities**: Only grant `NET_RAW`, not full `--privileged`
2. **Network Mode**: Use `--net=host` only when necessary
3. **User**: Container runs as root (required for packet capture)
4. **Volumes**: Mount volumes read-only when possible

## Troubleshooting

### Permission Denied

```
ngrep: pcap_open_live(): socket: Operation not permitted
```

**Solution**: Add `--cap-add=NET_RAW` to your docker run command.

### musl libc Compatibility

The default Alpine-based image uses musl libc instead of glibc. This is smaller and more secure, but if you encounter compatibility issues with certain tools or libraries, use the Ubuntu-based image:

```bash
docker build -f Dockerfile.ubuntu -t ngrep:ubuntu .
```

### No Interfaces Found

```
ngrep: can't get list of interfaces
```

**Solution**: Use `--net=host` to access host interfaces.

### Interface Not Found

```
ngrep: unknown interface eth0
```

**Solution**: List available interfaces first:

```bash
docker run --rm --net=host --cap-add=NET_RAW \
  ghcr.io/jpr5/ngrep:latest -L
```

## Kubernetes

Deploy ngrep as a DaemonSet to monitor cluster traffic:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ngrep
spec:
  selector:
    matchLabels:
      app: ngrep
  template:
    metadata:
      labels:
        app: ngrep
    spec:
      hostNetwork: true
      containers:
      - name: ngrep
        image: ghcr.io/jpr5/ngrep:latest
        args: ["-q", "GET|POST", "tcp", "port", "80"]
        securityContext:
          capabilities:
            add: ["NET_RAW"]
```

## Docker Compose

```yaml
version: '3.8'

services:
  ngrep:
    image: ghcr.io/jpr5/ngrep:latest
    network_mode: host
    cap_add:
      - NET_RAW
    command: ["-q", "GET|POST", "tcp", "port", "80"]
    restart: unless-stopped
```

## Links

- **GitHub Repository**: https://github.com/jpr5/ngrep
- **Container Registry**: https://github.com/jpr5/ngrep/pkgs/container/ngrep
- **Documentation**: https://github.com/jpr5/ngrep/blob/master/README.md
