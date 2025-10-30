# Build Portforward with Docker

Guide to build a CentOS 6-compatible binary on Ubuntu 24 or other systems.

## Requirements

- Docker installed
- Permission to run Docker (be in the docker group or use sudo)

## How to Build

### Method 1: Use the automatic script (RECOMMENDED)

```bash
./docker-build.sh
```

The script will:
1. Build a Docker image based on CentOS 6
2. Compile portforward inside the container
3. Copy the binary to the host
4. Verify library dependencies

### Method 2: Manual Build

```bash
# Build Docker image
docker build -f Dockerfile.build -t portforward-builder .

# Build the binary inside the container
docker run --rm portforward-builder make

# Copy the binary out
docker create --name temp portforward-builder
docker cp temp:/build/portforward ./portforward
docker rm temp
```

### Method 3: Use the alternative Dockerfile (if method 1 fails)

```bash
docker build -f Dockerfile.build-alt -t portforward-builder .
docker run --rm -v $(pwd):/output portforward-builder cp /build/portforward /output/
```

## Verify the Binary

After building, check:

```bash
# Check library dependencies
ldd ./portforward | grep ssl

# Expected result:
# libssl.so.10 => /usr/lib64/libssl.so.10
# libcrypto.so.10 => /usr/lib64/libcrypto.so.10
```

**NOTE:** The binary is built for CentOS 6 and will NOT run on Ubuntu 24. The check is just to ensure it's linked against libssl.so.10.

## Deploy to CentOS 6 Server

```bash
# Copy the binary to the server
scp ./portforward user@centos6-server:/path/to/destination/

# On the server, run:
chmod +x ./portforward
./portforward -w 10.9.4.10 -l 10.9.4.10 -W 8001 -L 8002 ...
```

## Troubleshooting

### Error: Cannot connect to Docker daemon

```bash
sudo usermod -aG docker $USER
# Then logout and login again
```

Or run with sudo:
```bash
sudo ./docker-build.sh
```

### Error: CentOS 6 repository not accessible

The Dockerfile is already configured to use vault.centos.org. If you still see errors:

1. Check your network connection
2. Try building at another time (the vault server might be temporarily down)

### Error: yum install fails

This could be due to the CentOS 6 vault server being slow. Please wait and try again later.

### Binary does not run on CentOS 6

Check:
```bash
# On CentOS 6 server
ldd ./portforward
file ./portforward
```

The binary must be x86_64 ELF and linked with libssl.so.10.

## Building on Other Systems

The binary built in the CentOS 6 container will:
- Be compatible with glibc 2.12–2.17
- Be linked against OpenSSL 1.0.1e
- Run successfully on CentOS 6

It will NOT run on:
- Ubuntu 20+ (glibc too new)
- CentOS 7+ with some library versions
- Systems without OpenSSL 1.0.1e
