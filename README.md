# Port Forwarder - WebSocket to TCP Proxy

A C program to forward WebSocket connections to TCP backend, capable of running a child process and lifecycle management.

## Requirements

- OpenSSL 1.0.1e-fips or later (CentOS 6 compatible)
- GCC with C99 support
- Linux kernel with epoll support

## Compilation

### 🐳 Build with Docker (RECOMMENDED - for Ubuntu 24 or other systems)

If you are building on Ubuntu 24 or a non–CentOS 6 system, use Docker to produce a compatible binary:

```bash
./docker-build.sh
```

See details in [README-DOCKER.md](README-DOCKER.md)

**Advantages:**
- Build on any system with Docker
- 100% compatible binary for CentOS 6 (OpenSSL 1.0.1e, glibc 2.17)
- Avoids library version mismatch issues

### Compile Directly on CentOS 6

**Important**: If you build on a system with OpenSSL 3.x but run on CentOS 6 (OpenSSL 1.0.1e), you must build directly on CentOS 6 or use Docker.

**On CentOS 6 server:**
```bash
make
```

Or use the automatic script:
```bash
./build.sh
```

### Manual Compilation on CentOS 6
```bash
gcc -Wall -Wextra -O2 -g -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations \
    -L/usr/lib64 -Wl,-rpath,/usr/lib64 \
    -o portforward portforward.c -lssl -lcrypto
```

### If you encounter the error "libssl.so.3: cannot open shared object file"

This happens if the program is compiled with OpenSSL 3.x but run on a system only having OpenSSL 1.0.1e.

**Solution 1: Recompile on CentOS 6 server**
```bash
make clean
make
```

**Solution 2: Use build.sh**
```bash
./build.sh
```

**Solution 3: Link directly to libssl.so.10**
```bash
gcc -Wall -Wextra -O2 -g -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations \
    -L/usr/lib64 -Wl,-rpath,/usr/lib64 \
    /usr/lib64/libssl.so.10 /usr/lib64/libcrypto.so.10 \
    -o portforward portforward.c
```

**Check linked libraries:**
```bash
ldd ./portforward | grep ssl
```

You should see `libssl.so.10` or `libssl.so.1.0.1e`, NOT `libssl.so.3`.

## Usage

```bash
./portforward -p /pirate/lcserver -H 10.18.14.35:2182,10.18.14.36:2182 \
    -G game20817 -w 10.18.14.34 -l 10.18.14.34 -d pirate20817 -W 8817 -L 9817
```

### Arguments

- `-p <path>`: Directory containing `lcserver_org` or `lcserver` binary
- `-W <port>`: TCP port that lcserver listens on (forwarded via WebSocket)
- `-L <port>`: Second TCP port that lcserver listens on
- `-w <host>`: Listening host for forwarding from `-W`
- `-l <host>`: Listening host for forwarding from `-L`
- Other arguments: passed through to the child process (`lcserver`, replacing `-p` with `lcserver`)

### Port Mapping

The program will create WebSocket listeners:

- **WebSocket (WS)**: `10000 + <port>` (e.g. `-W 8817` → port `18817`)
- **WebSocket Secure (WSS)**: `20000 + <port>` (e.g. `-W 8817` → port `28817`)

Example with `-W 8817` and `-w 10.18.14.34`:
- WS listener: `10.18.14.34:18817` → forward to `10.18.14.34:8817`
- WSS listener: `10.18.14.34:28817` → forward to `10.18.14.34:8817`

Similarly for `-L` and `-l`.

### SSL/TLS Certificate

To use WSS (WebSocket Secure), put certificate files named `portforward.*` in the `cer/` directory at the application root:

- `cer/portforward.pem` (PEM format)
- `cer/portforward.der` (DER format)
- `cer/portforward.p12` (PKCS12 format)
- `cer/portforward.crt` or `cer/portforward.key`

The program will automatically find and load a valid certificate file.

## Features

1. **Process Management:**
   - Automatically run `lcserver_org` (or `lcserver`) in the specified directory
   - Forwards all system signals (SIGTERM, SIGINT, etc.) to the child process
   - Automatically stops when the child process ends

2. **WebSocket Forwarding:**
   - Supports both WebSocket (WS) and WebSocket Secure (WSS)
   - Protocol-compliant WebSocket handshake
   - Automatic ping/pong handling
   - Keep-alive connections

3. **Performance:**
   - Uses epoll for high-performance I/O
   - Supports up to 10,000 concurrent connections
   - Non-blocking I/O
   - TCP keepalive
   - Connection timeout (5 minutes)

## Optimization

The program is optimized for:
- Large number of concurrent connections
- Continuous data sending/receiving
- Keep-alive connections
- Compatibility with OpenSSL 1.0.1e-fips and CentOS 6

## Signal Handling

The program forwards these signals to the child process:
- SIGTERM
- SIGINT
- All other signals

When the child process exits, portforward will also exit automatically.

## Example

Forwarding port 8817 and 9817:

```bash
./portforward -p /pirate/lcserver \
    -w 10.18.14.34 -W 8817 \
    -l 10.18.14.34 -L 9817 \
    -H 10.18.14.35:2182 -G game20817 -d pirate20817
```

This will:
1. Run `/pirate/lcserver/lcserver_org` with arguments `-p lcserver -H ... -G ... -d ...`
2. Listen on:
   - `10.18.14.34:18817` (WS) → `10.18.14.34:8817` (TCP)
   - `10.18.14.34:28817` (WSS) → `10.18.14.34:8817` (TCP)
   - `10.18.14.34:19817` (WS) → `10.18.14.34:9817` (TCP)
   - `10.18.14.34:29817` (WSS) → `10.18.14.34:9817` (TCP)

## Troubleshooting

1. **SSL Error**: Make sure the certificate file exists and is readable
2. **Port conflict**: Make sure required ports are not already in use
3. **Process not running**: Check if `lcserver_org` or `lcserver` exists in the `-p` directory and is executable
