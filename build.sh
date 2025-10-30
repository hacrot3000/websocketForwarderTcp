#!/bin/bash
# Build script for portforward - ensures compatibility with OpenSSL 1.0.1e-fips

echo "Building portforward for CentOS 6 / OpenSSL 1.0.1e-fips..."

# Check for OpenSSL libraries
if [ -f /usr/lib64/libssl.so.10 ]; then
    echo "Found libssl.so.10 - using OpenSSL 1.0.1"
    SSL_LIB_DIR=/usr/lib64
    SSL_LIB_VERSION=10
elif [ -f /usr/lib64/libssl.so.1.0.1e ]; then
    echo "Found libssl.so.1.0.1e - using OpenSSL 1.0.1e"
    SSL_LIB_DIR=/usr/lib64
    SSL_LIB_VERSION=1.0.1e
elif [ -f /usr/lib64/libssl.so.1.0.0 ]; then
    echo "Found libssl.so.1.0.0 - using OpenSSL 1.0.0"
    SSL_LIB_DIR=/usr/lib64
    SSL_LIB_VERSION=1.0.0
else
    echo "Warning: Could not find OpenSSL 1.0.x library"
    echo "Trying generic -lssl -lcrypto..."
    SSL_LIB_DIR=/usr/lib64
    SSL_LIB_VERSION=
fi

# Compile
CC=gcc
CFLAGS="-Wall -Wextra -O2 -g -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations"

if [ -n "$SSL_LIB_VERSION" ]; then
    # Link directly with specific library version
    LDFLAGS="-L${SSL_LIB_DIR} -Wl,-rpath,${SSL_LIB_DIR} ${SSL_LIB_DIR}/libssl.so.${SSL_LIB_VERSION} ${SSL_LIB_DIR}/libcrypto.so.${SSL_LIB_VERSION}"
else
    # Generic linking
    LDFLAGS="-L${SSL_LIB_DIR} -Wl,-rpath,${SSL_LIB_DIR} -lssl -lcrypto"
fi

echo "Compiling with:"
echo "  CFLAGS: $CFLAGS"
echo "  LDFLAGS: $LDFLAGS"
echo ""

$CC $CFLAGS -c portforward.c -o portforward.o
if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

$CC $CFLAGS -o portforward portforward.o $LDFLAGS
if [ $? -ne 0 ]; then
    echo "Linking failed!"
    exit 1
fi

echo ""
echo "Build successful!"
echo ""
echo "Checking linked libraries:"
ldd ./portforward | grep -E "(ssl|crypto)" || echo "  (No ssl/crypto libraries shown - may need to check manually)"

echo ""
echo "To verify OpenSSL version, run:"
echo "  ldd ./portforward | grep ssl"
