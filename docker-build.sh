#!/bin/bash
# Script để build portforward sử dụng Docker CentOS 6
# Đảm bảo binary tương thích với CentOS 6 / OpenSSL 1.0.1e-fips

set -e

IMAGE_NAME="portforward-builder"
CONTAINER_NAME="portforward-builder-$$"
BUILD_DIR="$(pwd)"
OUTPUT_FILE="portforward"
BUILD_TYPE="debug" # Default build type

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --release)
      BUILD_TYPE="release"
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

echo "Building portforward for CentOS 6 using Docker..."
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Please install Docker first"
    exit 1
fi

# Build Docker image if it doesn't exist
echo "Step 1: Building Docker image (this may take a few minutes)..."
echo "Note: CentOS 6 repositories are archived, download may be slow"
echo "Build type: $BUILD_TYPE"

# Pass build type as build argument
docker build -f Dockerfile.build --build-arg BUILD_TYPE=$BUILD_TYPE -t $IMAGE_NAME . || {
    echo ""
    echo "Failed to build Docker image. Trying alternative Dockerfile..."
    docker build -f Dockerfile.build-alt --build-arg BUILD_TYPE=$BUILD_TYPE -t $IMAGE_NAME . || {
        echo "Both Dockerfiles failed. Please check your Docker setup and network connection."
        exit 1
    }
}

echo ""
echo "Step 2: Extracting binary from Docker container..."

# Create a temporary container to copy files from
TEMP_CONTAINER=$(docker create $IMAGE_NAME)

# Copy the binary out
if docker cp $TEMP_CONTAINER:/build/$OUTPUT_FILE ./$OUTPUT_FILE 2>/dev/null; then
    echo ""
    echo "✓ Build successful! Binary: ./$OUTPUT_FILE"
    echo ""
    echo "Verifying library dependencies inside container (should show libssl.so.10):"
    docker run --rm $IMAGE_NAME ldd /build/$OUTPUT_FILE 2>/dev/null | grep -E "(ssl|crypto)" || echo "(Could not verify inside container)"

    # Try to check on host if possible
    if command -v ldd &> /dev/null && [ -f "./$OUTPUT_FILE" ]; then
        echo ""
        echo "Library dependencies on host:"
        ldd ./$OUTPUT_FILE | grep -E "(ssl|crypto)" || echo "Note: Binary may not run on this host (compiled for CentOS 6)"
    fi
else
    echo "Failed to copy binary from container"
    docker rm $CONTAINER_NAME 2>/dev/null || true
    exit 1
fi

# Cleanup
docker rm $TEMP_CONTAINER 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

echo ""
echo "Done! The binary ./$OUTPUT_FILE is ready for CentOS 6"
echo ""