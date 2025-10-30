CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=c99

# For compatibility with OpenSSL 1.0.1e-fips and CentOS 6
# OpenSSL 1.0.1 uses deprecated functions, so we need to disable warnings
CFLAGS += -Wno-deprecated-declarations

# For older systems
CFLAGS += -D_GNU_SOURCE

# Force linking with OpenSSL 1.0.1e (libssl.so.10) instead of OpenSSL 3.x
# Check if libssl.so.10 exists, if so link directly, otherwise use generic
ifneq ($(wildcard /usr/lib64/libssl.so.10),)
  # Link directly with OpenSSL 1.0.1e libraries
  LDFLAGS = -L/usr/lib64 -Wl,-rpath,/usr/lib64 \
            /usr/lib64/libssl.so.10 /usr/lib64/libcrypto.so.10
else ifneq ($(wildcard /usr/lib64/libssl.so.1.0.1e),)
  # Link with OpenSSL 1.0.1e (exact version)
  LDFLAGS = -L/usr/lib64 -Wl,-rpath,/usr/lib64 \
            /usr/lib64/libssl.so.1.0.1e /usr/lib64/libcrypto.so.1.0.1e
else
  # Fallback: generic linking (may link with wrong version if OpenSSL 3.x present)
  # WARNING: This may cause runtime errors on CentOS 6!
  LDFLAGS = -L/usr/lib64 -Wl,-rpath,/usr/lib64 -lssl -lcrypto
  $(warning WARNING: Could not find libssl.so.10 or libssl.so.1.0.1e)
  $(warning This may link with OpenSSL 3.x and cause runtime errors on CentOS 6)
  $(warning Consider using build.sh script or compile directly on CentOS 6 server)
endif

TARGET = portforward
SRCS = portforward.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "Checking linked OpenSSL library:"
	@ldd $(TARGET) 2>/dev/null | grep -E "(ssl|crypto)" || echo "Note: Run 'ldd $(TARGET)' to verify library linking"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
