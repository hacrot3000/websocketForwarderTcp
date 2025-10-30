# Portforward Build Guide

## OpenSSL Issue

The program must be compiled with **OpenSSL 1.0.1e-fips** to run on **CentOS 6**.
If it’s compiled on a system with **OpenSSL 3.x** (such as Ubuntu 24), the resulting binary **will not run** on CentOS 6.

---

## Solutions

### **Option 1: Build with Docker (RECOMMENDED for Ubuntu 24 or any other system)**

Build a CentOS 6–compatible binary from Ubuntu 24 or any system that supports Docker:

```bash
./docker-build.sh
```

Or see the detailed guide in [README-DOCKER.md](README-DOCKER.md).

**Advantages:**

* Can build from any system with Docker installed
* Guaranteed 100% compatibility with CentOS 6
* Automatically links against OpenSSL 1.0.1e and glibc 2.17

---

### **Option 2: Build directly on a CentOS 6 server**

```bash
cd /path/to/forwarder
make clean
make
```

---

### **Option 3: Use `build.sh` (only on CentOS 6)**

```bash
./build.sh
```

The script automatically detects and links against the correct OpenSSL version.

---

### **Option 4: Manual build with direct linking (only on CentOS 6)**

```bash
gcc -Wall -Wextra -O2 -g -std=c99 -D_GNU_SOURCE -Wno-deprecated-declarations \
    -L/usr/lib64 -Wl,-rpath,/usr/lib64 \
    /usr/lib64/libssl.so.10 /usr/lib64/libcrypto.so.10 \
    -o portforward portforward.c
```

---

### **Option 5: Check and fix after build**

If the program fails with an error like `libssl.so.3`, check your linked libraries:

```bash
ldd ./portforward | grep ssl
```

If you see `libssl.so.3`, you need to rebuild using one of the methods above.

---

## Building on another system (Ubuntu 24, etc.) for deployment to CentOS 6

**USE DOCKER** – This is the simplest and most reliable method:

```bash
./docker-build.sh
```

For details, see [README-DOCKER.md](README-DOCKER.md).

---

### **Why use Docker**

1. **glibc version mismatch:**
   Binaries built on Ubuntu 24 (glibc 2.35+) will **not run** on CentOS 6 (glibc 2.12–2.17).
2. **Library compatibility:**
   System libraries differ significantly across distributions.
3. **OpenSSL version:**
   CentOS 6 only provides OpenSSL 1.0.1e (no 3.x support).

**Docker solves all of these issues** by building inside a genuine CentOS 6 environment.

---

## Verify after build

After a successful build, check your linked libraries:

```bash
ldd ./portforward | grep -E "(ssl|crypto)"
```

**Expected output:**

```
libssl.so.10 => /usr/lib64/libssl.so.10 (0x...)
libcrypto.so.10 => /usr/lib64/libcrypto.so.10 (0x...)
```

❌ **Must NOT be:**

```
libssl.so.3 => ...
```
