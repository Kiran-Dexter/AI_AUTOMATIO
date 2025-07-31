#!/bin/bash
set -euo pipefail

# ========= DEPENDENCY CHECK =========
DEPENDENCIES=(gcc make pcre-devel zlib-devel openssl-devel)

echo "Checking for required build dependencies..."
MISSING_PKGS=()
for pkg in "${DEPENDENCIES[@]}"; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
        echo "Missing: $pkg"
        MISSING_PKGS+=("$pkg")
    fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo ""
    echo "The following packages are missing:"
    for pkg in "${MISSING_PKGS[@]}"; do
        echo " - $pkg"
    done
    echo "Please install them before continuing."
    exit 1
fi

# ========= USER INPUT =========
read -rp "Enter full installation path (e.g. /data/nginx1.26): " INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR%/}"  # Remove trailing slash if any

if [[ ! -d "$INSTALL_DIR" ]]; then
    echo "Creating install directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
fi

# ========= FIND TARBALL =========
echo "Searching for nginx tarball in current directory..."
TARBALLS=(nginx-*.tar.gz)
if [[ ${#TARBALLS[@]} -eq 0 ]]; then
    echo "No nginx-*.tar.gz tarball found."
    exit 1
elif [[ ${#TARBALLS[@]} -gt 1 ]]; then
    echo "Multiple nginx tarballs found. Keep only one."
    exit 1
fi

NGINX_TAR="${TARBALLS[0]}"
NGINX_VERSION=$(echo "$NGINX_TAR" | sed -E 's/nginx-([0-9.]+)\.tar\.gz/\1/')
NGINX_SRC_DIR="nginx-${NGINX_VERSION}"

echo "Using tarball: $NGINX_TAR"
echo "Detected version: $NGINX_VERSION"

# ========= EXTRACT & BUILD =========
tar -xf "$NGINX_TAR"
cd "$NGINX_SRC_DIR"

echo "Configuring nginx build..."
./configure \
    --prefix="${INSTALL_DIR}" \
    --conf-path="${INSTALL_DIR}/nginx.conf" \
    --sbin-path="${INSTALL_DIR}/sbin/nginx" \
    --pid-path="${INSTALL_DIR}/nginx.pid" \
    --lock-path="${INSTALL_DIR}/nginx.lock" \
    --http-log-path="${INSTALL_DIR}/logs/access.log" \
    --error-log-path="${INSTALL_DIR}/logs/error.log" \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_gzip_static_module \
    --with-stream \
    --with-pcre

echo "Building nginx..."
make -j"$(nproc)"

echo "Installing to: $INSTALL_DIR"
make install

# ========= CONFIG FILE =========
echo "Creating default nginx.conf..."
cat > "${INSTALL_DIR}/nginx.conf" <<EOF
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    access_log    ${INSTALL_DIR}/logs/access.log;
    error_log     ${INSTALL_DIR}/logs/error.log;

    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       80;
        server_name  localhost;

        location / {
            root   ${INSTALL_DIR}/html;
            index  index.html index.htm;
        }
    }
}
EOF

echo ""
echo "NGINX ${NGINX_VERSION} has been installed successfully in:"
echo "  $INSTALL_DIR"
echo ""
echo "To start NGINX:"
echo "  ${INSTALL_DIR}/sbin/nginx -c ${INSTALL_DIR}/nginx.conf"
