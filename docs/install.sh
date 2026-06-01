#!/bin/bash

set -e

# ============================================================
# Phantom Installer
# https://github.com/phantom-go/phantom
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[x]${NC} $1"; exit 1; }
prompt()  { echo -e "${BLUE}[?]${NC} $1"; }

PHANTOM_VERSION="${PHANTOM_VERSION:-}"
PHANTOM_DIR="/usr/local/bin"
CONFIG_DIR="/etc/phantom"
SERVICE_FILE="/etc/systemd/system/phantom-server.service"

# ============================================================
# 0. Fetch latest version
#
# Used by [1] Install to know which release binary to download.
# Management actions ([3]/[4]/[5]) don't need this — they only edit
# the local config — so a network failure here should not block the
# menu from showing.
# ============================================================
fetch_version() {
    if [ -n "$PHANTOM_VERSION" ]; then
        info "Using specified version: $PHANTOM_VERSION"
        return
    fi
    info "Fetching latest Phantom version..."
    PHANTOM_VERSION=$(curl -sI --max-time 10 https://github.com/phantom-go/phantom/releases/latest | grep -i location | grep -oP 'tag/\K[^"[:space:]]+' | head -1 | tr -d '\r')
    if [ -z "$PHANTOM_VERSION" ]; then
        warn "Could not fetch latest version (network issue or GitHub unreachable)."
        warn "Install action will be unavailable; management actions still work on the local config."
        PHANTOM_VERSION="unknown"
    else
        info "Latest version: $PHANTOM_VERSION"
    fi
}

# ============================================================
# 1. Check root
# ============================================================
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root: sudo bash install.sh"
    fi
}

# ============================================================
# 2. Detect OS
# ============================================================
detect_os() {
    if [ -f /etc/debian_version ]; then
        OS="debian"
        PKG="apt-get"
        WEB_ROOT="/var/www/html"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        PKG="yum"
        WEB_ROOT="/usr/share/nginx/html"
    else
        error "Unsupported OS. Only Debian/Ubuntu/CentOS are supported."
    fi
    info "Detected OS: $OS"
}

# ============================================================
# 3. Detect SSH port
# ============================================================
detect_ssh_port() {
    SSH_PORT=$(echo "$SSH_CONNECTION" | awk '{print $4}')
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(ss -tnlp | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
    fi
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=22
    fi
    warn "Detected SSH port: $SSH_PORT — this port will be kept open in firewall."
}

# ============================================================
# 4. Ask domain
# ============================================================
ask_domain() {
    echo ""
    prompt "Do you have a domain name pointing to this server? (recommended for best security)"
    read -rp "Domain name (leave empty to use IP only): " DOMAIN

    if [ -n "$DOMAIN" ]; then
        info "Checking DNS for $DOMAIN..."
        SERVER_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
        DOMAIN_IP=$(dig +short "$DOMAIN" | tail -1)

        if [ "$SERVER_IP" != "$DOMAIN_IP" ]; then
            warn "DNS mismatch: $DOMAIN resolves to $DOMAIN_IP, but this server IP is $SERVER_IP"
            warn "Please update your DNS A record to $SERVER_IP and re-run this installer."
            error "DNS check failed."
        fi
        info "DNS check passed: $DOMAIN -> $SERVER_IP"
        USE_DOMAIN=true
    else
        warn "No domain provided. Will use self-signed certificate (lower security)."
        USE_DOMAIN=false
        SERVER_IP=$(curl -s https://api.ipify.org || curl -s https://ifconfig.me)
    fi
}

# ============================================================
# 5. Install dependencies
# ============================================================
install_deps() {
    info "Installing dependencies..."
    if [ "$OS" = "debian" ]; then
        apt-get update -qq
        apt-get install -y -qq nginx ufw curl dnsutils openssl qrencode uuid-runtime
        if [ "$USE_DOMAIN" = true ]; then
            apt-get install -y -qq certbot
        fi
    else
        if ! rpm -q epel-release >/dev/null 2>&1; then
            yum install -y -q epel-release || true
        fi
        yum install -y -q nginx curl bind-utils openssl qrencode util-linux
        if [ "$USE_DOMAIN" = true ]; then
            yum install -y -q certbot
        fi
        if ! command -v ufw &>/dev/null; then
            warn "UFW is not natively available on RedHat. Firewall configuration will be skipped on this OS."
            warn "Consider configuring firewalld manually to allow ports 80, 443/tcp, and 443/udp."
        fi
    fi
    info "Dependencies installed."
}

# ============================================================
# 6. Download phantom-server
# ============================================================
download_phantom() {
    info "Downloading phantom-server $PHANTOM_VERSION..."
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)       error "Unsupported architecture: $ARCH" ;;
    esac

    URL="https://github.com/phantom-go/phantom/releases/download/${PHANTOM_VERSION}/phantom-${PHANTOM_VERSION}-linux-${ARCH}.tar.gz"

    if ! curl -sL "$URL" -o /tmp/phantom.tar.gz; then
        error "Failed to download binary from GitHub. Please check network connection."
    fi

    tar -xzf /tmp/phantom.tar.gz -C /tmp
    mv /tmp/phantom-server "$PHANTOM_DIR/phantom-server"
    chmod +x "$PHANTOM_DIR/phantom-server"
    info "phantom-server installed to $PHANTOM_DIR/phantom-server"
}

# ============================================================
# 7. Configure Nginx (Preserve default welcome page, enable HTTP/2)
# ============================================================
configure_nginx() {
    info "Configuring Nginx fallback server (default welcome page with HTTP/2)..."

    mkdir -p "$WEB_ROOT"
    if [ ! -f "$WEB_ROOT/index.html" ] && [ ! -f "$WEB_ROOT/index.nginx-debian.html" ]; then
        cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title>
<style>html{color-scheme:light dark;}body{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif;}</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>
EOF
    fi

    local nginx_conf=""
    if [ "$OS" = "debian" ]; then
        nginx_conf="/etc/nginx/sites-available/default"
    else
        nginx_conf="/etc/nginx/conf.d/default.conf"
        rm -f /etc/nginx/conf.d/welcome.conf 2>/dev/null || true
    fi

    cat > "$nginx_conf" <<EOF
server {
    listen 127.0.0.1:8080 default_server;
    http2 on;
    server_name _;

    root $WEB_ROOT;
    index index.html index.htm index.nginx-debian.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    if [ "$OS" = "debian" ]; then
        ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null || true
    fi

    if ! nginx -t 2>/dev/null; then
        warn "Modern HTTP/2 syntax not supported, falling back to HTTP/1.1 only."
        cat > "$nginx_conf" <<EOF
server {
    listen 127.0.0.1:8080 default_server;
    server_name _;

    root $WEB_ROOT;
    index index.html index.htm index.nginx-debian.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    fi

    systemctl restart nginx

    if [ "$USE_DOMAIN" = true ]; then
        info "Obtaining Let's Encrypt certificate for $DOMAIN via Certbot..."
        systemctl stop nginx || true
        certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos \
            --register-unsafely-without-email 2>/dev/null || true
        systemctl start nginx
    fi
    info "Nginx fallback environment configured."
}

# ============================================================
# 8. Generate password and config
# ============================================================
generate_config() {
    mkdir -p "$CONFIG_DIR"

    if [ -r /proc/sys/kernel/random/uuid ]; then
        PASSWORD=$(cat /proc/sys/kernel/random/uuid)
    elif command -v uuidgen &>/dev/null; then
        PASSWORD=$(uuidgen | tr '[:upper:]' '[:lower:]')
    else
        PASSWORD=$(openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')
    fi

    if [ "$USE_DOMAIN" = true ] && [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        if [ "$USE_DOMAIN" = true ]; then
            warn "Certbot failed to obtain certificate. Falling back to self-signed."
            USE_DOMAIN=false
        fi
        CERT_FILE="$CONFIG_DIR/server.crt"
        KEY_FILE="$CONFIG_DIR/server.key"
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -days 365 -nodes \
            -subj "/CN=phantom" 2>/dev/null
        chmod 600 "$KEY_FILE"
    fi

    cat > "$CONFIG_DIR/config.json" <<EOF
{
  "server": {
    "listen": ":443",
    "passwords": ["$PASSWORD"],
    "cert_file": "$CERT_FILE",
    "key_file": "$KEY_FILE",
    "fallback_addr": "127.0.0.1:8080"
  }
}
EOF
    chmod 600 "$CONFIG_DIR/config.json"
    info "Config generated at $CONFIG_DIR/config.json"
}

# ============================================================
# 9. Configure firewall
# ============================================================
configure_firewall() {
    if ! command -v ufw &>/dev/null; then
        return
    fi

    info "Configuring UFW firewall..."
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null
    ufw default allow outgoing > /dev/null
    ufw allow "$SSH_PORT/tcp" comment "SSH" > /dev/null
    ufw allow 80/tcp comment "HTTP" > /dev/null
    ufw allow 443/tcp comment "HTTPS" > /dev/null
    ufw allow 443/udp comment "QUIC" > /dev/null

    echo ""
    warn "About to enable UFW firewall."
    warn "SSH port $SSH_PORT will remain open."
    prompt "Please open a NEW terminal and verify you can still SSH in, then press Enter to continue."
    read -r

    ufw --force enable > /dev/null
    info "Firewall enabled."
}

# ============================================================
# 10. Install systemd service
# ============================================================
install_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Phantom Proxy Server
After=network.target nginx.service

[Service]
Type=simple
ExecStart=$PHANTOM_DIR/phantom-server --config $CONFIG_DIR/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable phantom-server > /dev/null
    systemctl restart phantom-server
    info "phantom-server service installed and started."
}

# ============================================================
# 11. Print connection info
# ============================================================
print_info() {
    if [ "$USE_DOMAIN" = true ]; then
        HOST="$DOMAIN"
        ALLOW_INSECURE=0
    else
        HOST="$SERVER_IP"
        ALLOW_INSECURE=1
    fi

    PHANTOM_URI="phantom://${PASSWORD}@${HOST}:443?type=tcp&security=tls&sni=${HOST}&allowInsecure=${ALLOW_INSECURE}#Phantom"
    TROJAN_URI="trojan://${PASSWORD}@${HOST}:443?security=tls&sni=${HOST}&allowInsecure=${ALLOW_INSECURE}#Phantom"

    echo ""
    echo "============================================================"
    echo -e "${GREEN}  Phantom installed successfully!${NC}"
    echo "============================================================"
    echo ""
    echo "  Server  : $HOST:443"
    echo "  Password: $PASSWORD"
    echo "  Mode    : TCP / QUIC Dual Stack"
    echo ""
    echo -e "${GREEN}  Native URI (recommended):${NC}"
    echo "  $PHANTOM_URI"
    echo ""
    if command -v qrencode &>/dev/null; then
        echo "  [Native QR Code]"
        qrencode -t ANSIUTF8 "$PHANTOM_URI"
        echo ""
    fi
    echo -e "${YELLOW}  Legacy compatibility URI (Trojan clients):${NC}"
    echo "  $TROJAN_URI"
    echo ""
    echo -e "${YELLOW}  Note: Trojan compatibility mode does not support all${NC}"
    echo -e "${YELLOW}  Phantom features (QUIC, metrics, hot reload).${NC}"
    echo -e "${YELLOW}  Native Phantom clients will be available soon.${NC}"
    echo ""
    echo "============================================================"
    echo ""
    info "Config saved at: $CONFIG_DIR/config.json"
    info "To reload config: kill -HUP \$(pgrep phantom-server)"
    info "To check status: systemctl status phantom-server"
    echo ""
}

# ============================================================
# Post-install management helpers
# ============================================================

# Require that Phantom is already installed. Used by all management
# actions to avoid showing useless errors deep inside the function.
require_installed() {
    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        warn "Phantom is not installed. Run [1] Install first."
        return 1
    fi
    return 0
}

# Generate a UUID-format password using the same fallback chain as the
# fresh install path, so existing and new entries are visually consistent.
new_password() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        openssl rand -hex 16 | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/'
    fi
}

# Recover the deployment's HOST (domain or IP) and ALLOW_INSECURE flag
# from the installed config. Sets globals HOST / ALLOW_INSECURE.
# The cert path is the discriminator: Let's Encrypt path -> domain mode,
# self-signed under $CONFIG_DIR -> IP mode.
resolve_host_mode() {
    local cert_file
    cert_file=$(grep -oP '"cert_file"\s*:\s*"\K[^"]+' "$CONFIG_DIR/config.json" 2>/dev/null || true)

    if echo "$cert_file" | grep -q '/etc/letsencrypt/live/'; then
        HOST=$(echo "$cert_file" | sed -E 's|/etc/letsencrypt/live/([^/]+)/.*|\1|')
        ALLOW_INSECURE=0
    else
        # Self-signed cert path — recover the public IP at runtime.
        # Validate the response looks like an IP literal; some hosts behind
        # captive portals or proxies return HTML or error text instead.
        local ip
        ip=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)
        if ! echo "$ip" | grep -qE '^([0-9]+\.){3}[0-9]+$|^[0-9a-fA-F:]+$'; then
            ip=$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)
        fi
        if ! echo "$ip" | grep -qE '^([0-9]+\.){3}[0-9]+$|^[0-9a-fA-F:]+$'; then
            warn "Could not determine public IP. URI will use <your-server-ip> placeholder."
            ip="<your-server-ip>"
        fi
        HOST="$ip"
        ALLOW_INSECURE=1
    fi
}

# Parse the passwords array out of config.json into the global PASSWORDS_ARR.
# Uses python3 (always present on supported distros via the install path)
# to avoid the well-known pitfalls of grepping JSON.
load_passwords() {
    PASSWORDS_ARR=()
    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        return
    fi
    while IFS= read -r p; do
        [ -n "$p" ] && PASSWORDS_ARR+=("$p")
    done < <(python3 -c "
import json, sys
try:
    with open('$CONFIG_DIR/config.json') as f:
        cfg = json.load(f)
    for p in cfg.get('server', {}).get('passwords', []):
        print(p)
except Exception as e:
    sys.exit(0)
")
}

# Write the PASSWORDS_ARR back into config.json, preserving all other fields.
# Uses python3 for safe JSON manipulation rather than sed surgery.
save_passwords() {
    python3 - "$CONFIG_DIR/config.json" "${PASSWORDS_ARR[@]}" <<'PYEOF'
import json, sys
path = sys.argv[1]
passwords = sys.argv[2:]
with open(path) as f:
    cfg = json.load(f)
cfg.setdefault('server', {})['passwords'] = passwords
with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
PYEOF
    chmod 600 "$CONFIG_DIR/config.json"
}

# Tell phantom-server to re-read config.json without dropping live
# connections. No-op (with a warning) if the service is not running.
reload_service() {
    if pgrep phantom-server >/dev/null 2>&1; then
        kill -HUP "$(pgrep phantom-server)" 2>/dev/null || true
        info "Sent SIGHUP — phantom-server reloaded config."
    else
        warn "phantom-server is not running. Start it with: systemctl start phantom-server"
    fi
}

# Render a single (password -> URI + QR) block. Used by [3] Show users
# after a user is added and during install. Reads HOST / ALLOW_INSECURE
# from globals — caller must invoke resolve_host_mode first.
print_uri_block() {
    local password=$1
    local index=$2
    local total=$3
    local phantom_uri="phantom://${password}@${HOST}:443?type=tcp&security=tls&sni=${HOST}&allowInsecure=${ALLOW_INSECURE}#Phantom"
    local trojan_uri="trojan://${password}@${HOST}:443?security=tls&sni=${HOST}&allowInsecure=${ALLOW_INSECURE}#Phantom"

    echo ""
    echo "------------------------------------------------------------"
    if [ -n "$index" ] && [ -n "$total" ]; then
        echo -e "  ${BLUE}User ${index} / ${total}${NC}"
    fi
    echo "  Password : $password"
    echo ""
    echo -e "  ${GREEN}Native URI:${NC}"
    echo "  $phantom_uri"
    echo ""
    if command -v qrencode &>/dev/null; then
        qrencode -t ANSIUTF8 "$phantom_uri"
    fi
    echo ""
    echo -e "  ${YELLOW}Trojan-compatible URI:${NC}"
    echo "  $trojan_uri"
    echo "------------------------------------------------------------"
}

# ============================================================
# Menu action: Show users
# ============================================================
show_users() {
    require_installed || return
    load_passwords
    resolve_host_mode

    local count=${#PASSWORDS_ARR[@]}
    if [ "$count" -eq 0 ]; then
        warn "No users configured."
        return
    fi

    echo ""
    info "Configured users ($count):"
    local i=1
    for pw in "${PASSWORDS_ARR[@]}"; do
        # Show a short hash prefix so users can identify entries from logs.
        local hash_prefix
        hash_prefix=$(printf "%s" "$pw" | sha256sum | head -c 8)
        printf "  [%d] %s   (hash: %s)\n" "$i" "$pw" "$hash_prefix"
        i=$((i + 1))
    done

    echo ""
    prompt "Enter a user number to view its URI + QR code (or Enter to skip):"
    read -r selection
    if [ -z "$selection" ]; then
        return
    fi
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$count" ]; then
        warn "Invalid selection."
        return
    fi
    print_uri_block "${PASSWORDS_ARR[$((selection - 1))]}" "$selection" "$count"
}

# ============================================================
# Menu action: Add user
# ============================================================
add_user() {
    require_installed || return
    load_passwords
    resolve_host_mode

    local new_pw
    new_pw=$(new_password)
    PASSWORDS_ARR+=("$new_pw")
    save_passwords
    reload_service

    info "New user added. Total users: ${#PASSWORDS_ARR[@]}"
    print_uri_block "$new_pw" "${#PASSWORDS_ARR[@]}" "${#PASSWORDS_ARR[@]}"
}

# ============================================================
# Menu action: Remove user
# ============================================================
remove_user() {
    require_installed || return
    load_passwords

    local count=${#PASSWORDS_ARR[@]}
    if [ "$count" -eq 0 ]; then
        warn "No users to remove."
        return
    fi
    if [ "$count" -eq 1 ]; then
        warn "Refusing to remove the only remaining user — that would lock everyone out."
        warn "Add a new user first if you want to rotate this one out."
        return
    fi

    echo ""
    info "Configured users:"
    local i=1
    for pw in "${PASSWORDS_ARR[@]}"; do
        local hash_prefix
        hash_prefix=$(printf "%s" "$pw" | sha256sum | head -c 8)
        printf "  [%d] %s   (hash: %s)\n" "$i" "$pw" "$hash_prefix"
        i=$((i + 1))
    done

    echo ""
    prompt "Enter the number of the user to remove (or Enter to cancel):"
    read -r selection
    if [ -z "$selection" ]; then
        return
    fi
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$count" ]; then
        warn "Invalid selection."
        return
    fi

    local removed_pw="${PASSWORDS_ARR[$((selection - 1))]}"
    prompt "Really remove user [$selection] ($removed_pw)? [y/N]:"
    read -r confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        info "Cancelled."
        return
    fi

    # Splice out the selected entry. Bash array element removal is awkward;
    # rebuild the array preserving order.
    local new_arr=()
    local j=0
    for pw in "${PASSWORDS_ARR[@]}"; do
        if [ "$j" -ne $((selection - 1)) ]; then
            new_arr+=("$pw")
        fi
        j=$((j + 1))
    done
    PASSWORDS_ARR=("${new_arr[@]}")

    save_passwords
    reload_service
    info "User removed. Remaining users: ${#PASSWORDS_ARR[@]}"
}

# ============================================================
# Uninstall
# ============================================================
uninstall() {
    warn "This will remove Phantom and all its configuration:"
    warn "  - /usr/local/bin/phantom-server"
    warn "  - /etc/systemd/system/phantom-server.service"
    warn "  - /etc/phantom/ (config and self-signed certificates)"
    read -rp "Are you sure? [y/N]: " CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        info "Uninstall cancelled."
        exit 0
    fi

    systemctl stop phantom-server 2>/dev/null || true
    systemctl disable phantom-server 2>/dev/null || true
    rm -f /usr/local/bin/phantom-server
    rm -f /etc/systemd/system/phantom-server.service
    rm -rf /etc/phantom/
    systemctl daemon-reload
    info "Phantom has been uninstalled."
    info "Note: Nginx config was modified during install. To fully revert, run:"
    info "  apt-get install --reinstall nginx-common  # on Debian/Ubuntu"
    info "  yum reinstall nginx                       # on RedHat/CentOS"
}

# ============================================================
# Menu
# ============================================================
show_menu() {
    while true; do
        echo ""
        echo -e "${BLUE}  Phantom ${PHANTOM_VERSION}${NC}"
        echo -e "${BLUE}  https://github.com/phantom-go/phantom${NC}"
        echo ""
        echo "  [1] Install Phantom"
        echo "  [2] Uninstall Phantom"
        echo "  [3] Show users (URI + QR code)"
        echo "  [4] Add user"
        echo "  [5] Remove user"
        echo "  [6] Exit"
        echo ""
        read -rp "Select an option [1-6]: " OPTION
        # Management actions handle their own errors with warn()/return — we
        # don't want a transient failure (e.g. pgrep missing on a minimal
        # system) to drop the user back to the shell. set -e is restored
        # before delegating to the install/uninstall paths, which DO want
        # fast-fail semantics.
        case $OPTION in
            1) main; return ;;
            2) uninstall; return ;;
            3) set +e; show_users;   set -e ;;
            4) set +e; add_user;     set -e ;;
            5) set +e; remove_user;  set -e ;;
            6) exit 0 ;;
            *) warn "Invalid option. Please select 1-6." ;;
        esac
    done
}

# ============================================================
# Main
# ============================================================
main() {
    if [ "$PHANTOM_VERSION" = "unknown" ] || [ -z "$PHANTOM_VERSION" ]; then
        error "Cannot install — version was not resolved. Re-run with a working network connection, or set the PHANTOM_VERSION environment variable."
    fi
    check_root
    detect_os
    detect_ssh_port
    ask_domain
    install_deps
    download_phantom
    configure_nginx
    generate_config
    configure_firewall
    install_service
    print_info
}

fetch_version
show_menu
