#!/bin/bash
set -euo pipefail

CERT_DIR="$HOME/.trust-bn-certs"
DRY_RUN=0
CERT_ANCHOR_DIR=""
UPDATE_CMD=""
CERT_EXT="crt"

usage() {
    cat <<EOF
Usage: $(basename "$0") [-h] [-n|--dry-run]

Interactive tool to fetch TLS certs and install them as trusted roots
on Linux. Also installs into Firefox profiles and the Chrome/Chromium
NSS DB when certutil is available.

Options:
  -n, --dry-run   Do everything except install trust (no sudo, no
                  cert store changes). Useful for previewing which certs
                  would be trusted.

Modes:
  1) Single cert  - prompts for a host:port and installs that cert.
  2) Multiple     - SSHes into the network services host, reads
                    network-services.yml, extracts hostnames, and
                    fetches/installs certs for each.

Certs are saved under ~/.trust-bn-certs/<host>_<timestamp>/

Supported distros: Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky/AlmaLinux,
                   Arch Linux, openSUSE
EOF
}

# --- distro detection ---

detect_distro() {
    if [[ ! -f /etc/os-release ]]; then
        echo "Warning: /etc/os-release not found; defaulting to Debian-style cert store." >&2
        CERT_ANCHOR_DIR="/usr/local/share/ca-certificates"
        UPDATE_CMD="update-ca-certificates"
        return
    fi

    local distro_id distro_like
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_id="${ID:-unknown}"
    distro_like="${ID_LIKE:-}"

    case "$distro_id" in
        debian|ubuntu|linuxmint|pop|kali|elementary|raspbian)
            CERT_ANCHOR_DIR="/usr/local/share/ca-certificates"
            UPDATE_CMD="update-ca-certificates"
            ;;
        rhel|centos|fedora|rocky|almalinux|ol|amzn)
            CERT_ANCHOR_DIR="/etc/pki/ca-trust/source/anchors"
            UPDATE_CMD="update-ca-trust"
            ;;
        arch|manjaro|endeavouros|garuda)
            CERT_ANCHOR_DIR="/etc/ca-certificates/trust-source/anchors"
            UPDATE_CMD="trust extract-compat"
            ;;
        opensuse*|sles)
            CERT_ANCHOR_DIR="/etc/pki/trust/anchors"
            UPDATE_CMD="update-ca-certificates"
            ;;
        *)
            if [[ "$distro_like" == *"debian"* || "$distro_like" == *"ubuntu"* ]]; then
                CERT_ANCHOR_DIR="/usr/local/share/ca-certificates"
                UPDATE_CMD="update-ca-certificates"
            elif [[ "$distro_like" == *"rhel"* || "$distro_like" == *"fedora"* ]]; then
                CERT_ANCHOR_DIR="/etc/pki/ca-trust/source/anchors"
                UPDATE_CMD="update-ca-trust"
            elif [[ "$distro_like" == *"arch"* ]]; then
                CERT_ANCHOR_DIR="/etc/ca-certificates/trust-source/anchors"
                UPDATE_CMD="trust extract-compat"
            else
                echo "Warning: Unknown distro '${distro_id}'; defaulting to Debian-style cert store." >&2
                CERT_ANCHOR_DIR="/usr/local/share/ca-certificates"
                UPDATE_CMD="update-ca-certificates"
            fi
            ;;
    esac

    echo "Distro: ${distro_id}  |  cert store: ${CERT_ANCHOR_DIR}"
}

# --- helpers ---

fetch_chain() {
    # Args: host [port]. Prints chain summary to stderr; prints top-of-chain
    # cert path on stdout. Returns 1 on failure.
    local host=$1 port=${2:-443}
    local fetch_dir="$CERT_DIR/${host}_$(date +"%Y_%m_%d_%H_%M")"
    local chain_file="$fetch_dir/chain.pem"
    mkdir -p "$fetch_dir"

    echo "  Fetching ${host}:${port}..." >&2
    openssl s_client -connect "${host}:${port}" -servername "${host}" -showcerts 2>/dev/null </dev/null \
        | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "$chain_file"

    if ! grep -q "BEGIN CERTIFICATE" "$chain_file"; then
        echo "  FAIL: no certificate retrieved from ${host}:${port}" >&2
        rm -rf "$fetch_dir"
        return 1
    fi

    awk -v dir="$fetch_dir" '
        /-BEGIN CERTIFICATE-/ { n++; f = sprintf("%s/cert_%d.pem", dir, n) }
        n > 0 { print > f }
    ' "$chain_file"

    local count
    count=$(grep -c "BEGIN CERTIFICATE" "$chain_file")
    local i cert subj issuer marker
    for i in $(seq 1 "$count"); do
        cert="$fetch_dir/cert_${i}.pem"
        subj=$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject=//')
        issuer=$(openssl x509 -in "$cert" -noout -issuer | sed 's/^issuer=//')
        marker=""
        [[ "$subj" == "$issuer" ]] && marker=" [self-signed]"
        echo "    [${i}] ${subj}${marker}" >&2
    done

    echo "$fetch_dir/cert_${count}.pem"
}

cert_fp() {
    openssl x509 -in "$1" -noout -fingerprint -sha1 2>/dev/null \
        | sed 's/.*=//;s/://g' | tr '[:upper:]' '[:lower:]'
}

cert_cn() {
    openssl x509 -in "$1" -noout -subject -nameopt multiline 2>/dev/null \
        | awk -F' = ' '/^\s*commonName/ { print $2 }'
}

already_trusted() {
    local fp
    fp=$(cert_fp "$1")
    [[ -d "$CERT_ANCHOR_DIR" ]] || return 1

    local cert_file existing_fp
    for cert_file in "$CERT_ANCHOR_DIR"/*; do
        [[ -f "$cert_file" ]] || continue
        existing_fp=$(cert_fp "$cert_file") || continue
        [[ "$existing_fp" == "$fp" ]] && return 0
    done
    return 1
}

# safe filename from CN: keep alphanum/dots/hyphens, collapse the rest to _
cn_to_filename() {
    local raw
    raw=$(cert_cn "$1")
    local safe
    safe=$(printf '%s' "${raw:-imported_cert}" | tr -cs 'a-zA-Z0-9._-' '_' \
           | sed 's/^[_.]*//;s/[_.]*$//')
    printf '%s' "${safe:-imported_cert}"
}

remove_old_cn() {
    local cert_path=$1 new_fp cn
    new_fp=$(cert_fp "$cert_path")
    cn=$(cert_cn "$cert_path")
    [[ -z "$cn" || ! -d "$CERT_ANCHOR_DIR" ]] && return 0

    local cert_file cert_cn_val fp
    for cert_file in "$CERT_ANCHOR_DIR"/*; do
        [[ -f "$cert_file" ]] || continue
        cert_cn_val=$(cert_cn "$cert_file") || continue
        [[ "$cert_cn_val" != "$cn" ]] && continue
        fp=$(cert_fp "$cert_file") || continue
        [[ -z "$fp" || "$fp" == "$new_fp" ]] && continue
        if [[ "$DRY_RUN" == "1" ]]; then
            echo "  [dry-run] would remove old trusted cert with CN='${cn}' (SHA1: $fp)"
        else
            echo "  Removing old trusted cert with CN='${cn}' (SHA1: $fp)..."
            sudo rm -f "$cert_file"
        fi
    done
}

install_trust() {
    local cert_path=$1
    local name dest
    name=$(cn_to_filename "$cert_path")
    dest="$CERT_ANCHOR_DIR/${name}.$CERT_EXT"

    if [[ "$DRY_RUN" == "1" ]]; then
        echo "  [dry-run] would: sudo cp $cert_path $dest && sudo $UPDATE_CMD"
        return 0
    fi

    [[ -d "$CERT_ANCHOR_DIR" ]] || sudo mkdir -p "$CERT_ANCHOR_DIR"
    sudo cp "$cert_path" "$dest"
    sudo chmod 644 "$dest"
    echo "  Installed to $dest"
    echo "  Running sudo $UPDATE_CMD ..."
    sudo $UPDATE_CMD
}

# --- browser trust (Firefox + Chrome/Chromium NSS DB) ---

nss_dbs() {
    # Print all NSS DB directories for Firefox profiles and Chrome/Chromium.
    local db
    # Firefox
    for db in "$HOME"/.mozilla/firefox/*/ "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/; do
        [[ -d "$db" ]] && printf '%s\n' "$db"
    done
    # Chrome / Chromium user NSS DB
    for db in "$HOME/.pki/nssdb" "$HOME/.local/share/pki/nssdb"; do
        [[ -d "$db" ]] && printf '%s\n' "$db"
    done
}

install_browser_trust() {
    local cert_path=$1
    command -v certutil >/dev/null 2>&1 || {
        echo "  (certutil not found; skipping browser trust)" >&2
        echo "  Install: apt-get install libnss3-tools  OR  dnf install nss-tools" >&2
        return 0
    }

    local name
    name=$(cn_to_filename "$cert_path")

    local db found=0
    while IFS= read -r db; do
        [[ -d "$db" ]] || continue
        found=1
        local db_arg="sql:$db"
        [[ ! -f "$db/cert9.db" ]] && db_arg="$db"  # legacy dbm format

        if [[ "$DRY_RUN" == "1" ]]; then
            echo "  [dry-run] would: certutil -A -n '$name' -t 'CT,,' -i $cert_path -d '$db_arg'"
        else
            # Remove existing entry with same name to avoid duplicates
            certutil -D -n "$name" -d "$db_arg" 2>/dev/null || true
            certutil -A -n "$name" -t "CT,," -i "$cert_path" -d "$db_arg" 2>/dev/null \
                && echo "  Browser trust: $db" \
                || echo "  Browser trust FAILED: $db" >&2
        fi
    done < <(nss_dbs)

    [[ "$found" -eq 0 ]] && echo "  (no Firefox/Chrome NSS databases found)"
}

remove_old_cn_browser() {
    local cert_path=$1
    command -v certutil >/dev/null 2>&1 || return 0

    local cn
    cn=$(cert_cn "$cert_path")
    [[ -z "$cn" ]] && return 0

    local db
    while IFS= read -r db; do
        [[ -d "$db" ]] || continue
        local db_arg="sql:$db"
        [[ ! -f "$db/cert9.db" ]] && db_arg="$db"

        # List all certs with matching CN (certutil -L shows names; grep for CN)
        local entry
        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue
            if [[ "$DRY_RUN" == "1" ]]; then
                echo "  [dry-run] would remove browser cert '$entry' from $db"
            else
                certutil -D -n "$entry" -d "$db_arg" 2>/dev/null || true
            fi
        done < <(certutil -L -d "$db_arg" 2>/dev/null \
                     | awk -v cn="$cn" 'index($0, cn) > 0 { sub(/[ \t]+[A-Za-z,]+[ \t]*$/, ""); sub(/^[ \t]+/, ""); print }')
    done < <(nss_dbs)
}

# --- SSH / multi-host helpers ---

port_for() {
    case "$1" in
        elastic.*) echo 5601 ;;
        *)         echo 443  ;;
    esac
}

require_expect() {
    if ! command -v expect >/dev/null 2>&1; then
        echo "This mode requires 'expect', which isn't on your PATH." >&2
        echo "Install with one of:" >&2
        echo "  apt-get install -y expect   # Debian/Ubuntu" >&2
        echo "  dnf install -y expect       # RHEL/Fedora" >&2
        echo "  pacman -S expect            # Arch" >&2
        exit 1
    fi
}

ssh_run() {
    # Args: host user password remote_cmd. Runs remote_cmd over SSH using
    # password auth via expect; prints remote stdout to our stdout.
    local host=$1 user=$2 password=$3 cmd=$4
    expect <<EOF
log_user 0
set timeout 30
spawn ssh -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no ${user}@${host} "${cmd}"
expect {
    -re {[Pp]assword:} { send "${password}\r" }
    timeout { exit 2 }
    eof      { exit 3 }
}
log_user 1
expect eof
EOF
}

trust_cert() {
    local cert=$1
    remove_old_cn "$cert"
    install_trust "$cert"
    remove_old_cn_browser "$cert"
    install_browser_trust "$cert"
}

# --- main ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -n|--dry-run) DRY_RUN=1; shift ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

detect_distro
mkdir -p "$CERT_DIR"

if [[ "$DRY_RUN" == "1" ]]; then
    echo "=== DRY RUN: no cert store changes will be made ==="
    echo
fi

echo "Trust mode:"
echo "  [1] Single cert"
echo "  [2] Multiple (hosts from network-services.yml)"
read -r -p "Choice [1/2]: " mode

if [[ "$mode" == "1" ]]; then
    read -r -p "Host [admin.bn.internal]: " host
    host=${host:-admin.bn.internal}
    read -r -p "Port [443]: " port
    port=${port:-443}

    root_cert=$(fetch_chain "$host" "$port") || exit 1
    echo "Top-of-chain: $root_cert"

    if already_trusted "$root_cert"; then
        echo "Already trusted; nothing to do."
        exit 0
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        echo "Would install as trusted root:"
    else
        echo "Installing as trusted root (requires sudo)..."
    fi
    trust_cert "$root_cert"

elif [[ "$mode" == "2" ]]; then
    require_expect

    read -r -p "Network services host/IP [172.30.2.10]: " ns_host
    ns_host=${ns_host:-172.30.2.10}
    read -r -p "User: " ns_user
    [[ -z "$ns_user" ]] && { echo "User required." >&2; exit 1; }
    read -r -s -p "Password: " ns_pass
    echo
    [[ -z "$ns_pass" ]] && { echo "Password required." >&2; exit 1; }

    echo "Fetching network-services.yml from ${ns_host}..."
    yml=$(ssh_run "$ns_host" "$ns_user" "$ns_pass" "file view home network-services.yml") || {
        echo "Failed to retrieve network-services.yml (ssh/expect error)." >&2
        exit 1
    }

    if [[ -z "$yml" ]]; then
        echo "Got empty response from ${ns_host}." >&2
        exit 1
    fi

    # Extract FQDN-looking strings; drop obvious non-hosts (yml files, version strings)
    # and hosts that don't serve TLS on 443 / aren't what clients talk to.
    hostnames=$(printf '%s\n' "$yml" \
        | grep -oE '[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+' \
        | grep -vE '\.(yml|yaml|json|conf|sh|txt|md)$' \
        | grep -vE '^(kafka|concentrator|elastic[0-9]+|fusion-center[0-9]*|kibana|lighthouse|loadbalancer|network-services|redis|storage)\.' \
        | sort -u)

    if [[ -z "$hostnames" ]]; then
        echo "No hostnames detected. First 40 lines of response for debugging:" >&2
        printf '%s\n' "$yml" | head -40 >&2
        exit 1
    fi

    echo
    echo "Detected hostnames:"
    printf '%s\n' "$hostnames" | sed 's/^/  /'
    echo
    read -r -p "Proceed? [Y=yes / e=edit list / n=no]: " go
    case "$go" in
        e|E|edit)
            tmp=$(mktemp)
            printf '%s\n' "$hostnames" > "$tmp"
            "${EDITOR:-nano}" "$tmp"
            hostnames=$(cat "$tmp")
            rm -f "$tmp"
            ;;
        n|N|no)
            echo "Aborted."; exit 0 ;;
    esac

    if [[ "$DRY_RUN" != "1" ]]; then
        echo "Caching sudo credential so the batch install doesn't reprompt..."
        sudo -v
    fi

    roots=()
    while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        p=$(port_for "$h")
        echo
        echo "=== $h:$p ==="
        if root=$(fetch_chain "$h" "$p"); then
            if already_trusted "$root"; then
                echo "  Already trusted; skipping."
            else
                roots+=("$root")
            fi
        fi
    done <<< "$hostnames"

    echo
    if [[ ${#roots[@]} -eq 0 ]]; then
        echo "No new certs to install."
        exit 0
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        echo "Would install ${#roots[@]} new trusted root(s):"
    else
        echo "Installing ${#roots[@]} new trusted root(s)..."
    fi
    for r in "${roots[@]}"; do
        trust_cert "$r"
    done

else
    echo "Invalid choice." >&2
    exit 1
fi
