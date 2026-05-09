#!/bin/bash
set -euo pipefail

CERT_DIR="$HOME/.trust-bn-certs"
DRY_RUN=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [-h] [-n|--dry-run]

Interactive tool to fetch TLS certs and install them as trusted roots
in the macOS System keychain.

Options:
  -n, --dry-run   Do everything except install trust (no sudo, no
                  keychain changes). Useful for previewing which certs
                  would be trusted.

Modes:
  1) Single cert  - prompts for a host:port and installs that cert.
  2) Multiple     - SSHes into the network services host, reads
                    network-services.yml, extracts hostnames, and
                    fetches/installs certs for each.

Certs are saved under ~/.trust-bn-certs/<host>_<timestamp>/
EOF
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

already_trusted() {
    local fp
    fp=$(openssl x509 -in "$1" -noout -fingerprint -sha1 | sed 's/.*=//;s/://g')
    security find-certificate -a -Z /Library/Keychains/System.keychain 2>/dev/null \
        | grep -qi "SHA-1 hash: ${fp}"
}

install_trust() {
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "  [dry-run] would: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $1"
        return 0
    fi
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$1"
}

port_for() {
    case "$1" in
        elastic.*) echo 5601 ;;
        *)         echo 443  ;;
    esac
}

require_expect() {
    if ! command -v expect >/dev/null 2>&1; then
        echo "This mode requires 'expect', which isn't on your PATH." >&2
        echo "Install with: brew install expect" >&2
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

# --- main ---

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -n|--dry-run) DRY_RUN=1; shift ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

mkdir -p "$CERT_DIR"

if [[ "$DRY_RUN" == "1" ]]; then
    echo "=== DRY RUN: no keychain changes will be made ==="
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
    install_trust "$root_cert"

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
        install_trust "$r"
    done

else
    echo "Invalid choice." >&2
    exit 1
fi
