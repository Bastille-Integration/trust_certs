# trust-cert

Fetch TLS certificates from Bastille internal services and install the
top-of-chain cert as a trusted root.

| Script | Platform | Trust store |
|--------|----------|-------------|
| `trust-cert-mac.sh` | macOS | System keychain (`security`) |
| `trust-cert-linux.sh` | Linux (desktop) | System CA store + Firefox/Chrome NSS DBs |
| `trust-cert-windows.ps1` | Windows | Certificate Store (`LocalMachine\Root`) |

## Requirements

### Linux (`trust-cert-linux.sh`)

- `openssl` — available via `apt-get install openssl` / `dnf install openssl`.
- `expect` — only needed for multi-cert mode.
  Install: `apt-get install expect` / `dnf install expect` / `pacman -S expect`.
- `certutil` (optional) — enables trust in Firefox and Chrome/Chromium NSS DBs.
  Install: `apt-get install libnss3-tools` / `dnf install nss-tools`.
- `sudo` privileges for system cert store changes.
- Supported distros: Debian, Ubuntu and derivatives; RHEL, CentOS, Fedora, Rocky, AlmaLinux;
  Arch Linux and derivatives; openSUSE.

### macOS (`trust-cert-mac.sh`)

- `openssl` (ships with macOS).
- `expect` (ships with macOS) — only needed for multi-cert mode.
- SSH access to the network services host (only needed for multi-cert mode).

### Windows (`trust-cert-windows.ps1`)

- PowerShell 5.1 or later (ships with Windows 10/11).
- `plink.exe` (PuTTY) on `PATH` — only needed for multi-cert mode.
  Install via: `winget install PuTTY.PuTTY` or https://www.putty.org
- Administrator privileges (not required for `--dry-run` / `-DryRun`).

The restricted shell on the network services host must allow the
`file view home <file>` command via the SSH exec channel.

## Install

Clone the repo and make the script executable:

```sh
git clone git@github.com:dalybastille/trust_certs.git
cd trust_certs
chmod +x trust-cert-mac.sh trust-cert-linux.sh
```

If you don't have SSH access set up for GitHub, use HTTPS instead:

```sh
git clone https://github.com/dalybastille/trust_certs.git
```

## Usage

**macOS:**
```
./trust-cert-mac.sh [-h] [-n|--dry-run]
```

**Linux:**
```
./trust-cert-linux.sh [-h] [-n|--dry-run]
```

**Windows (run from an elevated PowerShell):**
```
.\trust-cert-windows.ps1 [-DryRun] [-Help]
```

Running either script starts an interactive prompt:

```
Trust mode:
  [1] Single cert
  [2] Multiple (hosts from network-services.yml)
Choice [1/2]:
```

### Mode 1 — single cert

Prompts for a host and port (defaults: `admin.bn.internal`, `443`), fetches
the TLS chain, prints the chain's subject lines, and installs the
**top-of-chain** cert as a trusted root.

### Mode 2 — multiple

1. Prompts for the network services host (default `172.30.2.10`), user,
   and password (entered silently).
2. SSHes in and runs `file view home network-services.yml` via the
   restricted shell's exec channel.
3. Extracts FQDN-looking hostnames from the YAML response, filters out
   hosts known not to serve TLS on their listed port, and dedupes.
4. Shows the detected list and offers `y` / `e=edit` / `n`. Edit opens
   `$EDITOR` (or `nano`/`notepad`) on a temp file so you can tweak before
   proceeding.
5. For each hostname, fetches the chain on the appropriate port, skips
   hosts whose top-of-chain cert is already trusted, and installs the rest.

### Dry run

**macOS:** `./trust-cert-mac.sh --dry-run` (or `-n`)  
**Linux:** `./trust-cert-linux.sh --dry-run` (or `-n`)  
**Windows:** `.\trust-cert-windows.ps1 -DryRun`

Does everything except the actual trust installation — no keychain/store
changes, no elevated privileges required. Use this to preview which certs
would be installed.

## Browser trust on Linux

After installing into the system CA store, `trust-cert-linux.sh` also
installs the cert into:

- **Firefox** — all profiles under `~/.mozilla/firefox/*/` and the Flatpak
  path `~/.var/app/org.mozilla.firefox/...`.
- **Chrome / Chromium** — the user NSS DB at `~/.pki/nssdb`.

This requires `certutil` (`libnss3-tools` on Debian/Ubuntu, `nss-tools` on
RHEL/Fedora). If `certutil` is not found, the system store is still updated
and the browser step is skipped with a warning.

> **Note:** Modern Chrome/Chromium on Linux reads the system CA store
> directly, so the NSS DB step is mainly a belt-and-suspenders fallback.
> Firefox always requires its own trust database to be updated.

## Output

Each fetch produces a per-run subdirectory under `~/.trust-bn-certs/`
(`%USERPROFILE%\.trust-bn-certs\` on Windows):

```
~/.trust-bn-certs/
└── admin.bn.internal_2026_04_24_15_30/
    ├── chain.pem       # full chain as sent by the server (macOS only)
    ├── cert_1.pem      # leaf
    ├── cert_2.pem      # intermediate (if present)
    └── cert_3.pem      # top-of-chain (the one that gets trusted)
```

The top-of-chain cert is the one installed as the trusted root.
Leaf and intermediate certs are kept on disk for reference.

Chain summary includes a `[self-signed]` marker where subject equals issuer,
so you can tell at a glance whether the top cert is a proper root or an
intermediate that the server isn't sending the root for.

## Customization

### Exclude hostnames

All scripts filter out infrastructure hosts that don't serve client-facing
TLS. The pattern lives near the YAML parsing section:

**macOS/Linux:** `grep -vE '^(kafka|concentrator|elastic[0-9]+|...)\.`  
**Windows:** `$excludePrefix = '^(kafka|concentrator|elastic\d+|...)\.'`

Add alternations to either to skip additional hosts.

### Per-host ports

**macOS/Linux:**
```sh
port_for() {
    case "$1" in
        elastic.*) echo 5601 ;;
        *)         echo 443  ;;
    esac
}
```

**Windows:**
```powershell
function Get-PortForHost {
    param([string]$HostName)
    if ($HostName -like "elastic.*") { return 5601 }
    return 443
}
```

Add cases for any host whose TLS endpoint isn't on 443.

## Idempotency

Before installing, the script compares the fingerprint of the top-of-chain
cert against certs already in the trust store. If a match exists, the
install is skipped. Safe to re-run.

## Uninstall

**macOS:**
```sh
sudo security remove-trusted-cert -d ~/.trust-bn-certs/<dir>/cert_N.pem
```
Or use Keychain Access → System keychain to edit/delete trust.

**Linux:**
```sh
# Find the cert file that was installed (named after the cert's CN):
ls /usr/local/share/ca-certificates/          # Debian/Ubuntu
ls /etc/pki/ca-trust/source/anchors/         # RHEL/Fedora

# Remove it and update the store:
sudo rm /usr/local/share/ca-certificates/<name>.crt
sudo update-ca-certificates

# Also remove from Firefox/Chrome NSS DBs if certutil is installed:
certutil -D -n "<cert-name>" -d sql:~/.mozilla/firefox/<profile>/
certutil -D -n "<cert-name>" -d sql:~/.pki/nssdb
```

**Windows (elevated PowerShell):**
```powershell
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$env:USERPROFILE\.trust-bn-certs\<dir>\cert_N.pem")
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | Remove-Item
```
Or use `certmgr.msc` → Trusted Root Certification Authorities to delete manually.
