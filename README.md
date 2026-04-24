# trust-bn

Fetch TLS certificates from Bastille internal services and install the
top-of-chain cert as a trusted root in the macOS System keychain.

## Requirements

- macOS (uses `security` and the System keychain).
- `openssl` (ships with macOS).
- `expect` (ships with macOS) — only needed for multi-cert mode.
- SSH access to the network services host (only needed for multi-cert
  mode). The restricted shell must allow the `file view home <file>`
  command via the SSH exec channel.

## Usage

```
./trust-bn.sh [-h] [-n|--dry-run]
```

Running the script starts an interactive prompt:

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
   `$EDITOR` (or `nano`) on a temp file so you can tweak before proceeding.
5. Caches a single `sudo` ticket up front.
6. For each hostname, fetches the chain on the port returned by
   `port_for` (see below), skips hosts whose top-of-chain cert is already
   trusted in the keychain, and installs the rest in one batch.

### Dry run

`./trust-bn.sh --dry-run` (or `-n`) does everything except the actual
`sudo security add-trusted-cert` calls. No keychain changes, no sudo
prompt. Use this to preview which certs would be installed.

## Output

Each fetch produces a per-run subdirectory:

```
~/.trust-bn-certs/
└── admin.bn.internal_2026_04_24_15_30/
    ├── chain.pem       # full chain as sent by the server
    ├── cert_1.pem      # leaf
    ├── cert_2.pem      # intermediate (if present)
    └── cert_3.pem      # top-of-chain (the one that gets trusted)
```

The top-of-chain cert is what `add-trusted-cert -r trustRoot` installs.
Leaf and intermediate certs are kept on disk for reference but not added
to the keychain — the server presents them on each connection.

Chain summary printed to stderr includes a `[self-signed]` marker where
subject equals issuer, so you can tell at a glance whether the top cert
is a proper root or (for example) an intermediate that the server is not
sending the root for.

## Customization

Both of these live at the top of the multi-host logic in `trust-bn.sh`:

### Exclude hostnames

`grep -vE '^(kafka|concentrator|elastic[0-9]+|fusion-center[0-9]*|kibana|lighthouse|loadbalancer|network-services|redis)\.'`

Add alternations here to skip more hosts. Current list excludes hosts
that don't serve TLS on their listed port.

### Per-host ports

```sh
port_for() {
    case "$1" in
        elastic.*) echo 5601 ;;
        *)         echo 443  ;;
    esac
}
```

Add cases for any host whose TLS endpoint isn't on 443.

## Idempotency

Before installing, the script compares the SHA-1 fingerprint of the
top-of-chain cert against everything already in the System keychain. If
a match exists, the install is skipped. Safe to re-run.

## Uninstall

`add-trusted-cert` adds a trust setting without removing the cert's
previous state. To reverse a trust decision:

```sh
sudo security remove-trusted-cert -d ~/.trust-bn-certs/<dir>/cert_N.pem
```

Or use Keychain Access → System keychain to edit/delete trust.
