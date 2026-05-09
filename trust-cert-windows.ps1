#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive tool to fetch TLS certs and install them as trusted roots
    in the Windows Certificate Store (Local Machine\Root). (Windows only)

.PARAMETER DryRun
    Do everything except install trust (no admin required, no certificate
    store changes). Useful for previewing which certs would be trusted.

.PARAMETER Help
    Show this help message.

.DESCRIPTION
    Modes:
      1) Single cert  - prompts for a host:port and installs that cert.
      2) Multiple     - SSHes into the network services host, reads
                        network-services.yml, extracts hostnames, and
                        fetches/installs certs for each.

    Certs are saved under $env:USERPROFILE\.trust-bn-certs\<host>_<timestamp>\

    Mode 2 requires plink.exe (PuTTY) on your PATH for password-based SSH.
    Install via: winget install PuTTY.PuTTY  (or https://www.putty.org)
#>
param(
    [switch]$DryRun,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$CERT_DIR = Join-Path $env:USERPROFILE ".trust-bn-certs"

# ---- helpers ----

function Show-Usage {
    Get-Help $PSCommandPath -Full
}

function ConvertTo-Pem {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $b64 = [Convert]::ToBase64String($Cert.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`r`n$b64`r`n-----END CERTIFICATE-----"
}

function Get-CertChain {
    param([string]$HostName, [int]$Port = 443)

    $timestamp  = Get-Date -Format "yyyy_MM_dd_HH_mm"
    $fetchDir   = Join-Path $CERT_DIR "${HostName}_${timestamp}"
    New-Item -ItemType Directory -Force -Path $fetchDir | Out-Null

    Write-Host "  Fetching ${HostName}:${Port}..."

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($HostName, $Port)

        $validateAll = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($s, $c, $ch, $e) return $true
        }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $validateAll)
        $ssl.AuthenticateAsClient($HostName)

        $leafCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $ssl.RemoteCertificate
        )
        $ssl.Dispose()
        $tcp.Dispose()
    }
    catch {
        Write-Host "  FAIL: $_" -ForegroundColor Red
        Remove-Item -Recurse -Force $fetchDir -ErrorAction SilentlyContinue
        return $null
    }

    # Build the full chain (no revocation check — internal/self-signed certs)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllFlags
    $chain.Build($leafCert) | Out-Null

    $elements = $chain.ChainElements
    if ($elements.Count -eq 0) {
        Write-Host "  FAIL: no certificate chain built for ${HostName}:${Port}" -ForegroundColor Red
        Remove-Item -Recurse -Force $fetchDir
        return $null
    }

    $lastPath = $null
    for ($i = 0; $i -lt $elements.Count; $i++) {
        $cert    = $elements[$i].Certificate
        $certNum = $i + 1
        $pem     = ConvertTo-Pem $cert
        $path    = Join-Path $fetchDir "cert_${certNum}.pem"
        Set-Content -Path $path -Value $pem -Encoding ASCII
        $lastPath = $path

        $subj   = $cert.Subject
        $issuer = $cert.Issuer
        $marker = if ($subj -eq $issuer) { " [self-signed]" } else { "" }
        Write-Host "    [$certNum] ${subj}${marker}"
    }

    return $lastPath
}

function Test-AlreadyTrusted {
    param([string]$CertPath)

    $cert       = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    $thumbprint = $cert.Thumbprint
    $store      = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }
    $store.Close()
    return ($found.Count -gt 0)
}

function Install-Trust {
    param([string]$CertPath)

    if ($DryRun) {
        Write-Host "  [dry-run] would: Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root"
        return
    }
    Import-Certificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host "  Installed." -ForegroundColor Green
}

function Get-PortForHost {
    param([string]$HostName)
    if ($HostName -like "elastic.*") { return 5601 }
    return 443
}

function Invoke-SshCommand {
    param([string]$SshHost, [string]$User, [string]$Password, [string]$Command)

    if (-not (Get-Command plink -ErrorAction SilentlyContinue)) {
        Write-Host "  'plink' not found. Mode 2 requires PuTTY's plink.exe on your PATH." -ForegroundColor Red
        Write-Host "  Install: winget install PuTTY.PuTTY  (or https://www.putty.org)" -ForegroundColor Yellow
        throw "plink required for password-based SSH"
    }

    # -batch disables interactive prompts; -pw passes the password.
    # First connection: accept the host key automatically with -auto-store-sshkey.
    $result = & plink -ssh -batch -pw $Password -auto-store-sshkey "${User}@${SshHost}" $Command 2>&1
    return $result -join "`n"
}

# ---- main ----

if ($Help) { Show-Usage; exit 0 }

if (-not $DryRun) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        Write-Host "ERROR: installing trusted certificates requires Administrator." -ForegroundColor Red
        Write-Host "Re-run from an elevated PowerShell (right-click -> Run as Administrator)." -ForegroundColor Yellow
        exit 1
    }
}

New-Item -ItemType Directory -Force -Path $CERT_DIR | Out-Null

if ($DryRun) {
    Write-Host "=== DRY RUN: no certificate store changes will be made ===" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Trust mode:"
Write-Host "  [1] Single cert"
Write-Host "  [2] Multiple (hosts from network-services.yml)"
$mode = Read-Host "Choice [1/2]"

if ($mode -eq "1") {
    $hostInput = Read-Host "Host [admin.bn.internal]"
    if (-not $hostInput) { $hostInput = "admin.bn.internal" }
    $portInput = Read-Host "Port [443]"
    if (-not $portInput) { $portInput = "443" }

    $rootCert = Get-CertChain -HostName $hostInput -Port ([int]$portInput)
    if (-not $rootCert) { exit 1 }
    Write-Host "Top-of-chain: $rootCert"

    if (Test-AlreadyTrusted $rootCert) {
        Write-Host "Already trusted; nothing to do."
        exit 0
    }

    if ($DryRun) {
        Write-Host "Would install as trusted root:"
    } else {
        Write-Host "Installing as trusted root (requires admin)..."
    }
    Install-Trust $rootCert

} elseif ($mode -eq "2") {
    $nsHost = Read-Host "Network services host/IP [172.30.2.10]"
    if (-not $nsHost) { $nsHost = "172.30.2.10" }

    $nsUser = Read-Host "User"
    if (-not $nsUser) { Write-Host "User required." -ForegroundColor Red; exit 1 }

    $nsPassSecure = Read-Host "Password" -AsSecureString
    $nsPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($nsPassSecure)
    )
    if (-not $nsPass) { Write-Host "Password required." -ForegroundColor Red; exit 1 }

    Write-Host "Fetching network-services.yml from ${nsHost}..."
    try {
        $yml = Invoke-SshCommand -SshHost $nsHost -User $nsUser -Password $nsPass `
                                 -Command "file view home network-services.yml"
    } catch {
        Write-Host "Failed to retrieve network-services.yml (ssh error)." -ForegroundColor Red
        exit 1
    }

    if (-not $yml) {
        Write-Host "Got empty response from ${nsHost}." -ForegroundColor Red
        exit 1
    }

    # Extract FQDN-looking strings; drop obvious non-hosts (yml files, version strings)
    # and infrastructure hosts that don't serve TLS on the client-facing port.
    $fqdnPattern   = [regex]'[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+'
    $excludeExt    = '\.(yml|yaml|json|conf|sh|txt|md)$'
    $excludePrefix = '^(kafka|concentrator|elastic\d+|fusion-center\d*|kibana|lighthouse|loadbalancer|network-services|redis|storage)\.'

    $hostnames = ($yml -split "`n") | ForEach-Object {
        $fqdnPattern.Matches($_) | ForEach-Object { $_.Value }
    } | Where-Object {
        $_ -notmatch $excludeExt -and $_ -notmatch $excludePrefix
    } | Sort-Object -Unique

    if (-not $hostnames) {
        Write-Host "No hostnames detected. First 40 lines of response for debugging:" -ForegroundColor Red
        ($yml -split "`n") | Select-Object -First 40 | ForEach-Object { Write-Host $_ }
        exit 1
    }

    Write-Host ""
    Write-Host "Detected hostnames:"
    $hostnames | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    $go = Read-Host "Proceed? [Y=yes / e=edit list / n=no]"

    switch -Regex ($go.Trim()) {
        '^[eE]' {
            $tmp = [System.IO.Path]::GetTempFileName() + ".txt"
            Set-Content -Path $tmp -Value ($hostnames -join "`r`n")
            $editor = if ($env:EDITOR) { $env:EDITOR } else { "notepad" }
            Start-Process -FilePath $editor -ArgumentList "`"$tmp`"" -Wait
            $hostnames = Get-Content $tmp | Where-Object { $_.Trim() -ne "" }
            Remove-Item $tmp -ErrorAction SilentlyContinue
        }
        '^[nN]' {
            Write-Host "Aborted."; exit 0
        }
    }

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($h in $hostnames) {
        if (-not $h.Trim()) { continue }
        $p = Get-PortForHost $h
        Write-Host ""
        Write-Host "=== ${h}:${p} ==="
        $root = Get-CertChain -HostName $h -Port $p
        if ($root) {
            if (Test-AlreadyTrusted $root) {
                Write-Host "  Already trusted; skipping."
            } else {
                $roots.Add($root)
            }
        }
    }

    Write-Host ""
    if ($roots.Count -eq 0) {
        Write-Host "No new certs to install."
        exit 0
    }

    if ($DryRun) {
        Write-Host "Would install $($roots.Count) new trusted root(s):"
    } else {
        Write-Host "Installing $($roots.Count) new trusted root(s)..."
    }
    foreach ($r in $roots) {
        Install-Trust $r
    }

} else {
    Write-Host "Invalid choice." -ForegroundColor Red
    exit 1
}
