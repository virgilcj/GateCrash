# Patched pytune

These are **patched versions** of [pytune](https://github.com/AzureAD/pytune) (Secureworks) files
for Intune MDM enrollment when Conditional Access blocks the standard Graph API enrollment flow.

## What's patched

| File | Change |
|------|--------|
| `pytune.py` | `new_device()` loads PRT from file and reads tenant/device/user IDs from env vars instead of interactive auth |
| `utils/utils.py` | `get_nonce()` reads tenant ID from `TENANT_ID` env var instead of hardcoded GUID |
| `device/device.py` | `enroll_intune()` takes enrollment URL from `INTUNE_ENROLLMENT_URL` env var, skipping Graph API lookup (which CA blocks) |
| `device/windows.py` | Spoofed compliance telemetry reads `SPOOF_DOMAIN` and `DEVICE_ID` from env vars |

## Why patched

On tenants with strict CA policies, the standard pytune flow fails because:
1. Graph API calls to resolve the enrollment URL are CA-blocked
2. Device authentication needs a pre-existing PRT (from roadtx device registration)
3. Compliance telemetry fields need to match the target domain

These patches bypass those blocks by reading values from env vars or config instead of
querying APIs that CA denies.

## Usage

1. Install pytune normally (`pip install pytune` or clone from source)
2. Copy these patched files over the originals in your pytune install
3. Set the required environment variables:

```bash
export TENANT_ID="your-tenant-guid"
export PRT_PATH="/path/to/roadtx.prt"
export TENANT="contoso.onmicrosoft.com"
export DEVICE_ID="your-device-guid"
export USER_ID="your-user-guid"
export INTUNE_ENROLLMENT_URL="https://fef.YOURREGION.manage.microsoft.com:443/StatelessEnrollmentService/DeviceEnrollment.svc"
export SPOOF_DOMAIN="CORP.TARGET.INTERNAL"
```

4. Run pytune with the `--certpfx` flag to use the PRT-based flow

## Finding your enrollment URL

Capture a real Intune enrollment with Burp/Fiddler, or query:
```
GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices
```
The enrollment URL varies by region (e.g., `fef.msua06`, `fef.msub01`).

## Linux only

pytune requires Linux-specific dependencies (roadtools, xmltodict, specific OpenSSL builds).
On Windows, use GateCrash's `intune_ops.py` module which wraps pytune and tells you when
to switch to a Linux/Kali/WSL environment.
