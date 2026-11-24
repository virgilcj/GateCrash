# Dead Ends — Blocked Techniques (do NOT chase)

Every technique below was tested across 338+ real tests (38+ categories) against well-configured tenants and
**blocked**. These are not tool bugs — each produced the expected Azure AD response. The
framework documents them so operators don't waste time re-running them. Many are *conditional*:
they fail against a well-configured tenant but work elsewhere (noted as "works when").

| # | Category | Result | Why | Works when |
|---|----------|--------|-----|-----------|
| C1 | Direct ROPC (10 clients × 15 resources, Win/Linux UA) | `53003` | CA enforces device compliance; password valid (not 50126) | Never, for data resources under compliance CA |
| C2 | Legacy auth (SMTP 587 / IMAP 993 / EWS) | disabled / `53003` | Legacy auth off tenant-wide | Tenants with legacy auth still enabled |
| C3 | FOCI family sweep (12 clients) | `53003` | CA uniform across the family | Tenants with uneven CA across FOCI apps |
| C4 | Company Portal (ROPC/devicecode/authcode) | `53003` (DRS resource: `50076`) | CP not CA-exempt for data here | Tenants where CP is CA-exempt |
| C5 | Token exchange: RFC8693 / OBO / SAML-bearer / cross-resource RT | `70003` / `7000219` / `500132` / `53003` | CA evaluated on TARGET resource, not source token | OBO: with a confidential client |
| C6 | PRT jwt-bearer/cookie + macOS/iOS UA | `53003` | PRT platform comes from the device-registration claim (server-side), UA ignored | Never (UA spoof only works for ROPC/authcode) |
| C7 | Device-cert auth (client_credentials / assertion / mTLS) | `700016` | A device cert is not an app credential; no device grant type | Never |
| C8 | Headless Python auth-code | `501314` | Login needs JS/browser capabilities | Use Selenium (this is why T2 exists) |
| C9 | DRS compliance PATCH propagation | 200 accepted, AAD unchanged | DRS store is isolated from the AAD device object; compliance flows through Intune eval | Never (by design) |
| C10 | Intune MDM telemetry spoof (AV/FW/TPM/BitLocker/ATP) | 200 accepted, still non-compliant | Server-side Health Attestation needs a real TPM-signed blob | Real TPM or a TPM hardware attack |
| C11 | Windows Hello for Business / NGC key | blocked | Needs an existing compliant session or Graph write (CA-blocked) | Post-compliance scenarios |
| C12 | Desktop/seamless SSO, WAM headers, browserprtauth | `53003` | SSO evaluated identically to interactive auth | Never under the same CA |
| C13 | NAA (nested app authentication) broker | `53003` | NAA inherits the target/parent CA | Tenants with NAA-exempt parent apps |
| C14 | WNS channel data exfil | no data path | WNS carries MDM commands only | Never (not a data channel) |
| C15 | Zero-day research (undocumented paths, DRS quirks, 24h propagation timing, SyncML) | no breakthrough | — | — |
| C16 | WIA, device code, FEF endpoints, WS-Trust-for-data, mTLS-to-token, resource-specific CA gaps | `53003` / `403` | All re-evaluated by CA | Device code: tenants without compliance CA |
| C17 | Viva/Sway `50076` | red herring | Viva returns 50076 but the token has no Graph/Exchange/SharePoint scope | Never a real bypass |

## What this means for the framework

- `recon --sweep` empirically re-confirms C1/C4/C17 per tenant (resource surface), so you see the
  current posture rather than assuming. The quick/sweep modes keep the FOCI axis small (C3).
- `recon` runs the C2 legacy probe (SMTP/IMAP) once — cheap, and a real bypass where enabled.
- `drs_ops` performs the C9 PATCH and prints the non-propagation caveat.
- `intune_ops` sends the C10 telemetry spoof payload and prints that it does not flip compliance.
- C5/C6/C7/C11/C12/C13/C14/C15/C16 are **not built** (GOAL "What NOT to build"): they cost code
  for no payoff against a compliance CA. They live here as documentation.

## The one gap that worked

macOS/iOS/Android are exempt from device compliance (UA-controlled) → `50076` (MFA only) for
**all** resources. That is VULN-01 and the basis of the Selenium exploit (T2). Everything above
failed *because* the tenant was otherwise well configured.
