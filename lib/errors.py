"""Azure AD error-code intelligence. Maps AADSTS codes to meaning + next action."""
import re

# code -> (short meaning, action/decision hint)
ERRORS = {
    "50076": ("MFA required (no device compliance)", "EXPLOITABLE: platform bypass exists, proceed to MFA"),
    "53003": ("Blocked by CA (device compliance)", "Try different platform UA, DRS, or PRT broker"),
    "530003": ("Blocked by CA (variant of 53003)", "Try different platform UA, DRS, or PRT broker"),
    "530084": ("Blocked by CA (compliant/block variant)", "Try different platform UA, DRS, or PRT broker"),
    "50126": ("Invalid credentials", "Wrong password. Stop."),
    "50034": ("User not found", "Wrong username. Stop."),
    "501314": ("Browser capability required", "Need a real browser (Selenium), not raw HTTP"),
    "50011": ("Redirect URI mismatch", "Client+redirect not registered. Try a different redirect."),
    "700016": ("App not found in tenant", "client_id not valid for this tenant"),
    "65001": ("User/admin consent required", "App needs consent. Usually blocked without admin."),
    "7000218": ("client_assertion missing", "Confidential client needs a client cert"),
    "7000220": ("client_id in POST body for jwt-bearer", "Move client_id INTO the signed JWT payload"),
    "90014": ("Required field 'request' missing", "Use data= (form POST), not json=, for ProcessAuth"),
    "70003": ("Unsupported grant type", "Grant type not supported for this client"),
    "500132": ("SAML assertion condition not met", "SAML bearer exchange failed"),
    "399218": ("CmsiInterrupt (appverify speedbump)", "POST to /appverify to continue"),
}

# Codes that mean "keep going, a bypass may exist here".
EXPLOITABLE = {"50076"}
# Codes that mean "stop, nothing to do".
TERMINAL = {"50126", "50034"}


def parse_code(text):
    """Pull the first AADSTS code (or bare numeric code) out of an error string/body."""
    if not text:
        return None
    m = re.search(r"AADSTS(\d+)", text)
    if m:
        return m.group(1)
    m = re.search(r'"?error_codes"?\s*:\s*\[?\s*(\d+)', text)
    if m:
        return m.group(1)
    m = re.search(r"\b(\d{5,7})\b", text)
    return m.group(1) if m else None


def explain(code):
    code = str(code)
    meaning, action = ERRORS.get(code, ("Unknown error", "No known action"))
    return {"code": code, "meaning": meaning, "action": action,
            "exploitable": code in EXPLOITABLE, "terminal": code in TERMINAL}


def _demo():
    assert parse_code("error AADSTS53003: blocked") == "53003"
    assert parse_code('{"error_codes":[50076]}') == "50076"
    assert explain("50076")["exploitable"]
    assert explain("50126")["terminal"]
    print("errors ok")


if __name__ == "__main__":
    _demo()
