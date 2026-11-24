"""Offline smoke test: imports, crypto round-trips, storage, token normalize, reporting.
No network. Run: python test_smoke.py
"""
import os
import tempfile

from lib import clients, errors, kdf, jwe, ua
from lib.util import Engagement, decode_jwt


def test_lib_selfchecks():
    kdf._demo()
    jwe._demo()
    errors._demo()


def test_clients_resources():
    assert clients.client_id("office") == "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    assert clients.client_id("raw-guid") == "raw-guid"
    assert clients.v1_resource("sharepoint", "c.sharepoint.com") == "https://c.sharepoint.com"
    assert clients.v2_scope("graph") == "https://graph.microsoft.com/.default"
    assert "macos" in ua.BYPASS_PLATFORMS


def test_engagement_storage():
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "eng1")
        assert os.path.isdir(eng.tokens)
        p = eng.save_token("graph", {"access_token": "x"})
        assert eng.load_token("graph")["access_token"] == "x"
        # load by full path
        assert eng.load_token(p)["access_token"] == "x"
        assert eng.load_token("missing") is None


def _make_jwt(claims):
    import jwt as pyjwt
    return pyjwt.encode(claims, "k", algorithm="HS256")


def test_token_normalize():
    from modules import token_ops
    at = _make_jwt({"aud": "https://graph.microsoft.com", "upn": "a@b.com", "tid": "T", "exp": 9999999999})
    tok = token_ops.normalize({"access_token": at, "refresh_token": "0.A"}, source="manual")
    assert tok["upn"] == "a@b.com" and tok["tenant_id"] == "T"
    assert tok["_claims"]["aud"] == "https://graph.microsoft.com"
    assert token_ops.is_expired({"_claims": {"exp": 1}})


def test_reporting_matrix():
    from modules import reporting
    with tempfile.TemporaryDirectory() as d:
        eng = Engagement(d, "eng2")
        eng.save_json("evidence", "recon", {
            "summary": {"bypass_platforms": ["macos"], "direct_token": False, "all_blocked": False},
            "matrix": {"macos": {"office": {"graph": "50076", "drs": "50076"}},
                       "windows": {"office": {"graph": "53003", "drs": "50076"}}}})
        at = _make_jwt({"aud": "https://graph.microsoft.com", "amr": ["pwd"]})
        eng.save_token("graph", {"access_token": at, "source": "test"})

        class Cfg:
            engagement_name, tenant_id, username = "eng2", "T", "u@d.com"
        report = reporting.run(Cfg(), eng, None)
        vuln01 = next(f for f in report["findings"] if f.get("id") == "VULN-01")
        assert vuln01["status"] == "OBSERVED" and vuln01["severity"] == "Critical"
        md = open(os.path.join(eng.reports, "report.md"), encoding="utf-8").read()
        assert "VULN-01" in md and "50076" in md and "macos" in md


def test_devicekeys_blob():
    from lib import devicekeys
    devicekeys._demo()


def test_syncml_intel():
    from modules.post_ex import syncml_intel
    sample = ("DeviceName: DESKTOP-ATK01\n"
              "Subject DC=INTERNAL,DC=CONTOSO,DC=CORP CN=CORP-ISSUING-CA01\n"
              "AIA: http://pki.corp.contoso.internal/pki/CORP-ISSUING-CA01.crt server CORPSP024\n"
              "orgId: 1e2db5da-1e30-4c01-b5ff-fc9ba98bc6e3  edr-aen0a.aea.endpoint.security.microsoft.com\n"
              "PassportForWork disabled  Biometrics enabled  WNS notify.windows.com\n")
    intel = syncml_intel(sample)
    dom = intel["internal_domain"].lower()
    assert "contoso" in dom and "internal" in dom
    assert intel["pki_url"].startswith("http://pki.corp.contoso.internal")
    assert intel["mde_org_id"] == "1e2db5da-1e30-4c01-b5ff-fc9ba98bc6e3"
    assert intel["mde_edr_endpoint"].startswith("edr-aen0a")
    assert intel["passport_for_work"] == "disabled" and intel["biometrics"] == "enabled"


def test_all_modules_import():
    from modules import (recon, mfa_handler, platform_bypass, token_ops,
                         post_ex, prt_broker, device_reg, drs_ops, intune_ops, reporting)
    import cli
    assert cli and recon and mfa_handler and platform_bypass and post_ex and prt_broker
    assert device_reg and drs_ops and intune_ops and reporting and token_ops


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} smoke tests passed")
