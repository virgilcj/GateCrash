"""Config loader. Everything tenant-specific lives in config.yaml -- never in code."""
import os

import yaml

DEFAULTS = {
    "password": None,
    "sharepoint_host": None,
    "device_id": "",
    "transport_key_path": "",
    "device_cert_path": "",
    "prt_path": "",
    "session_key_path": "",
    "chromium_path": None,
    "headless": True,
    "mfa_timeout": 300,
    "mfa_number_file": "mfa_number.txt",
    "output_dir": "./output",
    "engagement_name": "assessment_001",
    "verbose": True,
}

REQUIRED = ["tenant_id", "username"]


class Config(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


def load(path):
    if not os.path.exists(path):
        raise SystemExit(f"[!] Config not found: {path}")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    cfg = dict(DEFAULTS)
    cfg.update(data)

    # Env override for the password (gotcha #9: special chars; never pass via shell args).
    if os.environ.get("AZCA_PASSWORD"):
        cfg["password"] = os.environ["AZCA_PASSWORD"]

    missing = [k for k in REQUIRED if not cfg.get(k)]
    if missing:
        raise SystemExit(f"[!] Config missing required keys: {', '.join(missing)}")

    # Derive sharepoint_host from username domain if not set.
    if not cfg.get("sharepoint_host") and "@" in cfg["username"]:
        tenant_name = cfg["username"].split("@")[1].split(".")[0]
        cfg["sharepoint_host"] = f"{tenant_name}.sharepoint.com"

    return Config(cfg)
