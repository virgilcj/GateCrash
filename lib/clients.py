"""client_id + resource database. All public first-party Microsoft app IDs."""

# --- Clients -------------------------------------------------------------
CLIENTS = {
    "office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "azure_cli": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "azure_ps": "1950a258-227b-4e31-a9cf-717495945fc2",
    "aad_ps": "1b730954-1685-4b74-9bfd-dac224a7b894",
    "graph_explorer": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
    "visual_studio": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "outlook": "27922004-5251-4030-b22d-91ecd9a37ea4",
    "onedrive": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    "windows_search": "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
    "edge": "ecd6b820-32c2-49b6-98a6-444530e5a77a",
    "bing": "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8",
    "cortana": "22d7579f-06c2-4baa-89d2-e844571e5ffa",
    "yammer": "00000005-0000-0ff1-ce00-000000000000",
    "substrate_client": "4e291c71-d680-4d0e-9640-0a3c0e2a1e5e",
    "office_com": "4765445b-32c6-49b0-83e6-1d93765276ca",
    "outlook_mobile": "27922004-5251-4030-b22d-91ecd9a37084",
    # FOCI family (share refresh tokens; CA might miss some)
    "authenticator": "4813382a-8fa7-425e-ab75-3b753aab3abb",
    "todo": "22098786-6e16-43cc-a27d-838a33190e27",
    "whiteboard": "57336123-6e14-4acc-8dcf-287b6088aa28",
    "planner": "66375f6b-983f-4c2c-9701-d680650f588f",
    "stream": "cf53fce8-def6-4aeb-8d30-b158e7b1cf83",
    "power_automate": "7df0a125-d3be-4c96-aa54-591f83ff541c",
    "sharepoint_app": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "office_lens": "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0",
    "onenote_app": "2d4d3d8e-2be3-4bef-9f87-7875a61c29de",
    # Special purpose
    "broker_wam": "dd762716-544d-4aeb-a526-687b73838a22",
    "broker_device": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "company_portal": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "intune_enroll": "d4bce7d4-7bfa-4b88-9f10-8b6f9b0c8b30",
}

# A quick, non-elaborate ROPC probe set (GOAL: don't build elaborate FOCI chains).
ROPC_PROBE = ["office", "teams", "azure_cli"]

BROKER_CLIENT = CLIENTS["broker_wam"]
BROKER_REDIRECT = f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{BROKER_CLIENT}"
NATIVE_REDIRECT = "https://login.microsoftonline.com/common/oauth2/nativeclient"

REDIRECTS = {
    "broker_wam": BROKER_REDIRECT,
    "broker_device": f"ms-appx-web://Microsoft.AAD.BrokerPlugin/{CLIENTS['broker_device']}",
    "company_portal": "companyportal://com.microsoft.CompanyPortal",
}


def client_id(name):
    """Resolve a friendly name to a client_id; pass a raw GUID through unchanged."""
    return CLIENTS.get(name, name)


def redirect_for(name):
    return REDIRECTS.get(name, NATIVE_REDIRECT)


# --- Resources -----------------------------------------------------------
# v1.0 resources (used with resource= param). {tenant} filled at runtime for SharePoint.
V1_RESOURCES = {
    "drs": "urn:ms-drs:enterpriseregistration.windows.net",
    "graph": "https://graph.microsoft.com",
    "aad_graph": "https://graph.windows.net",
    "exchange": "https://outlook.office365.com",
    "azure_mgmt": "https://management.azure.com",
    "intune": "https://api.manage.microsoft.com",
    "substrate": "https://substrate.office.com",
    "onenote": "https://onenote.com",
    "keyvault": "https://vault.azure.net",
    "sharepoint": "https://{sp_host}",
}

# v2.0 scopes (used with scope= param).
V2_SCOPES = {
    "graph": "https://graph.microsoft.com/.default",
    "exchange": "https://outlook.office365.com/.default",
    "sharepoint": "https://{sp_host}/.default",
    "azure_mgmt": "https://management.azure.com/.default",
    "intune": "https://api.manage.microsoft.com/.default",
    "substrate": "https://substrate.office.com/.default",
    "onenote": "https://onenote.com/.default",
    "keyvault": "https://vault.azure.net/.default",
    "aad_graph": "https://graph.windows.net/.default",
    "wvd": "https://www.wvd.microsoft.com/.default",
}

# Pivot targets after a platform-bypass refresh token (Module 4).
PIVOT_SCOPES = ["graph", "exchange", "sharepoint", "intune", "azure_mgmt", "aad_graph", "substrate", "onenote"]

# Extended CA-exemption sweep list (resource_uri, label).
SWEEP_RESOURCES = [
    ("urn:ms-drs:enterpriseregistration.windows.net", "DRS"),
    ("https://graph.microsoft.com", "MS Graph"),
    ("https://graph.windows.net", "AAD Graph"),
    ("https://outlook.office365.com", "Exchange"),
    ("https://management.azure.com", "Azure Mgmt"),
    ("https://api.manage.microsoft.com", "Intune"),
    ("https://substrate.office.com", "Substrate"),
    ("https://onenote.com", "OneNote"),
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
    ("https://manage.office.com", "Office Mgmt API"),
    ("https://protection.office.com", "Office Protection"),
    ("https://compliance.microsoft.com", "Compliance Center"),
    ("https://api.security.microsoft.com", "Security API"),
    ("https://api.spaces.skype.com", "Skype/Teams API"),
    ("https://api.yammer.com", "Yammer"),
    ("https://tasks.office.com", "Planner"),
    ("https://to-do.microsoft.com", "To-Do"),
    ("https://mam.manage.microsoft.com", "MAM"),
    ("https://intunemam.microsoftonline.com", "Intune MAM"),
    ("499b84ac-1321-427f-aa17-267ca6975798", "Azure DevOps"),
    ("https://feeds.office.com", "Office Feeds"),
    ("00000002-0000-0000-c000-000000000000", "AAD Graph (app ID)"),
    ("00000003-0000-0000-c000-000000000000", "MS Graph (app ID)"),
    ("00000003-0000-0ff1-ce00-000000000000", "SharePoint (app ID)"),
    ("00000006-0000-0ff1-ce00-000000000000", "Exchange (app ID)"),
    ("fc780465-2017-40d4-a0c5-307022471b92", "WindowsDefenderATP"),
    ("cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", "Teams Services"),
    ("48af08dc-f6d2-435f-b2a7-069abd99c086", "Intune Enrollment"),
]


def v1_resource(name, sp_host=None):
    r = V1_RESOURCES.get(name, name)
    return r.replace("{sp_host}", sp_host or "")


def v2_scope(name, sp_host=None):
    s = V2_SCOPES.get(name, name)
    return s.replace("{sp_host}", sp_host or "")
