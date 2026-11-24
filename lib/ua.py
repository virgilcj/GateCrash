"""User-Agent strings per platform. Platform is evaluated from UA in ROPC/authorize flows
(client-controlled, spoofable) -- this is the central asymmetry the framework exploits.

macOS / iOS / Android typically return 50076 (MFA only) when a Windows-only device-compliance
CA exists; Windows / Linux / ChromeOS return 53003.
"""

UA = {
    "windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.144",
    "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/17.2 Safari/605.1.15",
    "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
           "Version/17.2 Mobile/15E148 Safari/604.1",
    "android": "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/120.0.6099.144 Mobile Safari/537.36",
    "linux": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "chromeos": "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36",
    # Broker uses a WebView UA for the PRT authorize flow.
    "broker": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; WebView/3.0) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/70.0.3538.102 Safari/537.36 Edge/18.19044",
}

# Platforms that commonly bypass device-compliance CA (try these first).
BYPASS_PLATFORMS = ["macos", "ios", "android"]
ALL_PLATFORMS = ["windows", "macos", "ios", "android", "linux", "chromeos"]


def get(platform):
    return UA.get(platform, UA["windows"])
