import subprocess

WHITELIST = {
    "127.0.0.1",
    "0.0.0.0",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
}

# Only these private ranges can be blocked (internal network threats only)
BLOCKABLE_PREFIXES = (
    "10.",       # internal network
    "192.168.",  # internal network  
    "172.16.",   # internal network
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
)

def get_own_ips():
    try:
        result = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
        return set(result.stdout.strip().split())
    except Exception:
        return set()

def is_whitelisted(ip: str) -> bool:
    if not ip:
        return True

    # Only block internal IPs — never touch public internet
    if not ip.startswith(BLOCKABLE_PREFIXES):
        return True   # public IP → always whitelisted

    # Never block own machine
    if ip in get_own_ips():
        return True

    if ip in WHITELIST:
        return True

    return False
