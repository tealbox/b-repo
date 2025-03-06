import requests
from requests.auth import HTTPBasicAuth
from getpass import getpass

# F5 BIG-IP details
F5_HOST = "192.168.1.200"  # F5 management IP
F5_USER = input("Enter F5 username: ")
F5_PASSWORD = getpass("Enter F5 password: ")

# VIP and Pool Configuration
VIP_NAME = "my_vip"
VIP_ADDRESS = "192.168.1.100"
VIP_PORT = 80
POOL_NAME = "my_pool"
POOL_MEMBERS = ["192.168.1.11:80", "192.168.1.12:80"]
PARTITION = "Common"  # Default partition

# Disable SSL warnings (for testing only)
requests.packages.urllib3.disable_warnings()

def get_auth_token():
    """Authenticate with F5 and retrieve session token."""
    url = f"https://{F5_HOST}/mgmt/shared/authn/login"
    payload = {
        "username": F5_USER,
        "password": F5_PASSWORD,
        "loginProviderName": "tmos"
    }
    try:
        response = requests.post(url, json=payload, verify=False)
        response.raise_for_status()
        return response.json()["token"]["token"]
    except requests.exceptions.RequestException as e:
        print(f"Authentication failed: {e}")
        exit(1)

def create_pool(token):
    """Create a pool with backend servers."""
    url = f"https://{F5_HOST}/mgmt/tm/ltm/pool"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    payload = {
        "name": POOL_NAME,
        "partition": PARTITION,
        "members": [{
            "name": member,
            "address": member.split(":")[0],
            "port": int(member.split(":")[1])
        } for member in POOL_MEMBERS]
    }
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Pool '{POOL_NAME}' created successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to create pool: {e}")
        exit(1)

def create_virtual_server(token):
    """Create a Virtual Server (VIP)."""
    url = f"https://{F5_HOST}/mgmt/tm/ltm/virtual"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    payload = {
        "name": VIP_NAME,
        "partition": PARTITION,
        "destination": f"{VIP_ADDRESS}:{VIP_PORT}",
        "ipProtocol": "tcp",
        "pool": POOL_NAME,
        "profiles": [
            {"name": "tcp", "partition": "Common"}
        ]
    }
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Virtual Server '{VIP_NAME}' (VIP {VIP_ADDRESS}:{VIP_PORT}) created successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to create Virtual Server: {e}")
        exit(1)

if __name__ == "__main__":
    # Authenticate and get token
    token = get_auth_token()

    # Create Pool and VIP
    create_pool(token)
    create_virtual_server(token)
