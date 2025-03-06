import requests
from requests.auth import HTTPBasicAuth
from getpass import getpass

# F5 BIG-IP details
F5_HOST = "192.168.1.200"  # F5 management IP
F5_USER = input("Enter F5 username: ")
F5_PASSWORD = getpass("Enter F5 password: ")
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

def list_virtual_servers(token):
    """List all Virtual Servers (VIPs)."""
    url = f"https://{F5_HOST}/mgmt/tm/ltm/virtual?$select=name,destination,pool"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("items", [])
    except requests.exceptions.RequestException as e:
        print(f"Failed to list Virtual Servers: {e}")
        return []

def list_pools(token):
    """List all Pools and their members."""
    url = f"https://{F5_HOST}/mgmt/tm/ltm/pool?$select=name,membersReference"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("items", [])
    except requests.exceptions.RequestException as e:
        print(f"Failed to list Pools: {e}")
        return []

def get_pool_members(token, pool):
    """Retrieve members of a specific pool."""
    members_url = pool["membersReference"]["link"].replace("localhost", F5_HOST)
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(members_url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("items", [])
    except requests.exceptions.RequestException as e:
        print(f"Failed to retrieve members for pool {pool['name']}: {e}")
        return []

if __name__ == "__main__":
    # Authenticate and get token
    token = get_auth_token()

    # List Virtual Servers (VIPs)
    print("\n--- Virtual Servers (VIPs) ---")
    virtual_servers = list_virtual_servers(token)
    if not virtual_servers:
        print("No Virtual Servers found.")
    else:
        for vs in virtual_servers:
            print(f"Name: {vs['name']}")
            print(f"  Destination: {vs['destination']}")
            print(f"  Pool: {vs.get('pool', 'N/A')}")
            print("")

    # List Pools and their members
    print("\n--- Pools ---")
    pools = list_pools(token)
    if not pools:
        print("No Pools found.")
    else:
        for pool in pools:
            print(f"Pool Name: {pool['name']}")
            members = get_pool_members(token, pool)
            if not members:
                print("  No members found.")
            else:
                for member in members:
                    print(f"  Member: {member['name']} (Address: {member['address']}, Port: {member['port']})")
            print("")
