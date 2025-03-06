import requests
from requests.auth import HTTPBasicAuth
from getpass import getpass
import my_pass
# F5 BIG-IP details
F5_HOST = "192.168.1.179"  # F5 management IP
##F5_USER = input("Enter F5 username: ")
##F5_PASSWORD = getpass("Enter F5 password: ")

F5_USER = my_pass.F5_USER
F5_PASSWORD = my_pass.F5_PASSWORD

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

def create_monitor(token, monitor_type, monitor_name, **kwargs):
    """Create a Monitor of a specific type."""
    url = f"https://{F5_HOST}/mgmt/tm/ltm/monitor/{monitor_type}"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    payload = {
        "name": monitor_name,
        "partition": PARTITION,
        **kwargs  # Include additional parameters
    }
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Monitor '{monitor_name}' of type '{monitor_type}' created successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to create Monitor: {e}")
        exit(1)
def create_tcp_monitor(f5_host, token, monitor_name, destination_port, **kwargs):
    """
    Create a TCP Monitor on F5 BIG-IP.

    :param f5_host: F5 management IP or hostname (e.g., "192.168.1.200").
    :param token: Authentication token obtained from F5.
    :param monitor_name: Name of the TCP monitor to create.
    :param destination_port: Destination port for the monitor (e.g., 2090).
    :param kwargs: Additional parameters for the monitor (e.g., interval, timeout, send, recv).
    :return: None
    """
    # Construct the URL for creating the monitor
    url = f"https://{f5_host}/mgmt/tm/ltm/monitor/tcp"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }

    # Construct the payload with the specified destination port
    payload = {
        "name": monitor_name,
        "partition": "Common",  # Default partition; adjust if needed
        "defaultsFrom": "/Common/tcp",  # Parent TCP monitor template
        "destination": f"*:{destination_port}",  # Use the specified port
        **kwargs  # Include additional parameters
    }

    try:
        # Send the POST request to create the monitor
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"TCP Monitor '{monitor_name}' created successfully for port {destination_port}.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to create TCP Monitor: {e}")


token = get_auth_token()
    create_tcp_monitor(F5_HOST, token, monitor_name="B2B_DP_PRE_2089", destination_port=2089, interval=5, timeout=16)
