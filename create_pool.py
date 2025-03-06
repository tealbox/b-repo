import requests

def get_auth_token(f5_host, username, password):
    """
    Authenticate with F5 BIG-IP and retrieve an authentication token.
    """
    url = f"https://{f5_host}/mgmt/shared/authn/login"
    payload = {
        "username": username,
        "password": password,
        "loginProviderName": "tmos"
    }
    response = requests.post(url, json=payload, verify=False)
    response.raise_for_status()
    return response.json()["token"]["token"]

def create_tcp_monitor(f5_host, token, monitor_name, destination_port):
    """
    Create a custom TCP Monitor on F5 BIG-IP.

    :param f5_host: F5 management IP or hostname (e.g., "192.168.1.200").
    :param token: Authentication token obtained from F5.
    :param monitor_name: Name of the TCP monitor to create.
    :param destination_port: Destination port for the monitor (e.g., 2034).
    :return: None
    """
    url = f"https://{f5_host}/mgmt/tm/ltm/monitor/tcp"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    payload = {
        "name": monitor_name,
        "partition": "Common",  # Default partition; adjust if needed
        "defaultsFrom": "/Common/tcp",  # Parent TCP monitor template
        "destination": f"*:{destination_port}",  # Use the specified port
        "interval": 5,  # Check every 5 seconds
        "timeout": 16   # Timeout after 16 seconds
    }

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"TCP Monitor '{monitor_name}' created successfully for port {destination_port}.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to create TCP Monitor: {e}")

def create_pool_with_monitor(f5_host, token, pool_name, members, monitor_name):
    """
    Create a Pool with members and attach a health monitor.

    :param f5_host: F5 management IP or hostname (e.g., "192.168.1.200").
    :param token: Authentication token obtained from F5.
    :param pool_name: Name of the pool to create.
    :param members: List of member dictionaries (e.g., [{"address": "192.168.1.11", "port": 80}, ...]).
    :param monitor_name: Name of the health monitor to attach (e.g., "/Common/Monitor_TCP_2034").
    :return: None
    """
    url = f"https://{f5_host}/mgmt/tm/ltm/pool"
    headers = {
        "X-F5-Auth-Token": token,
        "Content-Type": "application/json"
    }
    payload = {
        "name": pool_name,
        "partition": "Common",  # Default partition; adjust if needed
        "loadBalancingMode": "round-robin",  # Load balancing method
        "members": [
            {
                "name": f"{member['address']}:{member['port']}",
                "address": member["address"],
                "port": member["port"]
            }
            for member in members
        ],
        "monitor": monitor_name  # Attach the monitor
    }

    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        print(f"Pool '{pool_name}' created successfully with monitor '{monitor_name}'.")
    except requests.exceptions.RequestException as e:
        print(f"Failed to create Pool: {e}")

if __name__ == "__main__":
    # F5 details
    F5_HOST = "192.168.1.200"
    F5_USER = "admin"
    F5_PASSWORD = "password"

    # Authenticate and get token
    token = get_auth_token(F5_HOST, F5_USER, F5_PASSWORD)

    # Configuration Parameters
    MONITOR_NAME = "Monitor_TCP_2034"
    DESTINATION_PORT = 2034
    POOL_NAME = "my-pool"
    MEMBERS = [
        {"address": "192.168.1.11", "port": 80},
        {"address": "192.168.1.12", "port": 80}
    ]

    # Step 1: Create the TCP Monitor
    create_tcp_monitor(
        f5_host=F5_HOST,
        token=token,
        monitor_name=MONITOR_NAME,
        destination_port=DESTINATION_PORT
    )

    # Step 2: Create the Pool and Attach the Monitor
    create_pool_with_monitor(
        f5_host=F5_HOST,
        token=token,
        pool_name=POOL_NAME,
        members=MEMBERS,
        monitor_name=f"/Common/{MONITOR_NAME}"
    )
