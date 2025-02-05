import requests
import random
import subprocess
import os
import json
import logging
import argparse
from prettytable import PrettyTable

# Global variables to store environment settings
PIA_USER = PIA_PASS = PIA_CA_CERT_PATH = PIA_WG_CONF_FILE = preferred_region = verbosity = None

def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch PIA token and generate a WireGuard configuration.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", "--piauser", type=str, metavar=("user"),
                        help="PIA account username (can also be set via PIA_USER env variable)")
    parser.add_argument("-p", "--piapass", type=str, metavar=("password"),
                        help="PIA account password (can also be set via PIA_PASS env variable)")
    parser.add_argument("-r", "--piaregion", type=str, metavar=("region"),
                        help="PIA region ID to connect to (can also be set via PIA_REGION env variable). Use -d to dump all current regions. Defaults to Singapore (sg)",
                        default=None)
    parser.add_argument("-w", "--piawgconf", type=str, metavar=("path/to/wg.conf"),
                        help="Output path for WireGuard config (can also be set via PIA_WG_CONF_FILE env variable). Defaults to piawg.conf in current directory",
                        default=None)
    parser.add_argument("-d", "--dumpregions", action='store_true',
                        help="Dump the current list of PIA regions and exit")
    parser.add_argument("-v", "--verbose", action="count", default=None,
                        help="Increase verbosity (-v for INFO, -vv for DEBUG; if not set, uses VERBOSE env variable or defaults to 0)")
    args = parser.parse_args()

    # Check if required credentials are provided via CLI or environment
    if not (args.piauser or os.getenv("PIA_USER")) or not (args.piapass or os.getenv("PIA_PASS")):
        if not args.dumpregions:
            parser.print_help()
            parser.error("PIA_USER and PIA_PASS must be provided via CLI or environment variables.")
    return args, parser

def setup_env(cli_args):
    """
    Initializes global configuration variables from environment variables and sets up logging based in verbosity level.

    Reads the following environment variables:
    - PIA_USER: PIA account username (required)
    - PIA_PASS: PIA account password (required)
    - PIA_CA_CERT_PATH: Path to PIA CA certificate (default: ca.rsa.4096.crt)
    - PIA_WG_CONF_FILE: Output path for WireGuard config (default: pia_wg.conf)
    - PIA_REGION: Preferred region ID (default: 'sg')
    - VERBOSE: Logging verbosity level (0=error, 1=info, 2=debug, default: 1)

    Returns:
        None

    Raises:
        ValueError: If environment variables PIA_USER or PIA_PASS are not set.
        FileNotFoundError: If the PIA CA certificate file is not found.
    """
    global PIA_USER, PIA_PASS, PIA_CA_CERT_PATH, PIA_WG_CONF_FILE, preferred_region, verbosity

    if cli_args.dumpregions:
        get_pia_regions(dump_regions_to_stdout=True)
        exit(0)

    # Fetch environment variables with default values
    PIA_CA_CERT_PATH = os.getenv('PIA_CA_CERT_PATH', "ca.rsa.4096.crt")
    if not os.path.exists(PIA_CA_CERT_PATH):
        # Let's try to download the cert
        PIA_CA_CERT_URL="https://raw.githubusercontent.com/pia-foss/desktop/refs/heads/master/daemon/res/ca/rsa_4096.crt"
        r = requests.get(PIA_CA_CERT_URL, allow_redirects=True, timeout=1)
        r.raise_for_status()

        open(PIA_CA_CERT_PATH, 'wb').write(r.content)
        # Exit if file still isn't downloaded
        if not os.path.exists(PIA_CA_CERT_PATH):
            raise FileNotFoundError("PIA CA certificate file not found.)")

    # For the WireGuard config file, use CLI value if given; otherwise check the environment variable
    PIA_WG_CONF_FILE = cli_args.piawgconf if cli_args.piawgconf else os.getenv('PIA_WG_CONF_FILE', "pia_wg.conf")

    # Verbosity: if CLI flag provided, use it; otherwise check env variable; default to 0
    if cli_args.verbose is not None:
        verbosity = cli_args.verbose
    else:
        verbosity = int(os.getenv('VERBOSE', "0"))

    preferred_region = cli_args.piaregion if cli_args.piaregion else os.getenv('PIA_REGION', "sg")

    # For PIA_USER and PIA_PASS, CLI arguments override environment variables
    PIA_USER = cli_args.piauser if cli_args.piauser else os.getenv('PIA_USER')
    PIA_PASS = cli_args.piapass if cli_args.piapass else os.getenv('PIA_PASS')

    # Validate required environment variables
    if not PIA_USER or not PIA_PASS:
        raise ValueError("Environment variables PIA_USER and/or PIA_PASS are not set.")

    # Configure logging based on verbosity level
    if verbosity > 1:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    elif verbosity == 1:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

    return

def get_pia_regions(dump_regions_to_stdout=False) -> dict:
    """
    Fetches the list of PIA regions and their server details.

    Returns:
        dict: A dictionary containing all PIA regions' server IPs, hostnames, etc.

    Raises:
        requests.exceptions.RequestException: If the request to fetch regions fails.
        json.JSONDecodeError: If the response cannot be parsed as JSON.
    """
    serverlist_url='https://serverlist.piaservers.net/vpninfo/servers/v6'

    response = requests.get(serverlist_url)

    # Check if the request was successful
    response.raise_for_status()

    # Parse the first line of the response as JSON
    first_line = next(response.iter_lines(), None)
    if first_line:
        logging.info(f"Fetched PIA Region and configs")
        pia_servers = json.loads(first_line.decode("utf-8"))
        pia_regions = pia_servers['regions']
        if (dump_regions_to_stdout):
            t = PrettyTable(['Name','ID','Country Code', 'Geo Located', 'Status'])
            for region in pia_regions:
                region_id = region['id']
                region_name = region['name']
                region_country = region['country']
                region_geo = region['geo']
                region_status = "Online" if not region['offline'] else "Offline"
                t.add_row([region_name, region_id, region_country, region_geo, region_status])
            print(t.get_string(sortby="Name"))
        return pia_regions
    else:
        logging.error(f"No data received:")
        return

def get_pia_wg_preferred_servers(pia_regions, preferred_region) -> list:
    """
    Filters and returns the WireGuard servers for the preferred region.

    Args:
        pia_regions (dict): A dictionary containing all PIA regions.
        preferred_region (str): The preferred region ID (e.g., "sg").

    Returns:
        list: A list of WireGuard servers for the preferred region.

    Raises:
        KeyError: If the preferred region or WireGuard servers are not found.
    """
    logging.info(f"Looking for config of region: {preferred_region}")
    for region in pia_regions:
        if region['id'] == preferred_region:
            logging.debug(f"Selected region config: {region}")
            return region['servers']['wg']
    raise KeyError(f"Preferred region '{preferred_region}' or WireGuard servers not found.")

def get_pia_wg_config(wg_servers, pia_token) -> dict:
    """
    Generates a WireGuard configuration by selecting a random server and registering the public key.

    Args:
        wg_servers (list): A list of WireGuard servers.
        pia_token (str): The PIA authentication token.

    Returns:
        dict: A dictionary containing the WireGuard configuration.

    Raises:
        subprocess.CalledProcessError: If the `wg` command fails.
        json.JSONDecodeError: If the response from the PIA API cannot be parsed as JSON.
    """

    # Select a random server from the list
    selected_server = random.choice(wg_servers)
    server_ip = selected_server['ip']
    server_hostname = selected_server['cn']

    # Generate WireGuard private and public keys
    wg_genkey_cmd = ["wg", "genkey"]
    result = subprocess.run(wg_genkey_cmd, capture_output=True, text=True)
    wg_pvtkey = result.stdout.strip()

    wg_pubkey_cmd = ["wg", "pubkey"]
    result = subprocess.run(wg_pubkey_cmd, input=wg_pvtkey, capture_output=True, text=True)
    wg_pubkey = result.stdout.strip()

    logging.debug(f"Wireguard keys: Pvt: {wg_pvtkey} Pub: {wg_pubkey}")

    # Register the public key with the PIA server
    curl_cmd = [
        "curl", "-s", "-G",
        "--connect-to", f"{server_hostname}::{server_ip}:",
        "--cacert", PIA_CA_CERT_PATH,
        "--data-urlencode", f"pt={pia_token}",
        "--data-urlencode", f"pubkey={wg_pubkey}",
        f"https://{server_hostname}:1337/addKey"
    ]
    logging.debug(f"Using Command: {curl_cmd}")
    result = subprocess.run(curl_cmd, capture_output=True, text=True)
    pia_wg_config_json = result.stdout

    # Parse the response and add the private key to the configuration
    pia_wg_config = json.loads(pia_wg_config_json)
    pia_wg_config['wg_pvtkey'] = wg_pvtkey

    logging.info(f"Received WireGuard Parameters from PIA")
    logging.debug(f"WireGuard Parameters Dump:\n{pia_wg_config}")

    if result.stderr:
        logging.error(f"STDERR: {result.stderr}")

    return pia_wg_config

def gen_wg_conf(pia_wg_config) -> str:
    """
    Generates a WireGuard configuration file content from the PIA WireGuard configuration.

    Args:
        pia_wg_config (dict): A dictionary containing the PIA WireGuard configuration.

    Returns:
        str: A string containing the WireGuard configuration file content.
    """

    # Interface section
    address = pia_wg_config['peer_ip']
    rt_table = 1337 # Custom routing table to avoid conflicts
    pvt_key = pia_wg_config['wg_pvtkey']
    # Configure routing rules for VPN traffic isolation
    post_up_1 = f"ip route add {address}/32 dev %i table {rt_table}"
    post_up_2 = f"ip rule add from {address}/32 lookup {rt_table}"
    post_down_1 = f"ip route del {address}/32 dev %i table {rt_table}"
    post_down_2 = f"ip rule del from {address}/32 lookup {rt_table}"

    # Peer Section
    keep_alive = 25
    pubkey = pia_wg_config['server_key']
    allowed_ips = "0.0.0.0/0"
    endpoint_ip = pia_wg_config['server_ip']
    endpoint_port = pia_wg_config['server_port']

    long_string = (
        f"[Interface]\n"
        f"Address = {address}\n"
        f"Table = {rt_table}\n"
        f"PrivateKey = {pvt_key}\n"
        f"PostUp = {post_up_1}\n"
        f"PostUp = {post_up_2}\n"
        f"PostDown = {post_down_1}\n"
        f"PostDown = {post_down_2}\n"
        f"\n"
        f"[Peer]\n"
        f"PersistentKeepalive = {keep_alive}\n"
        f"PublicKey = {pubkey}\n"
        f"AllowedIPs = {allowed_ips}\n"
        f"Endpoint = {endpoint_ip}:{endpoint_port}\n"
    )

    return long_string


def get_pia_token() -> str:
    """
    Fetches the PIA token using the provided credentials.

    Returns:
        str: The PIA token as a string.

    Raises:
        RuntimeError: If the request fails or the token is not found in the response.
    """
    try:
        # API endpoint
        url = 'https://www.privateinternetaccess.com/api/client/v2/token'
        payload = {
            'username': PIA_USER,
            'password': PIA_PASS
        }

        # Make the POST request
        logging.info(f"Requesting for a token from {url}")
        response = requests.post(url, data=payload)

        # Check if the request was successful
        response.raise_for_status()

        # Parse the JSON response into a dictionary
        response_data = response.json()

        # Extract the token from the response
        token = response_data.get('token')
        if token:
            logging.debug(f"Received token: {token}")
            return token
        else:
            raise RuntimeError("Token not found in the response.")

    except requests.exceptions.RequestException as e:
        # Handle request-related errors (e.g., connection errors, timeouts, etc.)
        logging.error(f"Request failed: {e}")
        raise RuntimeError(f"Request failed: {e}")
    except json.JSONDecodeError as e:
        # Handle JSON parsing errors
        logging.error(f"Failed to parse JSON response: {e}")
        raise RuntimeError(f"Failed to parse JSON response: {e}")
    except Exception as e:
        # Handle any other unexpected errors
        logging.error(f"An unexpected error occurred: {e}")
        raise RuntimeError(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    try:
        # Set up environment and fetch required configurations
        args, parser = parse_args()
        setup_env(args)
        token = get_pia_token()
        pia_regions=get_pia_regions()

        # Get preferred WireGuard servers and generate configuration
        wg_servers=get_pia_wg_preferred_servers(pia_regions, preferred_region)
        pia_wg_config=get_pia_wg_config(wg_servers, token)

        # Generate and write the WireGuard configuration file
        custom_wg_conf = gen_wg_conf(pia_wg_config)
        logging.debug(f"Wireguard Config Dump: {pia_wg_config}")
        with open(PIA_WG_CONF_FILE, "w") as f:
            f.write(custom_wg_conf)
        print(f"Wireguard config written to: {PIA_WG_CONF_FILE}")

    except Exception as e:
        print(f"Failed to fetch token: {e}")

