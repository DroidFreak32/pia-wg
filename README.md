# PIA WireGuard Configuration Generator

This Python script automates the process of generating a WireGuard configuration file for Private Internet Access (PIA) VPN. It fetches the necessary credentials, selects a server in the preferred region, and generates a WireGuard configuration file.

## Features

- Fetches PIA authentication token using provided credentials.
- Retrieves the list of available PIA regions and servers.
- Generates WireGuard keys and registers them with the selected PIA server.
- Creates a WireGuard configuration file on an isolated routing table with routing rules to avoid conflicts.
- Supports command-line arguments for customization.

## Prerequisites

- Python 3.x
- `requests` library
- `prettytable` library
- `wg` command-line tool (WireGuard)

## Installation

1. Clone the repository.
2. Install the required Python libraries:

```bash
pip install -r requirements.txt
```

3. Ensure that the `wg` command-line tool is installed on your system.

## Usage

### Basic Usage

To generate a WireGuard configuration file with default settings:

```bash
python pia_wg_config_generate.py -u <PIA_USER> -p <PIA_PASS>
```

### Command-Line Arguments

| Argument          | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `-u`, `--piauser` | PIA account username (can also be set via `PIA_USER` environment variable). |
| `-p`, `--piapass` | PIA account password (can also be set via `PIA_PASS` environment variable). |
| `-r`, `--piaregion` | PIA region ID to connect to (default: 'sg' for Singapore).                |
| `-w`, `--piawgconf` | Output path for WireGuard config (default: `pia_wg.conf` in $PWD).        |
| `-d`, `--dumpregions` | Dump the current list of PIA regions and exit.                          |
| `-v`, `--verbose` | Increase verbosity (`-v` for INFO, `-vv` for DEBUG).                        |

### Example

To generate a WireGuard configuration for a specific region and save it to a custom file:

```bash
python pia_wg_config_generate.py -u <PIA_USER> -p <PIA_PASS> -r us -w custom_wg.conf
```

To get PIA credentials from [pass](https://www.passwordstore.org/) and generate a WireGuard config for Singapore region and save it to `/tmp/pia.conf`:

```bash
python3 pia_wg_config_generate.py -u $(pass vpn/pia/username) -p $(pass vpn/pia/pass) -r sg -w /tmp/pia.conf
```

To list all available regions:

```bash
python pia_wg_config_generate.py -d
```

## Environment Variables

The script can also be configured using environment variables:

| Variable            | Description                                      | Default Value          |
|---------------------|--------------------------------------------------|------------------------|
| `PIA_USER`          | PIA account username.                            | None                   |
| `PIA_PASS`          | PIA account password.                            | None                   |
| `PIA_CA_CERT_PATH`  | Path to PIA CA certificate.                      | `ca.rsa.4096.crt` in `$PWD` |
| `PIA_WG_CONF_FILE`  | Output path for WireGuard config.                | `pia_wg.conf` in `$PWD`  |
| `PIA_REGION`        | Preferred region ID.                             | `sg` (Singapore)       |
| `VERBOSE`           | Logging verbosity level (0=error, 1=info, 2=debug). | `0`                  |


## Output

The script generates a WireGuard configuration file (`pia_wg.conf` by default) with the following structure:

```ini
[Interface]
Address = <peer_ip>
Table = 1337
PrivateKey = <wg_pvtkey>
PostUp = ip route add <Address> dev %i table <Table>
PostUp = ip rule add from <Address> lookup <Table>
PostDown = ip route del <Address> dev %i table <Table>
PostDown = ip rule del from <Address> lookup <Table>

[Peer]
PersistentKeepalive = 25
PublicKey = <server_key>
AllowedIPs = 0.0.0.0/0
Endpoint = <server_ip>:<server_port>
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Acknowledgments

- [Private Internet Access (PIA)](https://www.privateinternetaccess.com/) for providing the VPN service.
- [pia-foss](https://github.com/pia-foss) for providing bash script as a reference.
- [WireGuard](https://www.wireguard.com/) for the VPN protocol.

