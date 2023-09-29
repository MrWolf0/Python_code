import logging
import os
import sys
from pathlib import Path
from socket import socket
from subprocess import Popen, TimeoutExpired

import requests


def get_network_info(export_path: Path, network_file: Path):
    # If the OS is Windows #
    if os.name == 'nt':
        # Get the saved Wi-Fi network information, IP configuration, ARP table,
        # MAC address, routing table, and active TCP/UDP ports #
        syntax = ['Netsh', 'WLAN', 'export', 'profile',
                  f'folder={str(export_path)}',
                  'key=clear', '&', 'ipconfig', '/all', '&', 'arp', '-a', '&',
                  'getmac', '-V', '&', 'route', 'print', '&', 'netstat', '-a']

    try:
        # Open the network information file in write mode and log file in write mode #
        with network_file.open('w', encoding='utf-8') as network_io:
            try:
                # Setup network info gathering commands child process #
                with Popen(syntax, stdout=network_io, stderr=network_io, shell=True) as commands:
                    # Execute child process #
                    commands.communicate(timeout=60)

            # If execution timeout occurred #
            except TimeoutExpired:
                pass

            # Get the hostname #
            hostname = socket.gethostname()
            # Get the IP address by hostname #
            ip_addr = socket.gethostbyname(hostname)

            try:
                # Query ipify API to retrieve public IP #
                public_ip = requests.get('https://api.ipify.org').text

            # If error occurs querying public IP #
            except requests.ConnectionError as conn_err:
                public_ip = f'* Ipify connection failed: {conn_err} *'

            # Log the public and private IP address #
            network_io.write(f'[!] Public IP Address: {public_ip}\n'
                             f'[!] Private IP Address: {ip_addr}\n')

    # If error occurs during file operation #
    except OSError as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during file operation: %s\n', file_err)
def print_err(msg: str):
   # Displays the passed in error message via stderr.
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)
def main():
#Create a temp folder in c 
    working_path = Path('C:\\Temp\\')
    network_info = working_path / 'wolf_net.txt'
    get_network_info(working_path,network_info)
if __name__ == '__main__' :
    try:
        main()
    except Exception as ex:
        print_err(f"Unknown error please check network configuration:{ex}")
        sys.exit(0)
        
