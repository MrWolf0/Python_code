#!/usr/bin/env python
import optparse
import re
import subprocess


# This code only for linux users and to run the code you need sudo before running the script.

# A function that change the mac add to the new one that the user enter using the terminal.
def changing_mac(interface, new_mac_add):
    print("[+] changing the Mac address of " + interface)
    
    subprocess.run(["ifconfig", interface, "down"])
    
    subprocess.run(["ifconfig", interface, "hw", "ether", new_mac_add])
    
    subprocess.run(["ifconfig", interface, "up"])
    
    print("[+] done ....")
    

# This function hold the variables that the user enter and return them in object formate.
def get_user_arguments():
    parser = optparse.OptionParser()
    
    parser.add_option("-i", "--interface", dest="interface",
                      help="The interface you want to change its MAC address eg wlan or ether ")
    
    parser.add_option("-m", "--mac", dest="mac_add", help="New MAC you want to change ")
    
    (options, arguments) = parser.parse_args()
    
    if not options.interface:
        parser.error("[-] please specify an interface, use -h or --help for more info ")
    elif not options.mac_add:
        parser.error("[-] please specify a mac, use -h or --help for more info ")
    return options


# This function read current MAC add from terminal output using regex expressions and return the value of that MAC.
def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    
    mac_add_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result.decode('utf-8'))
    
    if mac_add_search_result:
        return mac_add_search_result.group(0)
    else:
        print(("[-] could not able to read the MAC address."))

# Hold vars that user enter.
options = get_user_arguments()
# Changing the MAC.
current_mac = get_current_mac(options.interface)

print("Current MAC address = " + str(current_mac))

changing_mac(options.interface, options.mac_add)

current_mac = get_current_mac(options.interface)
# Check if the MAC has been changed.
if current_mac == options.mac_add:
    print("[+] MAC address was successfully changed to " + current_mac)
else:
    print("[+] MAC address did not successfully change to " + current_mac)
