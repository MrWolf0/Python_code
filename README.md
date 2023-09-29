# Python scripts

In this repository, there are a scripts created as kind of fun to improve my skills in how write and use python
as tool of my penetration test

| File                            |
| ------------------------------- | 
| `getting_request_response.py`   | 
| `mac_changer.py`                | 
| `ip_list.py`                    | 
| `port_scanner.py`               | 
| `loginBruteForce.py`            | 
| `windows_network_info.py`       | 

## scripts :page_with_curl:

* **getting_request_response.py**
  * [getting_request_response.py](./getting_request_response.py): `getting_request_response` is a script using to get `header of respose` from a host by passing `user agent` as a paramter between `' '` and host as arguments also the script `resolve the host into ipv4`.

* **mac_changer.py**
  * [mac_changer.py](./mac_changer.py): `mac_changer` is a script using for change your `mac address` 

* **ip_list.py**
  * [ip_list.py](./GenerateRandomIpList.py): ip_list is a script used for generate `rondom ips` depends on the `number` you pass and creating a file named as `wolf.txt` in the same dir you can use the generated file as a list in `testing X-Forwared-For header` using an intager values passing through `-s option`.

* **port_scanner.py**
  * [port_scanner.py](./port_scanner.py): `port_scanner` is a script to test open ports on a host you can test a `single port or a list of ports` pass host/ip and single/list of ports as argument to the script using `options -h` for host and `-p for ports`.

* **loginBruteForce.py**
  * [loginBruteForce.py](./loginBruteForce.py): `loginBruteForce` this script designed to generate `2 files username and password` the idea is that you have an account you control and after failed attempets to login maybe `blocked`.
  That files used in that script `prevent blocking based on the number you feed it` and put your `username and password together` to forwared as correct credinitiales before blockling

* **windows_network_info.py**
  * [windows_network_info.py](./windows_network_info.py):  `Get the saved Wi-Fi network information` and if the SSID not `protected` it will show the password in `clear` txet  and `runs an array of commands to query network information`, such as `network profiles`,
    `ip configuration`, `arp table`, `routing table`, `tcp/udp ports`, and attempt to query the `ipify.org API` for public IP address. All the output is redirected to the `wolf_net` output file if an error occures print the error to `file_err`.

