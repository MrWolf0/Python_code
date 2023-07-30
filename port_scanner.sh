#!/usr/bin/python3
import optparse
from socket import *


#This fun resolve the domain into ip add if no execption will return an ip of entered domain
from threading import Thread


def socket_scan(host, port):
    try:
        sock_connect = socket(AF_INET, SOCK_STREAM)

        # Here connection attempt time in sec

        sock_connect.settimeout(5)
      #  result = sock_connect.connect((host, port))

        # if result return 0 mean that there is no error printing blow statement

        print("[+] port {} is tcp open".format(port))

    # if the result !=0 there is an exception printing blow statement

    except Exception as exeption:
        print("[-] port {} is tcp closed".format(port))
        print("[-] Reason is {}: ".format(exeption))
    sock_connect.close()


def port_on_sub_domain(domain, ports):
    try:
        ip = gethostbyname(domain)
        print('[+] Scanning for {} '.format(ip))
    except:
        print('[-] cannot resolve {} unknown host'.format(ip))
        return
    for port in ports:
        target = socket_scan(ip, int(port))
        t = Thread(target)
        t.start()


#here using optparse to parse user arguments

def main():
    print("."*50)
    parser = optparse.OptionParser(" test if the domain up or not by test ports please use options -d domain ")
    parser.add_option('-d', '--domain', dest='host', type='string', help='domain name')
    #parser.add_option('-p', '--port,list of ports', dest='port', type='string', help='port number')
    (options, args) = parser.parse_args()
    host = options.host
    port = [80,433]
    if host == None:
        print(parser.usage)
        exit(0)
    port_on_sub_domain(host, port)
    print("."*50)

if __name__=='__main__':
    main()
