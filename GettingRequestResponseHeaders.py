#!/usr/bin/python3
import optparse
from socket import *
import urllib.request
from urllib.request import Request

#This fun resolve the domain into ip add if no execption will return an ip of entered domain
def resolve_ip(host):
    try:
        ip = gethostbyname(host)
        print('[+] resolve ' + host + ' to {} '.format(ip))

    except Exception as ex:
        print('[-] cannot resolve ip unknown host {}'.format(host))
        print(ex)
        return

#here we establish a connection over http protocol using build_opener and install_opener in urllib 
#choosen build_opener and install_opener in urllib because the OpenerDirector class has alot of handlers that can automatically handle the request 
def opener_url(url,USER_AGENT):
    resolve_ip(url)
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', USER_AGENT)]
    urllib.request.install_opener(opener)
    response = urllib.request.urlopen(str('https://'+url))
    print('response header')
    print('-'*50)
    for header,value in response.getheaders():
        print(header + ":" + value)
    request = Request('https://'+url)
    request.add_header('User-agent', USER_AGENT)
    print('-'*50)
#here using optparse to parse user arguments
def main():
    parser = optparse.OptionParser("get request and response  headers of an url please use -U <Url> or --url and user Agent between ''")
    parser.add_option('-U', '--url', dest='host', type='string', help='url host')
    parser.add_option('-A', '--user-agent', dest='agent', type='string', help='user-agent')
    (options, args) = parser.parse_args()
    host = options.host
    useragent = options.agent
    if host == None:
        print(parser.usage)
        exit(0)
    opener_url(host, useragent)
if __name__=='__main__':
    main()
