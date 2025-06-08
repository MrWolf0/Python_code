# import some modules
from random import randint
import optparse
import re

# using optparse to getting the data entered by the user
parser = optparse.OptionParser("Generate a list of ips based on a given number use option -s to pass limit ")
parser.add_option('-s', dest='size', type='int', help='number of ips want to generate')
(options, args) = parser.parse_args()
size_ = options.size

# exit if no option passed
if size_ is None:
    print(parser.usage)
    exit(0)
list_ip = []

# loop to generate random ips
for _ in range(size_):
    list_ip.append('.'.join(str(randint(0, 255)) for _ in range(4)))
print(list_ip)

# pattern to extract only ip and ignor ',' in the above list
ip_patter = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# append data to a file called wolf in the same dir
for ip in list_ip:
    open_file = open('wolf.txt', 'a')
    open_file.write(ip_patter.search(ip)[0] + '\n')
    open_file.close()
