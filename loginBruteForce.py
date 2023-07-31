import optparse
from colorama import Fore


# here a function to open the user file in read mode remove newlines in the file storing the data in list
def opening_file(file_to_pass, arg_data):
    return_list = []
    counter = 0
    # open file
    with open(file_to_pass, 'r') as file:
        for line in file:
            line.strip()
            return_list.append(line)
            list_length = len(return_list)
            # inserting user data in the list in the index n based on the number entered before he blocked
            for _ in range(list_length):
                if counter <= list_length:
                    return_list.insert(counter, arg_data)
                    counter = counter + attempts
    return return_list

# generate username file
def generate_user_file(username_list):
    for line in username_list:
        open_file = open('wolf_users.txt', 'a')
        open_file.write(line.strip() + '\n')
        open_file.close()

# generate password file
def generate_password_file(password_list):
    for line in password_list:
        open_file = open('phoenix_password.txt', 'a')
        open_file.write(line.strip() + '\n')
        open_file.close()


parser = optparse.OptionParser(
    "[-] this script for brute force login based on number of attempts before blocked options -u for valid username -p "
    "for valid password -n number of -w username file name -x password file name attempts before blocked " + Fore.CYAN + "login_brute_force -u wolf -p phoenix -n 3 -w wolf.txt -x phoenix.txt")
parser.add_option('-u', dest='username', type='string', help='valid username')
parser.add_option('-p', dest='password', type='string', help='valid password')
parser.add_option('-w', dest='user_file_name', type='string')
parser.add_option('-x', dest='password_file_name', type='string')
parser.add_option('-n', dest='attempts', type='int', help='number of attempts before blocked')
(options, args) = parser.parse_args()
valid_user = options.username
valid_password = options.password
attempts = options.attempts
userfname = options.user_file_name
passfname = options.password_file_name
if valid_user is None:
    print(parser.usage)
    exit(0)
print('[+] generating username file done final result in wolf_users.txt')
generate_user_file(opening_file(userfname, valid_user))
print('[+] generating password file done final result in phoenix_password.txt')
generate_password_file(opening_file(passfname, valid_password))
