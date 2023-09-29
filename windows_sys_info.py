import logging
import os
import sys
from pathlib import Path
from subprocess import Popen, TimeoutExpired


def get_system_info(sysinfo_file: Path):
    # If the OS is Windows 
    if os.name == 'nt':
        syntax = ['systeminfo', '&', 'tasklist', '&', 'sc', 'query']
    try:
        # Setup system info gathering commands  process 
        with sysinfo_file.open('a', encoding='utf-8') as system_info:
            # Setup system info gathering commands  process 
            with Popen(syntax, stdout=system_info, stderr=system_info, shell=True) as get_sysinfo:
                # Execute  process #
                get_sysinfo.communicate(timeout=30)

    # If error occurs during file operation 
    except OSError as file_err:
        print_err(f'Error occurred during file operation: {file_err}')
        logging.exception('Error occurred during file operation: %s\n', file_err)

    # If process error or timeout occurs 
    except TimeoutExpired:
        pass



def print_err(msg: str):
   # Displays the passed in error message via stderr.
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)
def main():
#Create a temp folder in c 
    export_path = Path('C:\\Tmp\\')
    export_path.mkdir(parents=True, exist_ok=True)
    sysinfo_file = export_path / 'system_info.txt'
    get_system_info(sysinfo_file)

if __name__ == '__main__' :
    try:
        main()
    except Exception as ex:
        print_err(f"Unknown error please check network configuration:{ex}")
        sys.exit(0)
        
