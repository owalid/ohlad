import subprocess
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def command_exists(command):
    '''
        Check if a command exists.
    '''
    return subprocess.call("type " + command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def display_title(title):
    '''
        Display a title in yellow color.
    '''
    print(f"{bcolors.WARNING}\n\n> {title}\n\n{bcolors.ENDC}")
    
def safe_open_w(path):
    '''
      Open "path" for writing, creating any parent directories as needed.
    '''
    if '/' in path:
        dir = os.path.dirname(path)
        if not os.path.exists(dir):
            os.makedirs(dir)
    return open(path, 'w')