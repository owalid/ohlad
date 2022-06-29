import subprocess

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
    return subprocess.call("type " + command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def display_title(title):
    print(f"{bcolors.WARNING}\n\n> {title}\n\n{bcolors.ENDC}")