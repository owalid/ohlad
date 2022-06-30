import argparse as ap
import re
import subprocess
from argparse import RawTextHelpFormatter
from utils import bcolors, command_exists, display_title, safe_open_w

OUTPUT_PATH = None
OUTPUT_FILE_CONTENT = ""
ALL_DOMAINS = []

def print_process_result(result):
    global OUTPUT_FILE_CONTENT
    print(result)
    if OUTPUT_PATH:
        # remove colors from result
        result = re.sub(r'\033\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]', '', result)
        OUTPUT_FILE_CONTENT += result
    
def execute_simple_command(command):
    ret = subprocess.run(command.split(' '), stdout=subprocess.PIPE).stdout.decode('utf-8')
    print_process_result(ret)

def process_ldapsearch(ip):
    global ALL_DOMAINS
    for domain in ALL_DOMAINS:
        domain_upper = domain.upper()
        domain_split = domain_upper.split('.')
        domain_string = 'DC=' + ',DC='.join(domain_split)
        ret = subprocess.run(['ldapsearch', '-x', '-h', ip, f'-b "{domain_string}"'], stdout=subprocess.PIPE).stdout.decode('utf-8')
        print_process_result(f"{bcolors.OKGREEN}\n\n=========== {domain_string} ==========\n{bcolors.ENDC}")
        print_process_result(ret)
    
def clean_domains_found(domains_founds, domains, params_ip, params_domain):
    for domain in domains:
        if domain not in domains_founds and domain != params_domain and params_ip != domain:
            domains_founds.append(domain)
    return domains_founds

def process_digs(ip, domain):
    global ALL_DOMAINS
    digs = [
        f"dig axfr {domain} @{ip}",
        f"dig ANY @{ip} {domain}",
        f"dig A @{ip} {domain}",
        f"dig AAAA @{ip} {domain}",
        f"dig TXT @{ip} {domain}",
        f"dig MX @{ip} {domain}",
        f"dig NS @{ip} {domain}"
    ]
    
    for dig in digs:
        ret = subprocess.run(dig.split(' '), stdout=subprocess.PIPE).stdout.decode('utf-8')
        if 'failed' in ret:
            continue
        splited_ret = ret.split('\n')
        print_process_result(f"{bcolors.OKGREEN}\n\n=========== {dig} ==========\n{bcolors.ENDC}")
        clean_ret = '\n'.join(splited_ret[:-5])
        print_process_result(clean_ret)
        domains = re.findall(r'(?:[\w-]+\.)+[\w-]+', '\n'.join(splited_ret[3:]))
        ALL_DOMAINS = clean_domains_found(ALL_DOMAINS, domains, ip, domain)
    
    print_process_result(f"{bcolors.OKBLUE}\n\n\nPotentials domains or ips found:\n{bcolors.ENDC}")
    print_process_result('\n'.join(ALL_DOMAINS))
    
def process_nmaps(ip, domain, upd, nmap_level):
    if nmap_level == 1:
        options = [f"-sT -Pn -n -A --open {domain} -sV -p53,88,135,139,389,445,464,593,636,3268,3269,3389"]
    elif nmap_level == 2:
        options = [f"-p- -A -Pn"]
    else:
        options = [f"-p- -A -T4 -sY -Pn"]
    
    options += [
        f"-p 88 --script=krb5-enum-users --script-args=\"krb5-enum-users.realm={domain}\"",
        "-n -sV --script ldap-rootdse -p 389",
        "-n -sV --script smb-check-vulns.nse -p 445",
        "-sU -sS --script smb-enum-domains.nse -p U:137,T:139"
    ]
    
    if upd:
        options.append("-sU -A -PN -n -pU:19,53,123,161 -script=ntp-monlist,dns-recursion,snmp-sysdescr")
    
    for option in options:
        ret = subprocess.run(f"nmap {option} {ip}".split(' '), stdout=subprocess.PIPE).stdout.decode('utf-8')
        if 'failed' in ret or 'QUITTING!' in ret or len(ret.split('\n')) < 5:
            continue
        nmap_header = 'PORT     STATE SERVICE           VERSION'
        splited_ret = ret.split(nmap_header)
        clean_ret = nmap_header + '\n' + '\n'.join(splited_ret[-1].split('\n')[:-3])
        print_process_result(clean_ret)

def process_smbclient_default_credentials(ip):
    print_process_result(f"{bcolors.OKBLUE}\n\n\nSearch default credentials for samba:\n{bcolors.ENDC}")
    credentials = [
        ":",
        "Administrator:",
        "Administrator:admin",
        "Administrator:administrator",
        "Administrator:password",
        "guest:",
        "admin:admin",
        "admin:administrator",
        "admin:password",
        "arcserve:arcserve",
        "arcserve:backup",
        "tivoli:tivoli",
        "tivoli:tmersrvd",
        "tmersrvd:tivoli",
        "backup:backup",
        "backup'",
        "test:",
        "test:test",
        "test:lab",
        "test:demo",
        "test:password",
        "lab:test",
        "lab:lab",
        "lab:demo",
        "lab:password",
        "anonymous:"
    ]
    potential_credentials = []
    for credential in credentials:
        credential_split = credential.split(':')
        if len(credential_split) == 2:
            username = credential_split[0]
            password = credential_split[1]
            ret = subprocess.run(f"crackmapexec smb {ip} -u {username} -p {password} --shares --users".split(' '), stdout=subprocess.PIPE).stdout.decode('utf-8')
            if not 'STATUS_ACCESS_DENIED' in ret and not 'STATUS_LOGON_FAILURE' in ret:
                potential_credentials.append(f"{username}:{password}\n{ret}")
            
    if len(potential_credentials):
        print_process_result(f"{bcolors.OKBLUE}\n\n\nPotentials credentials found in samba:\n{bcolors.ENDC}")
        print_process_result('\n'.join(potential_credentials))
    else:
        print_process_result(f"{bcolors.FAIL}\n\n\nNo default credentials found for samba.\n{bcolors.ENDC}")

if __name__ == "__main__":
    parser = ap.ArgumentParser(formatter_class=RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument("-d", "--domain", required=True, type=str, help='Domain name: example.com')
    required.add_argument("-i", "--ip", required=True, type=str, help='IP address.')
    optional.add_argument("-skip-nmap", "--skip-nmap", required=False, default=False, action='store_true', help='Skip nmap scan')
    optional.add_argument("-u", "--udp", required=False, action='store_true', default=False, help='Perform UDP scans.')
    optional.add_argument("-nmap-level", "--nmap-level", required=False, type=int, default=1, help='Nmap scan level. 1-3')
    optional.add_argument("-o", "--output", required=False, type=str, help='Output file.')
    args = parser.parse_args()
    
    # Args
    nmap_level = args.nmap_level
    skip_nmap = args.skip_nmap
    ip = args.ip
    domain = args.domain
    udp = args.udp
    
    if udp and skip_nmap:
        print("You can't skip nmap and perform UDP scans at the same time.")

    # Global variables
    OUTPUT_PATH = args.output
    ALL_DOMAINS.append(domain)
    
    processes = {
        'dig': (lambda: process_digs(ip, domain)),
        'ldapsearch': (lambda: process_ldapsearch(ip)),
        'enum4linux': (lambda: execute_simple_command(f'enum4linux -a {ip}')),
        'smbclient': (lambda: process_smbclient_default_credentials(ip))
    }

    if not skip_nmap:
        nmap_dict = {"nmap": (lambda: process_nmaps(ip, domain, udp, nmap_level))}
        processes = {**nmap_dict, **processes}

    for command, process_fn in processes.items():
        display_title(command)
        if command_exists(command):
            process_fn()
        else:
            print_process_result(f"{bcolors.FAIL}{command} not found.{bcolors.ENDC}")
    
    if OUTPUT_PATH:
        with safe_open_w(OUTPUT_PATH) as f:
            f.write(OUTPUT_FILE_CONTENT)
