import argparse as ap
import os
import re
import subprocess
from argparse import RawTextHelpFormatter
from utils import bcolors, command_exists, display_title

ALL_DOMAINS = []

def print_process_result(result):
    print(result)
    
def execute_simple_command(command):
    ret = subprocess.run(command, stdout=subprocess.PIPE).stdout.decode('utf-8')
    print_process_result(ret)

def process_ldapsearch(ip):
    for domain in ALL_DOMAINS:
        domain_upper = domain.upper()
        domain_split = domain_upper.split('.')
        domain_string = 'DC=' + ',DC='.join(domain_split)
        ret = subprocess.run(['ldapsearch', '-x', '-h', ip, f'-b "{domain_string}"'], stdout=subprocess.PIPE).stdout.decode('utf-8')
        print_process_result(f"\n\n=========== {domain_string} ==========\n")
        print_process_result(ret)
    
def clean_domains_found(domains_founds, domains, params_ip, params_domain):
    for domain in domains:
        if domain not in domains_founds and domain != params_domain and params_ip != domain:
            domains_founds.append(domain)
    return domains_founds

def process_digs(ip, domain):
    digs = [
        f"dig axfr {domain} @{ip}",
        f"dig ANY @{ip} {domain}",
        f"dig A @{ip} {domain}",
        f"dig AAAA @{ip} {domain}",
        f"dig TXT @{ip} {domain}",
        f"dig MX @{ip} {domain}",
        f"dig NS @{ip} {domain}"
    ]
    
    domains_founds = []
    for dig in digs:
        ret = subprocess.run(dig.split(' '), stdout=subprocess.PIPE).stdout.decode('utf-8')
        if 'failed' in ret:
            continue
        splited_ret = ret.split('\n')
        splited_ret.insert(0, f'\n\n====== {dig} ======')
        clean_ret = '\n'.join(splited_ret[:-5])
        print_process_result(clean_ret)
        domains = re.findall(r'(?:[\w-]+\.)+[\w-]+', '\n'.join(splited_ret[3:]))
        domains_founds = clean_domains_found(domains_founds, domains, ip, domain)
    
    print_process_result(f"{bcolors.OKBLUE}\n\n\nPotentials domains or ips found:\n{bcolors.ENDC}")
    print_process_result('\n'.join(domains_founds))
    return domains_founds
    
def process_nmaps(ip, domain, upd):
    options = [
        f"-sT -Pn -n -A --open {domain} -sV -p53,88,135,139,389,445,464,593,636,3268,3269,3389",
        "-n -sV --script 'ldap* and not brute' -p 389"
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

if __name__ == "__main__":
    parser = ap.ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", "--domain", required=True, type=str, help='Domain name: example.com')
    parser.add_argument("-i", "--ip", required=True, type=str, help='IP address.')
    parser.add_argument("-u", "--udp", required=False, action='store_true', default=False, help='Perform UDP scans.')
    parser.add_argument("-o", "--output", required=False, type=str, help='Output file.')
    args = parser.parse_args()
    
    # Args
    output = args.output
    ip = args.ip
    domain = args.domain
    udp = args.udp
    
    # Global variables
    ALL_DOMAINS.append(domain)
    
    if output and not os.path.exists(output): # Create a output dir if not exist. 
        os.makedirs(output)
    
    processes = {
        'nmap': process_nmaps(ip, domain, udp),
        'dig': (lambda: process_digs(ip, domain)),
        'ldapsearch': (lambda: process_ldapsearch(ip)),
        'enum4linux': (lambda: execute_simple_command(f'enum4linux -a {ip}')),
        'crackmapexec': (lambda: execute_simple_command(f'crackmapexec smb {ip} -u '' -p '' --shares')),
        'smbmap': (lambda: execute_simple_command(f'smbmap -H {ip} -u anonymous'))
    }
    
    for command, process_fn in processes.items():
        display_title(command)
        if command_exists(command):
            process_fn()
        else:
            print_process_result(f"{bcolors.FAIL}{command} not found.{bcolors.ENDC}")
    
    