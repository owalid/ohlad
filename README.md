<div align="center">
<img height="350px" src="https://user-images.githubusercontent.com/28403617/176711745-5f48365d-ab9f-427e-9218-94f44b81d965.svg#gh-light-mode-only">
<img height="350px" src="https://user-images.githubusercontent.com/28403617/176711750-dafd4103-d60a-4ceb-b4d6-2c1e4f49ad47.svg#gh-dark-mode-only">
</div>

# Description

## 🇫🇷

`ohlad` est un script permettant de faire de la reconnaissance sur des systèmes de type `active directory` (Windows AD).
Le script se base sur des commandes déjà existantes, type `nmap`, `smbmap`, `enum4linux` etc.

Le script est capable de:

- Rechercher des domaines ou sous domaine via la commande `dig`.
- Lister les ports ouverts ainsi que les versions de chaque service (udp ou tcp).
- Tester des `credentials` par défaut sur le protocole SMB.
- Rechercher des informations via les protocoles LDAP et SMB.


## 🇺🇸

`ohlad` is a script that allows to do recon on `active directory` systems (Windows AD).
The script is based on existing commands, such as `nmap`, `smbmap`, `enum4linux` etc.

The script is able to:

- Search for domains or subdomains with the `dig` command.
- List open ports and versions of each service (udp or tcp).
- Test default credentials on the SMB protocol.
- Search information LDAP and SMB protocols.


# Usage

```
usage: sudo python3 ohlad.py [-h] -d DOMAIN -i IP [-skip-nmap] [-u]
                [-nmap-level NMAP_LEVEL] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -d DOMAIN, --domain DOMAIN
                        Domain name: example.com
  -i IP, --ip IP        IP address.

optional arguments:
  -skip-nmap, --skip-nmap
                        Skip nmap scan
  -u, --udp             Perform UDP scans.
  -nmap-level NMAP_LEVEL, --nmap-level NMAP_LEVEL
                        Nmap scan level. 1-3
  -o OUTPUT, --output OUTPUT
                        Output file.
```

# Example

```
sudo python3 ohlad.py -i 10.10.11.23 -d domain.com
```
