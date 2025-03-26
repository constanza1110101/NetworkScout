#!/usr/bin/env python3
import argparse
import socket
import threading
import time
import whois
import dns.resolver
import requests
import json
import ssl
import ipaddress
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

def banner():
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════╗")
    print(f"║  NetworkScout - Advanced Recon Tool       ║")
    print(f"╚═══════════════════════════════════════════╝{Style.RESET_ALL}")

def port_scan(target, ports):
    open_ports = []
    def scan(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        if sock.connect_ex((target, port)) == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "unknown"
            open_ports.append((port, service))
        sock.close()
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan, ports)
    
    return open_ports

def dns_lookup(domain):
    records = {}
    for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except:
            records[record_type] = []
    return records

def whois_lookup(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        return f"Error: {str(e)}"

def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return response
    except:
        return None

def reverse_ip_lookup(ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}").text
        return response.split('\n') if "No DNS" not in response else []
    except:
        return []

def get_ssl_info(target):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return cert
    except:
        return None

def subdomain_enum(domain, wordlist):
    subdomains = []
    with open(wordlist, 'r') as f:
        for sub in f.readlines():
            sub = sub.strip()
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
            except:
                pass
    return subdomains

def save_results(target, data):
    with open(f"{target}_scan_results.json", "w") as f:
        json.dump(data, f, indent=4)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Advanced Network Recon Tool")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-p", "--ports", help="Ports to scan (default: 1-1000)", default="1-1000")
    parser.add_argument("--dns", help="Perform DNS lookup", action="store_true")
    parser.add_argument("--whois", help="Perform WHOIS lookup", action="store_true")
    parser.add_argument("--geoip", help="Perform GeoIP lookup", action="store_true")
    parser.add_argument("--reverse-ip", help="Perform reverse IP lookup", action="store_true")
    parser.add_argument("--ssl", help="Retrieve SSL certificate details", action="store_true")
    parser.add_argument("--subdomains", help="Subdomain enumeration (provide wordlist)")
    args = parser.parse_args()
    
    target = args.target
    ports = range(*map(int, args.ports.split("-"))) if "-" in args.ports else list(map(int, args.ports.split(",")))
    
    print(f"{Fore.GREEN}[+] Scanning {target} at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    results = {"target": target, "scan_time": time.strftime('%Y-%m-%d %H:%M:%S')}
    
    print(f"{Fore.YELLOW}[*] Scanning ports...")
    open_ports = port_scan(target, ports)
    results["open_ports"] = open_ports
    for port, service in open_ports:
        print(f"  {Fore.CYAN}Port {port}/tcp: {service}")
    
    if args.dns:
        print(f"{Fore.YELLOW}[*] Performing DNS lookup...")
        results["dns_records"] = dns_lookup(target)
        print(results["dns_records"])
    
    if args.whois:
        print(f"{Fore.YELLOW}[*] Performing WHOIS lookup...")
        results["whois_info"] = str(whois_lookup(target))
        print(results["whois_info"])
    
    if args.geoip:
        print(f"{Fore.YELLOW}[*] Performing GeoIP lookup...")
        results["geoip_info"] = geoip_lookup(target)
        print(results["geoip_info"])
    
    if args.reverse_ip:
        print(f"{Fore.YELLOW}[*] Performing Reverse IP lookup...")
        results["reverse_ip_domains"] = reverse_ip_lookup(target)
        print(results["reverse_ip_domains"])
    
    if args.ssl:
        print(f"{Fore.YELLOW}[*] Retrieving SSL certificate info...")
        results["ssl_info"] = get_ssl_info(target)
        print(results["ssl_info"])
    
    if args.subdomains:
        print(f"{Fore.YELLOW}[*] Enumerating subdomains using {args.subdomains}...")
        results["subdomains"] = subdomain_enum(target, args.subdomains)
        print(results["subdomains"])
    
    save_results(target, results)
    print(f"{Fore.GREEN}[+] Scan completed. Results saved to {target}_scan_results.json")

if __name__ == "__main__":
    main()
