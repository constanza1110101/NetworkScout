#!/usr/bin/env python3
import argparse
import socket
import ipaddress
import threading
import time
import nmap
import whois
import dns.resolver
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════╗")
    print(f"║ NetworkScout - Network Reconnaissance Tool ║")
    print(f"╚═══════════════════════════════════════════╝{Style.RESET_ALL}")

def port_scan(target, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
            open_ports.append((port, service))
        sock.close()
    return open_ports

def dns_lookup(domain):
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(answer) for answer in answers]
        except Exception:
            results[record_type] = []
    
    return results

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    banner()
    parser = argparse.ArgumentParser(description="Network reconnaissance tool")
    parser.add_argument("target", help="Target IP address or domain")
    parser.add_argument("-p", "--ports", help="Ports to scan (default: top 1000)", default="1-1000")
    parser.add_argument("--dns", help="Perform DNS lookup", action="store_true")
    parser.add_argument("--whois", help="Perform WHOIS lookup", action="store_true")
    parser.add_argument("--headers", help="Retrieve HTTP headers", action="store_true")
    
    args = parser.parse_args()
    target = args.target
    
    # Parse port range
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    else:
        ports = list(map(int, args.ports.split(",")))
    
    print(f"{Fore.GREEN}[+] Target: {target}")
    print(f"{Fore.GREEN}[+] Starting scan at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Port scanning
    print(f"\n{Fore.YELLOW}[*] Scanning ports...")
    open_ports = port_scan(target, ports)
    
    if open_ports:
        print(f"{Fore.GREEN}[+] Open ports:")
        for port, service in open_ports:
            print(f"  {Fore.CYAN}Port {port}/tcp: {service}")
    else:
        print(f"{Fore.RED}[-] No open ports found")
    
    # DNS lookup
    if args.dns:
        try:
            print(f"\n{Fore.YELLOW}[*] Performing DNS lookup...")
            dns_results = dns_lookup(target)
            
            for record_type, records in dns_results.items():
                if records:
                    print(f"{Fore.GREEN}[+] {record_type} Records:")
                    for record in records:
                        print(f"  {Fore.CYAN}{record}")
        except Exception as e:
            print(f"{Fore.RED}[-] DNS lookup failed: {str(e)}")
    
    # WHOIS lookup
    if args.whois:
        try:
            print(f"\n{Fore.YELLOW}[*] Performing WHOIS lookup...")
            whois_data = whois_lookup(target)
            
            if isinstance(whois_data, dict):
                for key, value in whois_data.items():
                    if value and key not in ["raw"]:
                        print(f"{Fore.GREEN}[+] {key}: {Fore.CYAN}{value}")
            else:
                print(f"{Fore.RED}[-] {whois_data}")
        except Exception as e:
            print(f"{Fore.RED}[-] WHOIS lookup failed: {str(e)}")
    
    # HTTP headers
    if args.headers:
        try:
            print(f"\n{Fore.YELLOW}[*] Retrieving HTTP headers...")
            response = requests.get(f"http://{target}", timeout=5)
            print(f"{Fore.GREEN}[+] Status code: {response.status_code}")
            print(f"{Fore.GREEN}[+] Headers:")
            for header, value in response.headers.items():
                print(f"  {Fore.CYAN}{header}: {value}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to retrieve HTTP headers: {str(e)}")
    
    print(f"\n{Fore.GREEN}[+] Scan completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
