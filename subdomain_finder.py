#!/usr/bin/env python3

import asyncio
import aiohttp
import aiodns
import dns.resolver
import requests
import json
import argparse
import sys
import os
import re
import time
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style, init
import pyfiglet
import whois
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging
from pathlib import Path
from dotenv import load_dotenv
from censys.search import CensysCertificates
from shodan import Shodan

# Initialize colorama
init()

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    filename='subdomain_finder.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SubdomainFinder:
    def __init__(self):
        self.subdomains = set()
        self.active_subdomains = set()
        self.resolved_ips = {}
        self.api_keys = {
            'censys_api_id': os.getenv('CENSYS_API_ID'),
            'censys_api_secret': os.getenv('CENSYS_API_SECRET'),
            'shodan_api_key': os.getenv('SHODAN_API_KEY')
        }
        
        # Common subdomain wordlist
        self.wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'dns', 'dns1', 'dns2', 'ns', 'dev', 'staging', 'test', 'portal', 'admin',
            'secure', 'vpn', 'mx', 'email', 'api', 'server', 'cloud', 'blog', 'shop',
            'app', 'support', 'web', 'remote', 'docs', 'git', 'gitlab', 'jenkins'
        ]

    def display_banner(self):
        """Display tool banner"""
        banner = pyfiglet.figlet_format("Subdomain Finder")
        print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Reconnaissance Tool for Subdomain Discovery{Style.RESET_ALL}\n")

    async def find_subdomains(self, domain, methods=None):
        """Main method to find subdomains using multiple techniques"""
        if methods is None:
            methods = ['dns', 'cert', 'web', 'bruteforce']

        try:
            tasks = []
            
            if 'dns' in methods:
                tasks.append(self.dns_enumeration(domain))
            if 'cert' in methods:
                tasks.append(self.certificate_search(domain))
            if 'web' in methods:
                tasks.append(self.web_scraping(domain))
            if 'bruteforce' in methods:
                tasks.append(self.bruteforce_subdomains(domain))

            print(f"\n{Fore.BLUE}[*] Starting subdomain enumeration for {domain}{Style.RESET_ALL}")
            await asyncio.gather(*tasks)

            # Verify discovered subdomains
            await self.verify_subdomains()
            
            # Save results
            self.save_results(domain)
            
            # Display results
            self.display_results()

        except Exception as e:
            logging.error(f"Error in subdomain enumeration: {str(e)}")
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    async def dns_enumeration(self, domain):
        """Perform DNS-based enumeration"""
        print(f"\n{Fore.GREEN}[+] Performing DNS enumeration{Style.RESET_ALL}")
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2

            # Common DNS record types to query
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for rdata in answers:
                        if record_type in ['NS', 'MX', 'CNAME']:
                            subdomain = str(rdata.target).rstrip('.')
                            if domain in subdomain:
                                self.subdomains.add(subdomain)
                except Exception:
                    continue

        except Exception as e:
            logging.error(f"Error in DNS enumeration: {str(e)}")

    async def certificate_search(self, domain):
        """Search for subdomains in SSL/TLS certificates"""
        print(f"\n{Fore.GREEN}[+] Searching SSL/TLS certificates{Style.RESET_ALL}")
        
        try:
            # Censys certificate search
            if self.api_keys['censys_api_id'] and self.api_keys['censys_api_secret']:
                censys = CensysCertificates(
                    api_id=self.api_keys['censys_api_id'],
                    api_secret=self.api_keys['censys_api_secret']
                )
                
                query = f"parsed.names: {domain}"
                certificates = censys.search(query, fields=['parsed.names'])
                
                for cert in certificates:
                    for name in cert['parsed.names']:
                        if domain in name:
                            self.subdomains.add(name)

            # Certificate Transparency logs
            ct_logs = [
                f"https://crt.sh/?q=%.{domain}&output=json",
                f"https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            ]

            async with aiohttp.ClientSession() as session:
                for url in ct_logs:
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                data = await response.json()
                                if isinstance(data, list):
                                    for item in data:
                                        if 'name_value' in item:
                                            self.subdomains.add(item['name_value'])
                                        elif 'dns_names' in item:
                                            self.subdomains.update(item['dns_names'])
                    except Exception:
                        continue

        except Exception as e:
            logging.error(f"Error in certificate search: {str(e)}")

    async def web_scraping(self, domain):
        """Find subdomains through web scraping"""
        print(f"\n{Fore.GREEN}[+] Performing web scraping{Style.RESET_ALL}")
        
        search_engines = [
            f"https://www.google.com/search?q=site:{domain}",
            f"https://www.bing.com/search?q=site:{domain}",
            f"https://search.yahoo.com/search?p=site:{domain}"
        ]

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                for url in search_engines:
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                html = await response.text()
                                soup = BeautifulSoup(html, 'html.parser')
                                
                                # Extract URLs from search results
                                for link in soup.find_all('a'):
                                    href = link.get('href')
                                    if href:
                                        subdomain_match = re.search(f'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]+)?[.])?{domain}', href)
                                        if subdomain_match:
                                            self.subdomains.add(subdomain_match.group(0))
                    except Exception:
                        continue

        except Exception as e:
            logging.error(f"Error in web scraping: {str(e)}")

    async def bruteforce_subdomains(self, domain):
        """Bruteforce subdomains using wordlist"""
        print(f"\n{Fore.GREEN}[+] Starting subdomain bruteforce{Style.RESET_ALL}")
        
        resolver = aiodns.DNSResolver()
        tasks = []

        for word in self.wordlist:
            subdomain = f"{word}.{domain}"
            tasks.append(self.resolve_domain(resolver, subdomain))

        await asyncio.gather(*tasks)

    async def resolve_domain(self, resolver, domain):
        """Resolve a domain and check if it exists"""
        try:
            result = await resolver.query(domain, 'A')
            if result:
                self.subdomains.add(domain)
                self.resolved_ips[domain] = [r.host for r in result]
        except Exception:
            pass

    async def verify_subdomains(self):
        """Verify discovered subdomains are active"""
        print(f"\n{Fore.GREEN}[+] Verifying discovered subdomains{Style.RESET_ALL}")
        
        resolver = aiodns.DNSResolver()
        tasks = []

        for subdomain in self.subdomains:
            tasks.append(self.verify_subdomain(resolver, subdomain))

        await asyncio.gather(*tasks)

    async def verify_subdomain(self, resolver, subdomain):
        """Verify a single subdomain"""
        try:
            result = await resolver.query(subdomain, 'A')
            if result:
                self.active_subdomains.add(subdomain)
                self.resolved_ips[subdomain] = [r.host for r in result]
        except Exception:
            pass

    def save_results(self, domain):
        """Save results to JSON file"""
        output_dir = Path('results')
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"subdomains_{domain}_{timestamp}.json"
        
        results = {
            'domain': domain,
            'timestamp': timestamp,
            'total_subdomains': len(self.subdomains),
            'active_subdomains': len(self.active_subdomains),
            'subdomains': list(self.subdomains),
            'active_subdomains_list': list(self.active_subdomains),
            'resolved_ips': self.resolved_ips
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n{Fore.GREEN}[+] Results saved to: {output_file}{Style.RESET_ALL}")

    def display_results(self):
        """Display enumeration results"""
        print("\n" + "="*50)
        print(f"{Fore.CYAN}Subdomain Enumeration Results:{Style.RESET_ALL}")
        print("="*50)
        
        print(f"\n{Fore.YELLOW}Total Subdomains Found: {len(self.subdomains)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Active Subdomains: {len(self.active_subdomains)}{Style.RESET_ALL}\n")
        
        if self.active_subdomains:
            print(f"{Fore.CYAN}Active Subdomains:{Style.RESET_ALL}")
            for subdomain in sorted(self.active_subdomains):
                ips = self.resolved_ips.get(subdomain, [])
                ip_str = f" ({', '.join(ips)})" if ips else ""
                print(f"{Fore.GREEN}➜ {subdomain}{ip_str}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Subdomain Finder - A reconnaissance tool for subdomain discovery")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to enumerate")
    parser.add_argument("-m", "--methods", nargs="+", choices=['dns', 'cert', 'web', 'bruteforce'],
                      default=['dns', 'cert', 'web', 'bruteforce'],
                      help="Enumeration methods to use")
    parser.add_argument("-o", "--output", help="Output file path")
    
    args = parser.parse_args()

    finder = SubdomainFinder()
    finder.display_banner()

    try:
        asyncio.run(finder.find_subdomains(args.domain, args.methods))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Enumeration interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error in main execution: {str(e)}")

if __name__ == "__main__":
    main() 