#!/usr/bin/python3
import argparse
import whois
from crtsh import crtshAPI
import json
from shodan import Shodan
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI

#TO DO: implement shodan and censys API queries
def handle_args(): 
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Domain to perform reconnaissance on")
    parser.add_argument("--shodan", help="Shodan API key") 
    parser.add_argument("--censys", help="Censys API key")
    parser.add_argument("--output", help="Location to save result output to")
    args = parser.parse_args()
    return args

# To do: write output to individual files
def write_to_file(query):
    print("\n[*] Writing results for %s query" % query)

# To do: concat files to one single output html
def export_results(output_path):
    print("\n[*] Exporting results to report file at %s" % output_path)

# To do: implement censys lookup using API key
def censys_lookup(domain, key):
    pass

# To do: implement shodan lookup using API key
def shodan_lookup(domain, key):
    api = shodan(key)

# Attempt zone transfer
def dns_lookup(domain):
    print("\n[*] Performing DNS lookup\n")
    result = DNSDumpsterAPI().search(domain)
    for record in result['dns_records']:
        print("\n"+str(record).upper())
        for r in result['dns_records'][record]:
            if 'domain' in r and type(r) is dict:
                print("[+] %s : %s" % (r['domain'], r['ip']))
            # Account for txt records
            else:
                print(r) 
    return result

def crtsh_lookup(domain):
    domains = []
    print("\n[*] Performing crtsh lookup\n") 
    result = crtshAPI().search(domain)
    for record in result:
        for r in record:
            # Account for newline characters in some name records
            if '\n' in r['name_value']:
                domain_names = r['name_value'].split("\n")
                for d in domain_names:
                    domains.append(d.strip())
            else:
                domains.append(r['name_value'].strip())
    domains = list(dict.fromkeys(domains))
    for d in domains:
        print("[+] %s" % d)
    return result, domains

def whois_lookup(domain):
    print("\n[*] Performing whois lookup\n")
    result = whois.whois(domain)
    for record in result:
        print('\n' + record.replace("_", " ").upper())
        if type(result[record]) == list:
            for r in result[record]:
                print(r)
        else:
            print(result[record])
    
    return result

def main():
    args = handle_args()
    domain = args.domain
    shodan_api = args.shodan
    censys_api = args.censys
    output_path = args.output
    
    discovered_domains = []

    print("\n[*] Performing OSINT on domain %s" % args.domain)
    #whois lookup
    whois_result = whois_lookup(domain)
    #crtsh lookup
    crtsh_result, crtsh_domains = crtsh_lookup(domain)
    #dns lookup
    dns_result = dns_lookup(domain)
    # shodan.io lookup
    # shodan_result = shodan_lookup(domain, key)

    # censys lookup
    # censys_result = censys_lookup(domain, key) 
    

if __name__ == "__main__":
        main()
