#!/usr/bin/python3
import argparse
import whois
from crtsh import crtshAPI
import json
import shodan
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
import requests
import queue
from threading import Thread
from datetime import datetime

q = queue.Queue()

#Add time delta to check how long enumeration took

#TO DO: implement shodan and censys API queries
def handle_args(): 
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", help="Domain to perform reconnaissance on")
    parser.add_argument("--shodan", help="Shodan API key") 
    parser.add_argument("--output", help="Location to save result output to")
    parser.add_argument("--threads", help="Number of threads for subdomain bruteforcing")
    parser.add_argument("--wordlist", help="Wordlist to use for subdomain bruteforcing")
    args = parser.parse_args()
    return args

# To do: write output to individual files
def write_to_file(query):
    print("\n[*] Writing results for %s query" % query)

# To do: concat files to one single output html
def export_results(output_path):
    print("\n[*] Exporting results to report file at %s" % output_path)

def snapshot_websites(sites):
    print("\n[*] Snapshotting websites...")

def parse_subdomains(filename):
    with open(filename) as f:
        content = f.read()
        subdomains = content.splitlines()
    return subdomains

#Encounters issues when run with the requests.ConnectionError exception checking.
#Brute force common subdomains from a wordlist
def subdomain_scan(domain):
    global q
    #Construct the URL
    while True:
        try:
            #Get subdomain from queue
            subdomain = q.get(timeout=1)
            if subdomain is None:
                break
            #Construct URL
            url = f"http://{subdomain}.{domain}"
            try:
                requests.get(url)
            #except requests.ConnectionError:
            except:
                pass
            else:
                print("[+] %s" % url)
            finally:
                q.task_done()
        except queue.Empty:
            q.task_done()
            break

# To do: implement shodan lookup using API key
def shodan_lookup(domain, key):
    print('\n[*] Performing Shodan search with api key: %s' % key)
    try:
        #Setup the API
        api = shodan.Shodan(key)
        
        #Perform the search
        query = '{}'.format(domain)
        result = api.search(query)
        
        #Loop through the matches and print each IP
        for service in result['matches']:
            print('''
IP: {}
Hostnames: {} 
Organisation: {}
Ports: {}
            '''.format(service['ip_str'], service['hostnames'], service['org'], service['port']))
    except shodan.APIError as e:
        print("Error: {}".format(e))

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

#Add a try - catch around this -- something the API usage fails
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

#Add 'step complete... writing to file` at end of each stage
def main():
    start_time = datetime.now()
    global q
    args = handle_args()
    
    if args.threads:
        n_threads = int(args.threads)
    else:
        n_threads = 10

    if args.wordlist:
        wordlist = args.wordlist
    else:
        wordlist="subdomains.txt"
    
    domain = args.domain
    shodan_api = args.shodan
    output_path = args.output
    
    print("\n[*] Performing OSINT on domain %s" % args.domain)
    
    whois_result = whois_lookup(domain)
    
    crtsh_result, crtsh_domains = crtsh_lookup(domain)
    
    dns_result = dns_lookup(domain)
   
    
    subdomains = parse_subdomains(wordlist)

    for subdomain in subdomains:
        q.put(subdomain)
    
    print("\n[*] Performing subdomain brute force (%d threads)\n" % n_threads)
    #Start the threads
    for _ in range(n_threads):
        worker = Thread(target=subdomain_scan, args=(domain,))
        worker.daemon = True
        worker.start()
    
    #Hold main thread until all workers have completed.
    q.join()
    

    #shodan.io lookup
    #shodan_lookup(domain, shodan_api)
    
    #Sites grabbed from Shodan
    sites = []
    #selenium snapshotting of tcp/80, tcp/443 and tcp/8080
    #snapshot_websites(sites)
    print("\n[*] OSINT Completed in %s seconds." % str(datetime.now() - start_time))

if __name__ == "__main__":
        main()
