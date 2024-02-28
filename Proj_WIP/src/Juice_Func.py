#! /usr/bin/python3

import requests
import re
import ipaddress
from tqdm import tqdm # Load Bar
import concurrent.futures
import threading
import time

from Db import *

db_write_lock = threading.Lock()

def Write_2_DB(Ip, Term):
    try:
        with db_write_lock:
            DB().Write_Ip((str(Ip), Term))
    except Exception as e:
        print(e) 

 
# Function to search CIDR blocks
def Search_CIDR_Block(term):

    try:
        # URL Params:
        url = f"https://bgp.he.net/search?search%5Bsearch%5D={term}&commit=Search"
        headers = {'User-Agent': 'Mozilla/5.0'}  # Set a User-Agent header
        start = time.perf_counter()
        Total_Ips = 0

        # Send GET request:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            # Use regular expressions to extract IPv4 and IPv6 addresses with CIDR blocks
            ip_cidr_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b') # |\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/\d{1,3}\b

            # Find IP addresses with CIDR blocks in the response content
            ip_cidr_matches = ip_cidr_pattern.findall(response.text)

            # Eliminate Duplicates pulled from HREF's
            Unique_cidr_matches = list(set(ip_cidr_matches))

        if Unique_cidr_matches:

            for Cidr_Block in Unique_cidr_matches:
                Network = ipaddress.ip_network(Cidr_Block)

                with tqdm(total=Network.num_addresses, desc=f"[$] Converting {term}'s CIDR Block {Cidr_Block} to Ip's:") as Pbar:

                    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as Exec:

                        
                        Future = [Exec.submit(Write_2_DB, Ip, term) for Ip in Network]
                            

                        # Wait for all threads to complete before continuing
                        for x in concurrent.futures.as_completed(Future):
                            Total_Ips+=1
                            Pbar.update(1)


            finish = time.perf_counter()
            print("\n[!] INFO [!]")
            print(f"[!] Write {term} Ips to DB Time: {round(finish - start, 3)} Seconds")
            print(f"[!] Total IPs {Total_Ips}")
          
        else:
            print("No CIDR blocks found.")
            return []

    except requests.RequestException as e:
        print(f"Request Exception: {e}")
        return []



def print_ipv4_range():

	Start = '1.1.1.1'
	End = '255.255.255.255'
    # Split the start and end IP addresses into their components
	start_parts = list(map(int, Start.split('.')))
	end_parts = list(map(int, End.split('.')))

    # Loop through the IP address range and print each address
	for a in range(start_parts[0], end_parts[0] + 1):
		if a == "10" or a == "127":
			continue

		for b in range(start_parts[1], end_parts[1] + 1):
			if (a == "172" and b == "16") or (a == "192" and b == "168") or (a == "169" and b == "254"):
				continue

			for c in range(start_parts[2], end_parts[2] + 1):

				for d in range(start_parts[3], end_parts[3]):

					print(f"{a}.{b}.{c}.{d}")
