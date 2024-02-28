#! /usr/bin/python3

import sys # For sys.path(src/db_data)
import platform # For determining Win/OSX/Lin
from tqdm import tqdm # Load Bar
import time # For Scan Times
import importlib # For requirments.txt
import concurrent.futures # For Multiprocessing
import multiprocessing 
from functools import partial
import socket # For Doamin Name Search
from itertools import zip_longest # For Multi Var Forloops
from datetime import date # For Date and Time
import pandas as pd


# Platform Check for Portability:
os_type = platform.system()

# Include Src & Db_Data Folder 4 Custom Scripts:
if "Lin" in os_type or "Dar" in os_type:
	sys.path.insert(0, './src')
	sys.path.insert(0, './db_data')

else:
	sys.path.insert(0, '.\\src')
	sys.path.insert(0, '.\\db_data')

# Custom Script Imports:
from Jarm_Threaded import *
from Db import *
from Alert import *
from Juice_Func import *

def MultiProc_Thread_Jarm(Date, Ip, Ports, Proxy, Pbar, Desc, DB_Obj):


	# Var Dec:
	Jarms_Domain = []
	Jarms_Ip = []

	# Get Doamin Name:
	try:
		Domains = socket.gethostbyaddr(Ip)

		for Port in Ports:
			# Jarm Fingerprint! 
			Jarms_Domain.append(jarm(Domains[0], Port, Proxy))
			Jarms_Ip.append(jarm(Ip, Port, Proxy))



		# Write to DB:
		for Port, Jarm_Domain, Jarm_Ip in zip_longest(Ports, Jarms_Domain, Jarms_Ip, fillvalue="n/a"):

			# Failed on all ports write failure	
			if Jarm_Domain == "00000000000000000000000000000000000000000000000000000000000000" or Jarm_Ip == "00000000000000000000000000000000000000000000000000000000000000" and Port == Ports[len(Ports)-1]: 
				Data = (Date, Ip, Domains[0], Port, "Failed", "Failed", Desc)
				Search = (Ip, Domains[0], Port)
				DB_Obj.Update(Data, Search)
				Pbar.update(1)

			# Check For Time Outs:
			elif Jarm_Domain == "00000000000000000000000000000000000000000000000000000000000000" or Jarm_Ip == "00000000000000000000000000000000000000000000000000000000000000":
				Pbar.update(1)
				continue # Time Out, or Failed Negotaion, No Need to Write

			else: # Write to DB:
				Data = (Date, Ip, Domains[0], Port, Ip_Jarm, Ip_Jarm, Desc)
				Search = (Ip, Domains[0], Port)
				DB_Obj.Update(Data, Search)
				Pbar.update(1)


	# Domain Not Found:
	except socket.herror:
				
		for Port in Ports:
			# Jarm Fingerprint! 
			Jarms_Ip.append(jarm(Ip, Port, Proxy))

		# Write to DB:
		for Port, Jarm_Ip in zip_longest(Ports, Jarms_Ip, fillvalue="n/a"):

			# Check For Time Outs:
			if Jarm_Ip == "00000000000000000000000000000000000000000000000000000000000000" and Port != Ports[len(Ports)-1]:
				continue # Time Out, or SSL Failed Negotaion, No Need to Write

			# Failed on all ports write failure	
			elif Jarm_Ip == "00000000000000000000000000000000000000000000000000000000000000" and Port == Ports[len(Ports)-1]:
				Data = (Date, Ip, "n/a", Port, "Failed", "Failed", Desc)
				Search = (Ip, "n/a", Port)
				DB_Obj.Update(Data, Search)
				Pbar.update(1)

			else:
				Data = (Date, Ip, "n/a", Port, Ip_Jarm, Ip_Jarm, Desc)
				Search = (Ip, "n/a", Port)
				DB_Obj.Update(Data, Search)
				Pbar.update(1)

def main():
	# Initialize Command Variables: 
	Ports = args.Port
	Proxy = args.Proxy
	Date = date.today()
	

	# Set Default Port to 443:
	if Ports is None:
		Ports = [443]
	else:
		# Turn Ports Into Array
		Ports = Ports.replace(" ", "").split(",") 

	# Declare Proxy Ports: [-P]
	if not Proxy is None:
		proxyhost, proxyport = Proxy.split(':')
		proxyport = ParseNumber(proxyport)
		try:
			import socks
		except ImportError:
			print('[!] Option proxy requires PySocks: pip install PySocks')
			exit() 

	# Enumerate for JARMS
	if args.command == 'Enum':

		# Smart Mode: [-s, --smart-mode]
		if args.Smart_mode:

			# Command Line Arg Dec:
			Company = args.Company
			Company_file = args.Companies
			Target = args.Target
			Targets_file = args.Targets

			# Check for Reqired Inputs:
			if Company is None and Company_file is None and Target is None and Targets_file is None:
				Smart_mode_group.print_help()

				print("[!] Missing CMD Args [!]")
				print("[&] -c --Company [Company Name] needed or -C --Companies [File Path to Companies List] Required for Comapny IP Enumeration")
				print("[&] -t --Target [Target Domain or IP] or -T --Targets [File Path to Domains or Ips] Required for User Supplied Target Enumeration")
				exit()


			# Single Target: [-c]
			if Company: 

				# Created DB Obj:
				DB_Obj = DB()

				# Enumerate CIDR Blocks given a comapny name:
				Search_CIDR_Block(Company)

				# Pull the Len of the DB entried that conatain a comapny name:
				Target_Len = DB().Get_Ip_Len((Company,))

				print(f"[!] Count of Rows in Database {Target_Len}\n")

				exit()

				# Load Bar
				with tqdm(total=(Target_Len * len(Ports)), desc=f"[$] Enumerating {Company}...") as Pbar:

					# Split the IPs Into Chunks to Save Memory:
					for Chunk in pd.read_sql_query(f"SELECT DISTINCT Ip FROM Jarm WHERE Description = '{Company}'", DB_Obj._DB__Conn, chunksize=10000):

						with concurrent.futures.ProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as Exec:
							Proc = [Exec.submit(MultiProc_Thread_Jarm, Date, Ip, Ports, Proxy, Pbar, Company, DB_Obj) for Ip in Chunk["Ip"]]

							# Wait for all Multiprocesses to finish
							concurrent.futures.wait(Proc)

						# Read Chunk Column:
						# for Ip in Chunk["Ip"]:


				# Load Bar:
				
				#	Proc = []

				#	for Ip in Ips:
				#		MultiProc_Thread_Jarm(Date, Ip, Ports, Proxy, Pbar, Desc, DB())

				# print(DB().Get_DB())
    					

			# Single user Suplied Target: [-t]
			if Target:
				for Port in Ports:
					jarm(Target, int(Port), Proxy)



			# User Suppiled Target File: [-T]
			if Targets_file:
				# Error Handle:
				try:

					# Get Length of File
					with open(Targets_file, "r") as File:
						Iterate = sum(1 for line in File) * len(Ports)

					# Get Jarms
					with open(Targets_file, "r") as File:

						# Load Bar: 
						with tqdm(total=Iterate, desc="Scanning Targets") as Pbar:

							# Threaded For Loop:
							for Host in File:
								for Port in Ports:
									jarm(Host, int(Port), Proxy)
									Pbar.update(1)
								

				# Handel File Not Found Error:
				except FileNotFoundError:
					print("[!] File Not Found... [!]")
					exit()

				# Handel all other errors:
				except Exception as e:
					print(e)


			# Multiple Targets: [-C]
			if Company_file: 
				pass


		# Verbose Mode: --verbose-mode:
		elif args.Verbose_Mode:
			pass


			
		# None Selected:
		else:
			print("[!] %(prog)s [-V] [-P] [-h] Enum -[s/v] or --[smart-mode/verbose-mode] required [!]")
			exit()
    
    # Database Output Commands: 
	elif args.command == 'DB':
		pass # May want to make it terminal interacive like a real DB!?

    # Config for alert methods 
	elif args.command == 'Alert':
		pass
	

if __name__ == '__main__':

	##### HEADER #####
	print(f'''
       __      _                __                         
      / /_  __(_)______  __    / /___ __________ ___  _____
 __  / / / / / / ___/ / / /_  / / __ `/ ___/ __ `__ \/ ___/
/ /_/ / /_/ / / /__/ /_/ / /_/ / /_/ / /  / / / / / (__  ) 
\____/\__,_/_/\___/\__, /\____/\__,_/_/  /_/ /_/ /_/____/  
                  /____/                                   
By: N0tHarbor
	''')

	##### Check Python3 Requirements #####
	if "Lin" in os_type or "Dar" in os_type:
		with open("./requirements.txt", 'r') as file:
			required_packages = [line.strip() for line in file]

			for package in required_packages:
				if importlib.util.find_spec(package) is None:
					print(f"[!] Package; {package} is not installed, please run 'python3 -m pip install {package} []'")
					exit()
	else:
		with open("./requirements.txt", 'r') as file:
			required_packages = [line.strip() for line in file]

			for package in required_packages:
				if importlib.util.find_spec(package) is None:
					print(f"[!] Package; {package} is not installed, please run 'python3 -m pip install {package} []'")
					exit()


	##### ARGUMENTS DEFINITION #####
	parser = argparse.ArgumentParser(usage='%(prog)s [-P] [-p] [-h] [Enum,DB,Alrt] ...')

	# Optional Options:
	parser.add_argument("-p", "--Port", help="Enter a port or list of comma-separated ports, Default is 443 HTTPs", type=str, required=False)
	parser.add_argument("-P", "--Proxy", help="To use a SOCKS5 proxy, provide address:port.", type=str, required=False)

	# Sub Commands:
	subparser = parser.add_subparsers(dest='command', required=True)

	# Enum Option:
	Enum_Parse = subparser.add_parser('Enum', help="Enumerate Target Company, User Supplied Targets, or the Internet for JARM fingerprints", usage="%(prog)s [-s, --smart-mode] or [-v, --verbose-mode] ")
	Enum_group = Enum_Parse.add_mutually_exclusive_group(required=True)
	Enum_group.add_argument('-s', '--Smart-mode', help="Enable smart mode, takes domain name, pulls ASN(s) to get IP address Space, then scans Space for Jarms", action='store_true')
	Enum_group.add_argument('-v', '--Verbose-mode', help="Enable verbose mode, Scans IPv4, IPv6, or Both for JARMS.", action='store_true')

	# Enum Smart_Mode_Options:
	Smart_mode_group = Enum_Parse.add_argument_group('Smart Mode Options')
	Smart_mode_group.add_argument('-c', '--Company', help="Specify a company name for smart-mode to enumerate", type=str)
	Smart_mode_group.add_argument('-C', '--Companies', help="Specify a file containing a list of target comapnies for smart-mode to enumerate", type=str)
	Smart_mode_group.add_argument('-t', '--Target', help="Enter a Target to Fingerprint", required=False, type=str)
	Smart_mode_group.add_argument('-T', '--Targets', help="Enter a file path containing a list of Target to Fingerprint", required=False, type=str)

	# Enum Verbose_Mode_Options:
	Verbose_mode_group = Enum_Parse.add_argument_group('Verbose Mode Options')
	Verbose_mode_group.add_argument("-i", "--Ip", type=str, help="", choices=['Ipv4', 'Ipv6', 'All'])

	# Database Options:
	Db_Parse = subparser.add_parser('DB', help='Pull Data from Database')

	# Notification Options
	Notify = subparser.add_parser('Alert', help='Configure Method to Alert on JuicyJarms Findings')

	args = parser.parse_args()
	
	main() # Main Function Call. 
