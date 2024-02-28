

def jarm(destination_host, destination_port, Proxy):

    # Client send to server
    # Server Responds
    # Client ack and data transmition 

    

    # 10 Hello Packets # 
    # Array format = [destination_host,destination_port,version,cipher_list,cipher_order,GREASE,RARE_APLN,1.3_SUPPORT,extension_orders]
    tls1_2_forward = [destination_host, destination_port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"]
    tls1_2_reverse = [destination_host, destination_port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"]
    tls1_2_top_half = [destination_host, destination_port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    tls1_2_bottom_half = [destination_host, destination_port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"]
    tls1_2_middle_out = [destination_host, destination_port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"]
    tls1_1_middle_out = [destination_host, destination_port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"]
    tls1_3_forward = [destination_host, destination_port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    tls1_3_reverse = [destination_host, destination_port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    tls1_3_invalid = [destination_host, destination_port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"]
    tls1_3_middle_out = [destination_host, destination_port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"]
    #Possible versions: SSLv3, TLS_1, TLS_1.1, TLS_1.2, TLS_1.3
    #Possible cipher lists: ALL, NO1.3
    #GREASE: either NO_GREASE or GREASE
    #APLN: either APLN or RARE_APLN
    #Supported Verisons extension: 1.2_SUPPPORT, NO_SUPPORT, or 1.3_SUPPORT
    #Possible Extension order: FORWARD, REVERSE

    
    queue = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]
    jarm = ""


    # MultiThreading Var Dec:
    

    #Assemble, send, and decipher each packet
    start = time.perf_counter()
    iterate = 0
    jarm = ""

    while iterate < len(queue):
        payload = packet_building(queue[iterate])

        print("Test")
        server_hello = send_packet(payload, destination_host, destination_port, Proxy) 

        print(server_hello)
    
        # Deal with timeout error
        if server_hello == "TIMEOUT":
            jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
            break

        ans = read_packet(server_hello, queue[iterate])
        jarm += ans
        iterate += 1
        if iterate == len(queue):
            break
        else:
            jarm += ","

    # Fuzzy hash
    result = jarm_hash(jarm)  
        
    finish = time.perf_counter()

    # print("Pre Hash Jarm:", jarm)
    print(f"Time: {round(finish - start, 3)} Seconds")
    print("Post Hash Jarm:", result)
    print("Destination:", destination_host)

############################################################################################

    start = time.perf_counter()
    Index = 0
    jarm = ""

    # Assemble Packet:
    Serv_Questions = [tls1_2_forward, tls1_2_reverse, tls1_2_top_half, tls1_2_bottom_half, tls1_2_middle_out, tls1_1_middle_out, tls1_3_forward, tls1_3_reverse, tls1_3_invalid, tls1_3_middle_out]

    # Send Packets: Threading
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(Serv_Questions)) as executor:
        Results = executor.map(lambda Serv_Questions: send_packet(packet_building(Serv_Questions), destination_host, destination_port, Proxy), Serv_Questions)
        # executor.map will map our threads so the results will stay in order. Jarms have to be in order.
        # Lamda is used to pass our server questions by each array.
        
        # Read Packets:
        for Server_hello in Results:
            # Deal with timeout error
            if Server_hello == "TIMEOUT":
                jarm = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||"
                break

            
            ans = read_packet(Server_hello, Serv_Questions[Index])
            jarm += ans

            if Index == len(Serv_Questions) - 1:
                break
            else:
                jarm += ","
                


    # Get Jarm Fingerprints 
    result = jarm_hash(jarm)  
        
    finish = time.perf_counter()

    # print("Pre Hash Jarm:", jarm)
   # print(f"Time: {round(finish - start, 3)} Seconds")
   # print("Post Hash Jarm:", result)
    # print("Destination:", destination_host)

############################################################################################

# Load Bar:
                with tqdm(total=(len(Ips) * len(Ports)), desc="[$] Enumerating Targets...") as Pbar:

                    with concurrent.futures.ProcessPoolExecutor(max_workers=2) as Exec:

                        # Date, Ip, Ports, Proxy, DB_Obj, Pbar, Decs

                        [Exec.submit(MultiProc_Thread_Jarm, Date, Targ, Ports, Proxy, DataBase, Pbar, Desc) for Targ in Ips] 





def Search_CIDR_Block(term):
    Ip_List = []

    try:
        # URL Params:
        url = f"https://bgp.he.net/search?search%5Bsearch%5D={term}&commit=Search"
        headers = {'User-Agent': 'Mozilla/5.0'}  # Set a User-Agent header

        # Send GET request:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:

            # Use regular expressions to extract IPv4 and IPv6 addresses with CIDR blocks
            ip_cidr_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/\d{1,3}\b')

            # Find IP addresses with CIDR blocks in the response content
            ip_cidr_matches = ip_cidr_pattern.findall(response.text)

            # Eliminate Duplicates pulled from HREF's
            Unique_cidr_matches = list(set(ip_cidr_matches))
            
            # Return List of IP's
            if Unique_cidr_matches:
                with tqdm(total=(len(Unique_cidr_matches)), desc=f"[$] Pulling CIDR Blocks From {term}") as Pbar:

                    for Cidr_Block in Unique_cidr_matches:

                        Network = ipaddress.ip_network(Cidr_Block)

                        for Ip in Network:
                            Ip_List.append(str(Ip))

                        Pbar.update(1)

                    return Ip_List

        else:
            print(f"Failed to fetch data. Status code: {response.status_code}")
            exit()

    except requests.RequestException as e:
        print(f"Request Exception: {e}")
        exit()

