Work in Progress Jarm Tool. Remove Return Statment in ./src/Jarm_Threaded.py to see output or read SQLite file.


       __      _                __
      / /_  __(_)______  __    / /___ __________ ___  _____
 __  / / / / / / ___/ / / /_  / / __ `/ ___/ __ `__ \/ ___/
/ /_/ / /_/ / / /__/ /_/ / /_/ / /_/ / /  / / / / / (__  )
\____/\__,_/_/\___/\__, /\____/\__,_/_/  /_/ /_/ /_/____/
                  /____/
By: N0tHarbor

usage: Juice.py [-P] [-p] [-h] [Enum,DB,Alrt] ...

positional arguments:
  {Enum,DB,Alert}
    Enum                Enumerate Target Company, User Supplied Targets, or the Internet for JARM fingerprints
    DB                  Pull Data from Database
    Alert               Configure Method to Alert on JuicyJarms Findings

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --Port PORT  Enter a port or list of comma-separated ports, Default is 443 HTTPs
  -P PROXY, --Proxy PROXY
                        To use a SOCKS5 proxy, provide address:port.
