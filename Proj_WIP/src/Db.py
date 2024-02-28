#! /usr/bin/python3 

import sqlite3 
from contextlib import closing
from dbutils.pooled_db import PooledDB
import os

# Create a function to create a connection pool
def create_connection_pool():
	return PooledDB(sqlite3, maxconnections=75, check_same_thread=False, database='./db_data/Jarm_Db.sqlite')

# Initialize the connection pool
connection_pool = create_connection_pool()



class DB:

	# Default Constructor:
	def __init__(self):
		self.__Conn = connection_pool.connection()

		# Create Tables if They do not Exist. 
		try:
			with closing(self.__Conn.cursor()) as Connection:

				# Write Jarm Table:
				Connection.execute("""
					CREATE TABLE IF NOT EXISTS Jarm (
						no integer primary key, 
						Scan_Date TEXT,
						Ip TEXT,
						Domain TEXT,
						Port TEXT,
						Domain_Jarm TEXT, 
						IP_Jarm TEXT,
						Description TEXT
						)""")

				self.__Conn.commit()

		except sqlite3.Error as Err: # Test the Write Error while multiprocessing
			print("[!] Initalization Failire for DB Obj, Exiting... \n", Err)
			exit()



	# Write to the Database: 
	def Write_New(self, Data): # Data = (Date, Ip, Domain, Port, Domain_Jarm, Ip_Jarm, Desc)

		try:
			with closing(self.__Conn.cursor()) as Connection:

				Connection.execute("""INSERT INTO Jarm (Scan_Date, Ip, Domain, Port, Domain_Jarm, Ip_Jarm, Description) 
					VALUES (?, ?, ?, ?, ?, ?, ?)""", Data)

				self.__Conn.commit()

		except sqlite3.Error as Err: # Test the Write Error while multiprocessing
			print("[!] Write Error in DB.Write_New() Function, Exiting... \n", Err)
			exit()

	# Update Existing DB Entries:
	def Update(self, Data, Search): 
		# Data = (Date, Ip, Domain, Port, Domain_Jarm, Ip_Jarm, Desc)
		# Search = (Ip, Domain, Port)

		try:
			with closing(self.__Conn.cursor()) as Connection:

				# Check for Failed Scans:
				Connection.execute("""SELECT EXISTS (SELECT 1 FROM Jarm WHERE IP = ? AND Domain = ? AND Port = ? AND Domain_Jarm = 'Failed')""", Search)
				Failed = Connection.fetchone()[0]

				if Failed: # No Need to Concat to a Failed Scan
					
					Connection.execute("""UPDATE Jarm SET Scan_Date = Scan_Date || ',' || ?, Ip = ?, Domain = ?, Port = ?, Domain_Jarm = ?, Ip_Jarm = ?, Description = ? 
						WHERE Ip = ? AND Domain = ? AND Port = ?""", tuple(Data + Search))

					# Update did not match the IP and Domain and Port number. So its a new entry. 
					if Connection.rowcount <= 0:
						self.Write_New(Data)
					else:
						self.__Conn.commit()

				else: # Concat to previous Successful scan
					Connection.execute("""UPDATE Jarm SET Scan_Date = Scan_Date || ',' || ?, Ip = ?, Domain = ?, Port = ?, Domain_Jarm = Domain_Jarm || ',' || ?, Ip_Jarm = Ip_Jarm || ',' || ?, Description = ? 
						WHERE Ip = ? OR Domain = ? AND Port = ?""", tuple(Data + Search))
					
					# Update did not match the IP or Domain and also have the same port number. So its a new entry. 
					if Connection.rowcount <= 0:
						self.Write_New(Data)
					else:
						self.__Conn.commit()


		except sqlite3.Error as Err: # Test the Write Error while multiprocessing
			print("[!] Write Error in DB.Update() Function, Exiting... \n", Err)
			exit()

	# Get Scan Success & Failure Count. 
	def Get_Scan_Count(self, Date):
		with closing(self.__Conn.cursor()) as Connection:
			# Get Success:
			Connection.execute("SELECT * FROM Jarm WHERE Domain_Jarm != 'Failed' AND Date = ?", Date)
			Success = len(Connection.fetchall())

			# Get Failure:
			Connection.execute("SELECT * FROM Jarm WHERE Domain_Jarm = 'Failed' AND Date = ?", Date)
			Failure = len(Connection.fetchall())

			return Success, Failure 

	def Get_DB(self):
		with closing(self.__Conn.cursor()) as Connection:
			Connection.execute("SELECT * FROM Jarm")
			return Connection.fetchall()



#1 - Get IP's into Database:
	def Write_Ip(self, Data):
		try:
			with closing(self.__Conn.cursor()) as Connection:

				Connection.execute("""INSERT INTO Jarm (Ip, Description) VALUES (?, ?)""", Data)
				self.__Conn.commit()

		except Exception as Err: # Test the Write Error while multiprocessing
			print("[!] Write Error in DB.Write_Ip() Function, Exiting... \n", Err)
			exit()

#2 - Get IP Length:
	def Get_Ip_Len(self, Data):
		with closing(self.__Conn.cursor()) as Connection:

			Connection.execute("""SELECT * FROM Jarm WHERE Description = ?""", Data)

			return len(Connection.fetchall())

#3 - Chu





