import csv

import pandas as pd
from pymongo import MongoClient

connection_string = "mongodb://127.0.0.1:27017/cve"
client = MongoClient(connection_string)
#connection string to MongoDBB

db = client.cvedata
#database to use 'cvedata'
mydb = client["cvedata"]
mycol= mydb["2018-2"]
#collection created '2018-2'


file = pd.read_csv(r"/Users/rachelbell/Desktop/2018.csv")
#reader csv file from desktop

file = file.drop(file.columns[[0, 2, 3,5,6,8,9,10,11,12,13,14]], axis=1)
#remove unwanted columns (CWE ID, # of Exploits, etc.

file.columns = ['CVE ID', 'Vulnerability Type(s)', 'Score']
#header names

file = file.sample(n=5000)
#accessing sample of 5000 entries

file.to_csv("2018_updated.csv", index=False)
#updated file name

df = pd.read_csv("2018_updated.csv")
# read updated file
data = df.to_dict(orient = "records")
#convert file
#print(data) - test

db = client.cvedata
#connect to client
# print(db) - test

db.data2018.insert_many(data)
#insert data to MongoDB

