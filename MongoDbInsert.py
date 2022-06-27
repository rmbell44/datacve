from pymongo import MongoClient
import pandas as pd


connection_string = "mongodb://127.0.0.1:27017/cve"
client = MongoClient(connection_string)

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