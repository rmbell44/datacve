from pymongo import MongoClient

connection_string = "mongodb://127.0.0.1:27017/cve"
client = MongoClient(connection_string)
#connection string to MongoDBB

db = client.cvedata
#mydb = client["cvedata"]
col = db['2018']
#database to use 'cvedata'
#mydb = client["cvedata"]

db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring Bypass
            'Vulnerability Type(s)': re.compile(r"Bypass")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Bypass
            '_id': 'Bypass Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of Bypass Entries',
            #find # of Bypass entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring XSS
            'Vulnerability Type(s)': re.compile(r"XSS")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Bypass
            '_id': 'XSS Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of XSS Entries',
            #find # of XSS entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring DoS
            'Vulnerability Type(s)': re.compile(r"DoS")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type DoS
            '_id': 'DoS Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of DoS Entries',
            #find # of DoS entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring CSRF
            'Vulnerability Type(s)': re.compile(r"CSRF")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type CSRF
            '_id': 'CSRF Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of CSRF Entries',
            #find # of CSRF entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring Sql
            'Vulnerability Type(s)': re.compile(r"Sql")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Sql
            '_id': 'Sql Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of Sql Entries',
            #find # of Sql entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring Overflow
            'Vulnerability Type(s)': re.compile(r"Overflow")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Overflow
            '_id': 'Overflow Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of Overflow Entries',
            #find # of Overflow entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring Dir. Trav.
            'Vulnerability Type(s)': re.compile(r"Dir. Trav.")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Directory Traversal
            '_id': 'Dir. Trav. Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of Dir. Trav. Entries',
            #find # of Dir. Trav entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring +Info
            'Vulnerability Type(s)': re.compile(r"Info")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type +info
            '_id': '+Info Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of +info Entries',
            #find # of +info entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring +Priv
            'Vulnerability Type(s)': re.compile(r"Priv")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type +Priv
            '_id': '+Priv Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of +Priv Entries',
            #find # of Priv entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring Exec Code
            'Vulnerability Type(s)': re.compile(r"Exec Code")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Exec Code
            '_id': 'Exec Code Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of Exec Code Entries',
            #find # of Exec Code entries
            'n': {
                '$sum': 1
            }
        }
    }
])
db.col.aggregate(
    #aggregate to create pipeline
[
    {
        '$match': {
            #find all Strings in Vulnerability Type with substring Mem. Corr.
            'Vulnerability Type(s)': re.compile(r"Mem. Corr.")
        }
    }, {
        '$group': {
            #group by score
            '_id': '$Score',
            'count': {
                '$sum': 1
                #count entries per score - to find Mode # of entries
            }
        }
    }, {
        '$sort': {
            'count': -1
            #place in descending order
        }
    }, {
        '$group': {
            #group by threat type Mem. Corr.
            '_id': 'Mem. Corr. Avg',
            'avgScore': {
                '$avg': '$Score'
                #collect avg score
            }
        }
    }, {
        '$group': {
            '_id': '# of Mem. Corr. Entries',
            #find # of Mem. Corr. entries
            'n': {
                '$sum': 1
            }
        }
    }
])
