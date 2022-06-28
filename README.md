# datacve
#Data Files
Each data folder consists of a JSON File with the entire list of data stored in MongoDB after inserting through PyMongo and narrowing to 3 columns
Along with the Scores recorded in descending order by Average Score and the associated # of entries per each threat type
2018Data-2022Data each consist of entire Data JSON File (following the edits made in Python - 3 Columns)

findScores.py consist of aggregations used to find the scores and strings splitting the Vulnerability Threat to sort the data these same aggregations are used on each years worth of data to access these data points

Import CSV to MongoDB file is also included in fileImport.py 

Uploaded Orignal 2018.csv and 2018_Updated.csv is the updated csv after manipulating its data, for comparison

MORE TO COME! 🎉
