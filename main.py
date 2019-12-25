import json
import sys
import random
import numpy as np

from clientTemplate import NodeClient

# password_characters = string.ascii_letters + string.digits + string.punctuation 
# then remove all JSON troublesome characters
# ID generation command for addresses.json: [''.join(random.choice(password_characters) for i in range(20)) for i in range(0,20)]
# Solution adapted from: https://pynative.com/python-generate-random-string/

DEFAULT_NUM_CONN = 5

def main(arguments):
    with open('addresses.json', 'r') as addressFile:
        parsedJson = json.loads(addressFile.read())
    
    allClients = []
    allIDs = parsedJson.get("ids")
    allData = parsedJson.get("data")

    if len(allIDs) == len(allData):
        listLength = len(allIDs)
        for i in range(listLength):
            validConnIDs = allIDs[0:i] + allIDs[i+1:listLength]
            connIDs = []

            for j in range(DEFAULT_NUM_CONN):
                randIndex = np.random.randint(len(validConnIDs))
                connIDs.append(validConnIDs[randIndex])
                validConnIDs = allIDs[0:randIndex] + allIDs[randIndex+1:listLength]
            
            allClients.append(NodeClient(allIDs[i], allData[i], connIDs))
    else:
        print("Inequal ID and Data JSON length")
    
    return 0

if __name__ == '__main__':
    # For predictable output
    np.random.seed(0)
    main(sys.argv)