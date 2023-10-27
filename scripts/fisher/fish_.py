# probeer dns resorver te importer uit dns python lib
try:
    from ipwhois import IPWhois

except ModuleNotFoundError:# als linrary niet bestaat haal deze op met pip
    import pip
    pip.main(['install', 'ipwhois'])
    from ipwhois import IPWhois


try:# probeer dns resorver te importer uit dns python lib
    import dns.resolver

except ModuleNotFoundError:# als linrary niet bestaat h
    import pip
    pip.main(['install', 'dnspython'])
    import dns.resolver

import csv
import sys
import os


# A FANCY BANNER
banner = '''
    ___________   ________    __
    |  _______|  |  ____  |  | |
    |  |    ____    |   __|  | |
    |  |___ |  |             | |_____
    |   __| |  |  __         |  ___ |
    |  |    |  | |  | |  |   | |  | |
    |  |    |  | |  |_/  /   | |  | |   ______
    |_ |    |__| | _____/    |_|  |_|  |______|

##########################################################
|                                                        |
|   MR. Fish has super sonar powers to find all          |
|   the hidden treasures in a sea of 0's and 1's         |
|                                                        |
|                                                        |
|   This python tool is developt for reconnaissance      |
|   purposes. It can by used to find infomation as:      |
|                                                        |
| Domain    IP, GeoIp, autonomous system number & name,  |
|           Text, Name server and Mail exchange server.  |
|                                                        |
| Format$   fish_ file.txt file.csv                      |
|           file.txt = List of domains in a txt file     |
|           file.csv = name of outputfile                |
|________________________________________________________|

##############################################################
#                        DISCLAIMER:                         #
##############################################################
#                                                            #
#   This tool is developt for Internal use (COPS -THTC),     #
#   external use is prohibited.This tool is provided "as is" #
#   without warranty of any kind, either express or implied. #
#   Use at your own risk.                                    #
#                                                            #
##############################################################

'''



domeinen=[] # TABLE WITH ALL DOMAINNAMES IN fname.txt
table=[] # TABLE WITH DICTIONARYS FROM THE DNS QUERY. FORMAT: [{{},{},{}}], ALL RESULTS TOGETHER

# THIS FUNTION LOADS TE DATA OF fname.txt
def load(fname):

    with open(fname, "r") as bestand:
        
        for regel in bestand:
            domein = regel.strip()# LOAD EVERY SINGLE LINE AND REMOVE '\n
            domeinen.append(domein)

# THIS IS THE FUNCTION FOR SCANNING THE GIVVEN DOMAINS
def scan(domeinen):

    resultHost={} # RESULT IS A SET OF RESULTS FOR A SPECIFIC HOST, FORMAT exp. [{you..com:123.123.123.123},{abc..com: ..},{test..com: ..}]
    info={} # IS A DICT OF AN ANSWER TO A SPECIFIC QUERY OF A HOST

    for domein in domeinen: #FOR EVERY DOMEIN IN DOMEINEN

        try: 
            dnsRec = ["Domein", "A", "TXT", "MX", "NS"] # A LIST OF DNS QUERY FLAGS
	
            for record in dnsRec: # FOR EVERY DNS QUERY IN dnsRec
                
                if record == "Domein": 
                    info["Domein"] = domein # SAVE KEY VALUE IN INFO
                
                elif record == "A":    
                    response = dns.resolver.resolve(domein, record) # MAKE THE QUERY REQUEST
                    
                    for data in response: # FOR RAW DATA IN RESPONSE
                        info['IP (A)'] = data.to_text( )# SAVE IP IN INFO DICTIONARY
                        resultHost.update(info) # APPEND NEW KEY: VALUE IN INFO
                        table.append(dict(resultHost)) # APPEND THE NEW DICT INFO IN THE LIST OF resultHost (set of results) 

                        obj = IPWhois(data.to_text())
                        lookup = obj.lookup_whois()# MAKE A WHOIS LOOKUP

			# TAKE THE IP ADRESS AND SEARCH FOR ASN INFO WITH WHOIS
                        info["Land"] = lookup["asn_country_code"]
                        info["AS Number"] = lookup["asn"]
                        info["AS Name"] = lookup["asn_description"]

                else:
                    response = dns.resolver.resolve(domein, record)

                    for data in response:

                        if record == "TXT":
                            key = "text (TXT)"
                        elif record == "MX":
                            key = "mail server (MS)"
                        elif record == "NS":
                            key = "name server (NS)"

                        info[key]=data.to_text() # SAVE KEY VALUE IN INFO
                        resultHost.update(info) # UPDATE INFO with new information
                        table.append(dict(resultHost)) # PUT THE SET OF RESULTS FOR A SPECIFIC QUERY IN table
                
        except Exception as e:
            print(e)

    return table

# FUNCTION FOR MAKING DE CSV
def CSV(data, fname):# maakt csv bestand van resultaten
    
# CSV COLUMN HEADERS
    csvHeader = ["Domein", "IP (A)", "Land", "AS Number", "AS Name", "text (TXT)", "mail server (MS)", "name server (NS)"]
    
    with open(fname, "w") as bestand: # UPDATE SAME FILE, W PERMISSION. IF YOU WANT TO APPEND, CHANGE IN A PERMISSION
        writer = csv.DictWriter(bestand, fieldnames = csvHeader)
        writer.writeheader()
        writer.writerows(data)

print(banner)

print("fish_ file.txt file.csv\n")
print("Where are de list of domains store ?")
fnameL= input('Fish_ file.txt = ')
print("\nHow would you name the outputfile ?")
fnameO= input('Fish_ file.csv = ')

print("\n  .. searching for domains in "+fnameL+" and loading the results in "+fnameO)
load(fnameL)
scan(domeinen)
CSV(table,fnameO)
print(" ..! The scan is done, your can find the results in "+fnameO+"\n")

