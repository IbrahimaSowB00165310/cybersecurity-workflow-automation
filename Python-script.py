import requests
import csv
import time
import os
from datetime import datetime
import glob
import sys

unique_ip = set()
current_direct = os.path.dirname(os.path.abspath(__file__))

check_files = os.path.join(current_direct, "*_suspicious_IPs_login.csv") #check all files no matter the date
found = glob.glob(check_files)  #lists all matching files even previous ones

if not found:
    print("No suspicous Log file")
    sys.exit(1)

suspectfile = max(found, key=os.path.getmtime) # take the most recent one as that correspond to the maximum

VT_API_KEY = os.environ.get('VT_API_KEY')# setting the API Key as environmental variable
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

VT_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/' # VT API endpoint for file reports

with open (suspectfile, "r", encoding="utf-8") as f:
   
   log_line = csv.reader(f)
   next(log_line)
   for row in log_line: 
     if len(row) < 3:
            continue

     repip = row[2].strip()
     unique_ip.add(repip)
       
       
if not VT_API_KEY:
     APIKEY = input("Enter your API KEY : ").strip() # Ask to enter API key when not in environmental variable
     VT_API_KEY = APIKEY
if not VT_API_KEY:
    raise RuntimeError(
        "VT_API_KEY is not defined in the environment variables or API key not entered"
    )  
    

def check_ip(ip: str) -> dict: #function to request VirusTotal for checking
    url = VT_API_URL + ip

    headers = {
        "x-apikey": VT_API_KEY
    }

    r = requests.get(url, headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()

       
 #generating the filetoanalyse.csv      
with open(os.path.join(current_direct, timestamp + "_" + "filetoanalyse.csv"), "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["ip", "malicious", "suspicious", "error"])

    for ip in unique_ip:
        try:
            data = check_ip(ip)

            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats["malicious"]
            suspicious = stats["suspicious"]

            print(f"{ip} → malicious={malicious}, suspicious={suspicious}")
            writer.writerow([ip, malicious, suspicious, ""])

            time.sleep(15)  # waiting 15 secs after requet for an IP for rate limit

        except (requests.RequestException, KeyError) as e:
            print(f"[ERREUR] {ip}: {e}")
            writer.writerow([ip, "", "", str(e)])
    

