import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSE_API_KEY")

url = "https://api.abuseipdb.com/api/v2/blacklist"
headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}

response = requests.get(url, headers=headers)
data = response.json()

with open("abuseipdb_raw.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print("Saved response to abuseipdb_raw.json")