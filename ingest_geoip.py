import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEOIP_API_KEY")

url = "https://api.ipgeolocation.io/v2/ipgeo"
params = {
    "apiKey": API_KEY,
    "ip": "8.8.8.8"
}

response = requests.get(url, params=params, timeout=30)
response.raise_for_status()

data = response.json()

with open("geoip_raw.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("Saved response to geoip_raw.json")