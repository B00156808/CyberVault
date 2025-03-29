import requests
import json

def queryApi():
    response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft")
    print(response.text)