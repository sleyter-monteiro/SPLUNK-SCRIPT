import requests
import json

def CVE_check(requestURL):
    response = requests.get(url=requestURL)
    if response.status_code != 200:
        print("Erreur: ", response.status_code)
        exit()
    data = response.json()
    return json.dumps(data)

def get_CVE():
    requestURL = "https://cve.circl.lu/api/last"
    return CVE_check(requestURL)

def main():
    resultat = get_CVE()
    data_cve = json.loads(resultat)
    print(json.dumps(data_cve))
    
main()    