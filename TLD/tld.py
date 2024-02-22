# SIEM - Splunk : Récupération des dépôts récents de noms de domaine malveillants pour anticiper une campagne de phishing.

# Source : https://red.flag.domains/

import requests
import xml.etree.ElementTree as ET
import json

def fetch_domains(url):
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            
            malicious_domains = []
            
            for item in root.findall('.//item'):

                pub_date = item.find('pubDate').text
                
                description = item.find('description').text
                
                malicious_domains.append({'pubDate': pub_date, 'description': description})
            
            # Liste des domaines malveillants au format JSON pour Splunk
            return json.dumps(malicious_domains)
        else:
            print(f"Erreur lors de la requête : {response.status_code}")
            return None
    except Exception as e:
        print(f"Une erreur s'est produite : {str(e)}")
        return None

url = "https://red.flag.domains/index.xml"

malicious_domains_json = fetch_domains(url)

if malicious_domains_json:
    print("Liste des noms de domaine malveillants récupérés avec succès :")
    print(malicious_domains_json)
else:
    print("Impossible de récupérer les noms de domaine.")
