# SIEM - Splunk : Récupération des alertes et rapport de sécurité du CERT-FR.
# Source : https://www.cert.ssi.gouv.fr

import requests
import xml.etree.ElementTree as ET
import json

def fetch_domains(url):
    try:
        response = requests.get(url)
        
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            
            cve = []
            
            for item in root.findall('.//item'):
                
                title = item.find('title').text

                pub_date = item.find('pubDate').text
                
                description = item.find('description').text
                
                link = item.find('link').text
                
                cve.append({'title': title, 'pubDate': pub_date, 'description': description, 'link': link})
            
            # Liste des alertes du CERT-FR au format JSON pour Splunk
            return json.dumps(cve)
        else:
            print(f"Erreur lors de la requête : {response.status_code}")
            return None
    except Exception as e:
        print(f"Une erreur s'est produite : {str(e)}")
        return None

url = "https://www.cert.ssi.gouv.fr/feed/"

cert_json = fetch_domains(url)

if cert_json:
    print("Liste des ALERTES du CERT-FR :")
    print(cert_json)
else:
    print("Impossible de récupérer les ALERTES du CERT-FR.")
