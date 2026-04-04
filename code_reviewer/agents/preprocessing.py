import os
import logging
import json
import requests
from cvss import CVSS4, CVSS3
from typing import List, Dict
from dotenv import load_dotenv
from langchain_core.documents import Document


load_dotenv()
logging.basicConfig(level=logging.INFO)

KEV_JSON_LINK = os.getenv('KEV_JSON_LINK')
CWE_JSON_FILE = os.getenv('CWE_JSON_FILE')
OSV_API_URL = os.getenv('OSV_API_URL')
MITRE_CWE_URL = os.getenv('MITRE_CWE_URL')
CWE_JSON_PATH = os.path.join(os.path.abspath(__file__), '..', CWE_JSON_FILE)


def dependency_preparation(file: str) -> List[Dict[str, str]]:
    depends = []
    with open(file, 'r', encoding='utf-8') as file_lines:
        for line in file_lines:
            line = line.strip().split('==')
            # { "package": { "name": "jinja2", "ecosystem": "PyPI" }, "version": "3.1.4" } => format for OSV
            depends.append({
                "package": {"name": line[0],"ecosystem": "PyPI"}, # currently for python only
                "version": line[1]
            })
    logging.info(f"Dependecies for OSV: {depends}")
    return depends


# temp placed here
def get_dependency_vulnerability(dependeces):
    vulns = []
    unprocessed_vulns = []
    for depend in dependeces:
        response = requests.post(url=OSV_API_URL, json=depend)
        data = response.json()
        if data:
            unprocessed_vulns.append(data)
    for data in unprocessed_vulns:
        for vuln in data.get('vulns', []):
            if vuln:
                for s in vuln.get("severity"):
                    vector_type = s.get("type")
                    vector = s.get("score")  # vector representation
                    
                    if vector_type == "CVSS_V4":
                        cvss_obj = CVSS4(vector)
                        severity = cvss_obj.severity
                        break
                    elif vector_type == "CVSS_V3":
                        cvss_obj = CVSS3(vector)
                        severity = cvss_obj.severities()
                        break

                vulns.append({
                    "summary": vuln.get('summary'),
                    "details": vuln.get('details'),
                    "CVE_ids": vuln.get('aliases'),
                    "CWE_ids": vuln.get('database_specific').get('cwe_ids'),
                    "severity": severity,
                    "fixed_version": vuln.get('affected')[0].get('ranges')[0].get('events')[0].get('fixed')
                })
    return vulns

# TODO: parse mitre data
def get_mitre_cwe(cwe_ids):
    cwe_data = []
    for cwe_id in cwe_ids:
        mitre_url = f"{MITRE_CWE_URL}/{cwe_id}"
        print(mitre_url)
        response = requests.get(mitre_url)
        data = response.json()
        cwe_data.append(data)
    print(cwe_data)
    return cwe_data


def run_dependency_check():
    cwe_ids = []
    data = dependency_preparation('requirements.txt')
    vulns = get_dependency_vulnerability(data)
    for vuln in vulns:
        for cwe in vuln.get('CWE_ids'):
            cwe_ids.append(cwe.split('-')[1].strip())
    get_mitre_cwe(cwe_ids)
    print(cwe_ids)


def kev_json_to_txt(kev_link=KEV_JSON_LINK):
    docs = []
    response = requests.get(url=kev_link)
    data = response.json()
    text = data['vulnerabilities']
    for vul in text:
        docs.append(
            Document(
                page_content=vul['shortDescription'],
                metadata={
                    'cveID': vul['cveID'],
                    'vulnerabilityName': vul['vulnerabilityName'],
                    'requiredAction': vul['requiredAction']
                }
            )
        )
    return docs


def cwe_documents(cwe_json=CWE_JSON_PATH):
    docs = []
    with open(cwe_json, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for vul in data:
        docs.append(
            Document(
                page_content=vul['embedding_text'],
                metadata={
                    'cweID': vul['id'],
                    'name': vul['name'],
                    'description': vul['description'],
                    'potential_mitigations': vul['potential_mitigations']
                }
            )
        )
    print('everything is loaded')
    return docs
if __name__ == '__main__':
    cwe_documents()