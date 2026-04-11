import os
import logging
import requests
from cvss import CVSS4, CVSS3
from typing import List, Dict
from dotenv import load_dotenv


load_dotenv()
logging.basicConfig(level=logging.INFO)

CWE_JSON_FILE = os.getenv('CWE_JSON_FILE')
OSV_API_URL = os.getenv('OSV_API_URL')
MITRE_CWE_URL = os.getenv('MITRE_CWE_URL')
CWE_JSON_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), CWE_JSON_FILE)


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
    #logging.info(f"Dependecies for OSV: {depends}")
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


def run_dependency_check():
    cwe_ids = []
    data = dependency_preparation('requirements.txt')
    vulns = get_dependency_vulnerability(data)
    for vuln in vulns:
        for cwe in vuln.get('CWE_ids'):
            cwe_ids.append(cwe.split('-')[1].strip())
    print(['CWE-' + cweID for cweID in cwe_ids])
    return ['CWE-' + cweID for cweID in cwe_ids]
