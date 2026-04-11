import os
import logging
import json
from dotenv import load_dotenv
from langchain_core.documents import Document


load_dotenv()
logging.basicConfig(level=logging.INFO)

CWE_JSON_FILE = os.getenv('CWE_JSON_FILE')
CWE_JSON_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), CWE_JSON_FILE)


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
