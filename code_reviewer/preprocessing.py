import os
import requests
from dotenv import load_dotenv
from langchain_core.documents import Document


load_dotenv()

KEV_JSON_LINK = os.getenv('KEV_JSON_LINK')


def json_to_txt(kev_link=KEV_JSON_LINK):
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


if __name__ == '__main__':
    docs = json_to_txt(KEV_JSON_LINK)
    print(docs[:5])