import os
import json
import requests
from azure.identity import DefaultAzureCredential, ClientSecretCredential, InteractiveBrowserCredential
from datetime import datetime, timezone
import time

tenant_id = os.environ['tenant_id']
client_id = os.environ['client_id']
client_secret = os.environ['client_secret']
workspace_id = os.environ['workspace_id']
table_name = os.environ['table_name']
json_file_path = os.environ['json_file_path']
batch_size = 500 
 
class AzureLogIngestion:
    def __init__(
        self, dce_endpoint, dcr_immutable_id, stream_name, 
        tenant_id=None, client_id=None, client_secret=None, use_browser_auth=False
    ):
        self.dce_endpoint = dce_endpoint.rstrip('/')
        self.dcr_immutable_id = dcr_immutable_id
        self.stream_name = stream_name
        self.upload_url = f"{self.dce_endpoint}/dataCollectionRules/{self.dcr_immutable_id}/streams/{self.stream_name}?api-version=2023-01-01"
        
        if client_id and client_secret and tenant_id:
            print("Using Service Principal authentication...")
        
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )

        elif use_browser_auth:
            print("Using Interactive Browser authentication...")
            self.credential = InteractiveBrowserCredential()

        else:
            print("Using DefaultAzureCredential (requires Azure CLI login or environment variables)...")
            self.credential = DefaultAzureCredential()
 
    def get_access_token(self):
        token = self.credential.get_token("https://monitor.azure.com/.default")
        return token.token
    
    def chunk_data(self, data, chunk_size=1000):
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]
    
    def add_timestamp(self, record):
        if 'TimeGenerated' not in record:
            record['TimeGenerated'] = datetime.now(timezone.utc).isoformat()
        return record
 
    def ingest_data(self, data, batch_size=1000, delay_between_batches=1):
        if isinstance(data, str):
            print(f"Loading data from {data}...")
            with open(data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        
        if not isinstance(data, list):
            data = [data]
        
        total_records = len(data)
        print(f"Total records to ingest: {total_records}")
        
        data = [self.add_timestamp(record) for record in data]
        
        successful_batches = 0
        failed_batches = 0
        
        for i, chunk in enumerate(self.chunk_data(data, batch_size), 1):
            try:
                token = self.get_access_token()
                headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
                }
 
                response = requests.post(
                self.upload_url,
                    headers=headers,
                    json=chunk,
                    timeout=60
                )
 
                if response.status_code == 204:
                    successful_batches += 1
                    records_processed = min(i * batch_size, total_records)
                    print(f"✓ Batch {i} uploaded successfully ({records_processed}/{total_records} records)")
                else:
                    failed_batches += 1
                    print(f"✗ Batch {i} failed: {response.status_code} - {response.text}")
                
                if i * batch_size < total_records:
                    time.sleep(delay_between_batches)
 
            except Exception as e:
                failed_batches += 1
                print(f"✗ Error uploading batch {i}: {str(e)}")
                
                print("\n" + "="*50)
                print(f"Ingestion Summary:")
                print(f" Total Records: {total_records}")
                print(f" Successful Batches: {successful_batches}")
                print(f" Failed Batches: {failed_batches}")
                print("="*50)
                
if __name__ == "__main__":
    DCE_ENDPOINT = os.environ['DCE_ENDPOINT']
    DCR_IMMUTABLE_ID = os.environ['DCR_IMMUTABLE_ID']
    STREAM_NAME = os.environ['STREAM_NAME']
    
    JSON_FILE_PATH = os.environ['JSON_FILE_PATH']
    TENANT_ID = tenant_id
    CLIENT_ID = client_id
    CLIENT_SECRET = client_secret
    
    ingestion_client = AzureLogIngestion(
        dce_endpoint=DCE_ENDPOINT,
        dcr_immutable_id=DCR_IMMUTABLE_ID,
        stream_name=STREAM_NAME,
        tenant_id=TENANT_ID,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET
    )
    ingestion_client.ingest_data(
        data=JSON_FILE_PATH,
        batch_size=1000,
        delay_between_batches=1
    )
