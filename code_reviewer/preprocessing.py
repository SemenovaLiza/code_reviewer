# TODO: organize the file
from typing import Dict, Any
from langchain_community.document_loaders import DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from chromadb import Documents, EmbeddingFunction, Embeddings
from chromadb.utils.embedding_functions import register_embedding_function
from sentence_transformers import SentenceTransformer
from langchain_community.vectorstores import Chroma


DATA_PATH = "knowledge_base/"
CHROMA_PATH = "chroma_db"

# chroma uses this model by defalt
embed_model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')


@register_embedding_function()
class EmbeddingFucntionCustom(EmbeddingFunction):

    def __init__(self, model):
        self.model = model

    def __call__(self, input: Documents) -> Embeddings:
        embeddings = self.model.encode(input)
        return embeddings.tolist()
    
    @staticmethod
    def name() -> str:
        return "custom_embed_fn"
    
    def get_config(self) -> Dict[str, Any]:
        return dict(model=self.model)
    
    @staticmethod
    def build_from_config(config: Dict[str, Any]):
        model = SentenceTransformer(config["model"])
        return EmbeddingFucntionCustom(model=model)
    

def load_documents():
    loader = DirectoryLoader(DATA_PATH, glob="*.json")
    documents = loader.load()
    return documents


def split_documents(documents):
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=500,
        length_function=len,
        add_start_index=True
    )
    chunks = text_splitter.split_documents(documents)
    return chunks


em = EmbeddingFucntionCustom(model=embed_model)


def save_to_chroma(chunks):
    db = Chroma.from_documents(documents=chunks, embedding=em, collection_name="code_quality_patterns", persist_directory=CHROMA_PATH)
    db.persist()

def generate_data_store():
    documents = load_documents()
    print("Loaded documents:", len(documents))
    chunks = split_documents(documents)
    print("Created chunks:", len(chunks))
    save_to_chroma(chunks)
    # db = Chroma(collection_name="code_quality_patterns", persist_directory=CHROMA_PATH)
    # db.add_documents(chunks)

def embedd():
    generate_data_store()

if __name__ == "__main__":
    embedd()