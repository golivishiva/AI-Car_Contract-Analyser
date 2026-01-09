# vector_store.py
"""
Vector store for semantic search over contract documents using ChromaDB.
"""

import os
import chromadb
from chromadb.utils import embedding_functions

# Initialize ChromaDB client (persistent storage)
CHROMA_DIR = "./chroma_db"
os.makedirs(CHROMA_DIR, exist_ok=True)

client = chromadb.PersistentClient(path=CHROMA_DIR)

# Use OpenAI embeddings (or change to sentence-transformers for free option)
# For OpenAI: requires OPENAI_API_KEY in environment
# For free alternative: use "all-MiniLM-L6-v2" with sentence_transformers

try:
    # Try OpenAI embeddings first (better quality)
    openai_ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key=os.environ.get("OPENAI_API_KEY"),
        model_name="text-embedding-3-small"
    )
    collection = client.get_or_create_collection(
        name="contracts",
        embedding_function=openai_ef,
        metadata={"description": "Vehicle contract documents"}
    )
    EMBEDDING_TYPE = "openai"
except Exception as e:
    # Fallback to free sentence-transformers
    print(f"OpenAI embeddings unavailable ({e}), using sentence-transformers")
    default_ef = embedding_functions.DefaultEmbeddingFunction()
    collection = client.get_or_create_collection(
        name="contracts",
        embedding_function=default_ef,
        metadata={"description": "Vehicle contract documents"}
    )
    EMBEDDING_TYPE = "sentence-transformers"


def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> list[str]:
    """
    Split text into overlapping chunks for better semantic search.
    
    Args:
        text: Full contract text
        chunk_size: Characters per chunk
        overlap: Overlapping characters between chunks
    
    Returns:
        List of text chunks
    """
    if not text or len(text) < chunk_size:
        return [text]
    
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += (chunk_size - overlap)
    
    return chunks


def add_document_to_chroma(text: str, metadata: dict = None):
    """
    Add a contract document to ChromaDB vector store.
    
    Args:
        text: Full extracted contract text
        metadata: Optional metadata (e.g., filename, date)
    """
    if not text or not text.strip():
        print("⚠️ Empty text provided to vector store")
        return
    
    # Split into chunks for better retrieval
    chunks = chunk_text(text)
    
    # Generate unique IDs for each chunk
    base_id = metadata.get("file", "contract") if metadata else "contract"
    ids = [f"{base_id}_chunk_{i}" for i in range(len(chunks))]
    
    # Prepare metadata for each chunk
    metadatas = []
    for i, chunk in enumerate(chunks):
        chunk_meta = metadata.copy() if metadata else {}
        chunk_meta.update({
            "chunk_index": i,
            "total_chunks": len(chunks),
            "chunk_size": len(chunk)
        })
        metadatas.append(chunk_meta)
    
    try:
        # Add to ChromaDB
        collection.add(
            documents=chunks,
            ids=ids,
            metadatas=metadatas
        )
        print(f"✅ Added {len(chunks)} chunks to vector store (using {EMBEDDING_TYPE})")
    except Exception as e:
        print(f"❌ Error adding to vector store: {e}")


def query_chroma(question: str, n_results: int = 3) -> list[str]:
    """
    Query ChromaDB for relevant contract sections.
    
    Args:
        question: User's question
        n_results: Number of relevant chunks to return
    
    Returns:
        List of relevant text chunks
    """
    if not question or not question.strip():
        return []
    
    try:
        results = collection.query(
            query_texts=[question],
            n_results=n_results
        )
        
        # Extract documents from results
        if results and results.get("documents"):
            documents = results["documents"][0]  # First query result
            return documents
        
        return []
    
    except Exception as e:
        print(f"❌ Vector search error: {e}")
        return []


def clear_chroma_db():
    """
    Clear all documents from the vector store.
    Useful for testing or resetting.
    """
    try:
        client.delete_collection(name="contracts")
        print("✅ Vector store cleared")
    except Exception as e:
        print(f"❌ Error clearing vector store: {e}")


# For testing
if __name__ == "__main__":
    # Test the vector store
    test_contract = """
    This Vehicle Lease Agreement is entered into on January 1, 2024.
    
    Vehicle Details:
    - Make: Tesla
    - Model: Model 3
    - Year: 2024
    - VIN: 5YJ3E1EA1KF123456
    
    Lease Terms:
    - Monthly Payment: $499
    - Lease Duration: 36 months
    - Total Due at Signing: $2,499
    - Mileage Allowance: 12,000 miles per year
    
    The lessee agrees to maintain comprehensive insurance coverage.
    """
    
    # Add test document
    add_document_to_chroma(test_contract, metadata={"file": "test_lease.pdf"})
    
    # Test queries
    print("\n🔍 Testing queries:")
    
    q1 = "What is the monthly payment?"
    print(f"\nQ: {q1}")
    results = query_chroma(q1)
    for i, r in enumerate(results, 1):
        print(f"{i}. {r[:100]}...")
    
    q2 = "What are the mileage limits?"
    print(f"\nQ: {q2}")
    results = query_chroma(q2)
    for i, r in enumerate(results, 1):
        print(f"{i}. {r[:100]}...")