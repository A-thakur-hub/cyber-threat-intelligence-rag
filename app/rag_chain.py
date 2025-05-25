from llama_cpp import Llama
import faiss
import pickle
import numpy as np
from sentence_transformers import SentenceTransformer

INDEX_PATH = "faiss_index/cve.index"
META_PATH = "faiss_index/cve_metadata.pkl"
EMBED_MODEL = "all-MiniLM-L6-v2"
MISTRAL_MODEL_PATH = "models/mistral-7b-instruct-v0.1.Q4_K_M.gguf" 

def load_faiss_index():
    index = faiss.read_index(INDEX_PATH)
    with open(META_PATH, "rb") as f:
        metadata = pickle.load(f)
    return index, metadata

def embed_query(query, model):
    return model.encode([query], convert_to_numpy=True)

def search_index(query_vector, index, k=5):
    D, I = index.search(query_vector, k)
    return I[0]

def build_prompt(query, chunks):
    context = "\n\n".join(chunks)
    prompt = f"""You are a cybersecurity assistant. Based on the following CVE reports, answer the user's question clearly and concisely.

Context:
{context}

Question: {query}
Answer:"""
    return prompt

def run_rag_pipeline():
    query = "Are there any known privilege escalation issues in Windows servers reported this year?"

    print(f" Query: {query}")

    # Embed the query
    embedder = SentenceTransformer(EMBED_MODEL)
    query_vec = embed_query(query, embedder)

    # Load FAISS index and metadata
    index, metadata = load_faiss_index()
    top_ids = search_index(query_vec, index, k=5)

    # Collect context chunks
    top_chunks = []
    sources = []
    for i in top_ids:
        meta = metadata[i]
        sources.append(f"{meta['cve_id']} ({meta['severity']}) - {meta['published']}")
        text = meta.get("chunk", meta.get("description", "N/A"))
        top_chunks.append(text)

    print("\n==== Retrieved Chunks ====")
    for chunk in top_chunks:
        print(chunk)
    
    # Build prompt for Mistral
    prompt = build_prompt(query, top_chunks)

    # Load Mistral model
    print("Loading Mistral model ...")
    llm = Llama(model_path=MISTRAL_MODEL_PATH)
    
    print("Generating response...")
    output = llm(prompt, max_tokens=300, stop=["\n", "Question:", "Context:"])
    answer = output["choices"][0]["text"]

    print("Answer:")
    print(answer.strip())

    print(" Sources used:")
    for src in sources:
        print("•", src)

if __name__ == "__main__":
    run_rag_pipeline()