import json
import os
import re
import faiss
import pickle
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
from typing import List, Dict

# === Config ===
DATA_PATH = "data/cve/cve_data.jsonl"
INDEX_PATH = "faiss_index/cve.index"
META_PATH = "faiss_index/cve_metadata.pkl"
CHUNK_SIZE = 500  # characters

# === Load CVE Data ===
def load_jsonl(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]

# === Clean text ===
def clean_text(text: str) -> str:
    text = re.sub(r"\s+", " ", text)  # remove extra whitespaces/newlines
    return text.strip()

# === Chunk text into small parts ===
def chunk_text(text: str, chunk_size: int = CHUNK_SIZE) -> List[str]:
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]

# === Embed and index ===
def build_faiss_index(model_name="all-MiniLM-L6-v2"):
    print("🔄 Loading CVE data...")
    cves = load_jsonl(DATA_PATH)

    print("🧠 Loading embedding model...")
    model = SentenceTransformer(model_name)

    texts, metadata = [], []
    for cve in tqdm(cves):
        desc = clean_text(cve.get("description", ""))
        chunks = chunk_text(desc)
        for chunk in chunks:
            texts.append(chunk)
            metadata.append({
                "cve_id": cve["cve_id"],
                "severity": cve["severity"],
                "published": cve["published"],
                "source": cve["source"],
                "text": chunk
            })

    print(f"🔢 Embedding {len(texts)} text chunks...")
    embeddings = model.encode(texts, show_progress_bar=True)

    print("💾 Building FAISS index...")
    dimension = embeddings[0].shape[0]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)

    os.makedirs(os.path.dirname(INDEX_PATH), exist_ok=True)
    faiss.write_index(index, INDEX_PATH)

    with open(META_PATH, "wb") as f:
        pickle.dump(metadata, f)

    print(f"✅ FAISS index saved to {INDEX_PATH}")
    print(f"✅ Metadata saved to {META_PATH}")


# === Search interface ===
def search_faiss(query: str, k: int = 5, model_name="all-MiniLM-L6-v2") -> List[Dict]:
    print(f"🔍 Searching for: {query}")
    model = SentenceTransformer(model_name)
    query_vec = model.encode([query])

    index = faiss.read_index(INDEX_PATH)
    with open(META_PATH, "rb") as f:
        metadata = pickle.load(f)

    distances, indices = index.search(query_vec, k)
    results = [metadata[i] for i in indices[0]]
    return results


if __name__ == "__main__":
    build_faiss_index()
