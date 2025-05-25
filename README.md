# Cyber Threat Intelligence using RAG
A privacy-preserving Retrieval-Augmented Generation (RAG) system for offline analysis of cybersecurity threats using local LLMs and structured threat intelligence documents.

## Overview
This project enables secure, offline querying of cybersecurity data by retrieving relevant information from MITRE ATT&CK, CVE reports, and similar sources, then generating contextual responses using a local LLM. It is designed for environments where data privacy and API independence are critical

## Motivation
Cloud-based language models often raise privacy concerns in cybersecurity settings. This system solves that by offering a completely offline RAG pipeline that allows natural language interaction with threat data—ideal for air-gapped, secure infrastructures.

## Features
* Semantic search over 5,000+ threat reports using FAISS
* Offline RAG pipeline with local LLMs (e.g., Mistral or LLaMA)
* 100% privacy-preserving: no external API or internet access required
* Under 1 second average query response time
* 92% response relevance verified by domain expert evaluation

## Tech Stack
* Python, FAISS, LangChain, Sentence Transformers
* Local LLMs (e.g., Mistral-7B via llama-cpp or gguf)
* Data from MITRE ATT&CK, NIST NVD, and CVE repositories

## Getting Started

### Installation

```
git clone https://github.com/a-thakur-hub/cyber-threat-intelligence-rag.git
cd cyber-threat-intelligence-rag
pip install -r requirements.txt
```
### Run the System

```
python app/rag_chain.py
```
## Limitations
* Currently supports only structured text-based reports (JSON, plain text); PDF parsing and visual elements are not yet supported
* Retrieval accuracy depends on quality and consistency of the chunking logic; overly long or short chunks may affect semantic match
* Requires manual FAISS re-indexing when new threat data is added (no dynamic ingestion pipeline yet)





