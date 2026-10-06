from functools import lru_cache
from pathlib import Path

from fastembed import TextEmbedding
from langchain.tools import tool
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_text_splitters import MarkdownHeaderTextSplitter

RUNBOOK_DIR = Path(__file__).parent.parent / "data" / "runbooks"

class LocalEmbeddings(Embeddings):
    """Local ONNX embedding model: no API key, no data leaves the box."""
    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5"):
        self.model = TextEmbedding(model_name)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [v.tolist() for v in self.model.embed(texts)]

    def embed_query(self, text: str) -> list[float]:
        return next(iter(self.model.query_embed(text))).tolist()

def load_runbooks() -> list[Document]:
    splitter = MarkdownHeaderTextSplitter([("#", "runbook"), ("##", "section")], strip_headers=False)
    docs = []
    for path in sorted(RUNBOOK_DIR.glob("*.md")):
        for chunk in splitter.split_text(path.read_text()):
            chunk.metadata["source"] = path.name
            docs.append(chunk)
    return docs

@lru_cache
def get_vectorstore() -> InMemoryVectorStore:
    return InMemoryVectorStore.from_documents(load_runbooks(), LocalEmbeddings())

@tool
def search_runbooks(query: str) -> str:
    """Search internal security runbooks for remediation procedures, SLAs and policy.
    Use for 'how do we fix X', 'what is our SLA for Y', or rule IDs like PSC-K8S-001."""
    hits = get_vectorstore().similarity_search_with_score(query, k=3)
    return "\n\n---\n\n".join(
        f"[{d.metadata['source']} > {d.metadata.get('section', d.metadata.get('runbook'))}] (score {s:.2f})\n{d.page_content}"
        for d, s in hits
    )

if __name__ == "__main__":
    print(search_runbooks.invoke({"query": "How do I fix a privileged container?"}))