"""
Load target/corpus/*.md into pgvector for the RAG target (target/rag_app.py).

Each document is chunked, embedded locally with fastembed, and written to the
``rag_chunks`` table. The run is idempotent: the table is truncated and fully
reloaded every time, so re-running after editing the corpus is always safe.

The corpus deliberately contains a poisoned document (travel_policy.md, with
an instruction hidden in an HTML comment) and a confidential one
(vendor_contracts.md). Ingestion does NOT sanitize either -- that is the point.
A retrieval pipeline that indexes whatever it is given is exactly what an
indirect prompt injection exploits.

Usage (with the database from docker-compose.yml running):

    python target/rag_ingest.py
"""

import os
import re
from pathlib import Path

import psycopg
from fastembed import TextEmbedding
from pgvector.psycopg import register_vector

CORPUS_DIR = Path(__file__).parent / "corpus"
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://rag:rag@localhost:5432/rag"
)

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
EMBED_DIMS = 384
TABLE = "rag_chunks"

CHUNK_SIZE = 500
CHUNK_OVERLAP = 50


def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """Split ``text`` into ~``size``-char chunks with ``overlap`` chars carried over.

    Paragraphs are packed whole where possible, so a short paragraph -- such as
    the hidden HTML comment in the poisoned doc -- lands intact in one chunk
    rather than being cut in half by a fixed-width window. Paragraphs longer
    than ``size`` are hard-split.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]

    pieces: list[str] = []
    for para in paragraphs:
        if len(para) <= size:
            pieces.append(para)
        else:
            step = size - overlap
            pieces.extend(para[i: i + size] for i in range(0, len(para), step))

    chunks: list[str] = []
    current = ""
    for piece in pieces:
        if current and len(current) + 2 + len(piece) > size:
            chunks.append(current)
            current = current[-overlap:] + "\n\n" + piece
        else:
            current = f"{current}\n\n{piece}" if current else piece
    if current:
        chunks.append(current)
    return chunks


def load_corpus() -> list[tuple[str, str]]:
    """Return (source filename, chunk text) pairs for every corpus document."""
    rows = []
    for path in sorted(CORPUS_DIR.glob("*.md")):
        for chunk in chunk_text(path.read_text(encoding="utf-8")):
            rows.append((path.name, chunk))
    return rows


def main() -> None:
    rows = load_corpus()
    print(f"Chunked {len(rows)} chunks from {CORPUS_DIR}")

    embedder = TextEmbedding(model_name=EMBED_MODEL)
    embeddings = list(embedder.embed([chunk for _, chunk in rows]))

    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        register_vector(conn)
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE} (
                id bigserial PRIMARY KEY,
                source text NOT NULL,
                chunk text NOT NULL,
                embedding vector({EMBED_DIMS}) NOT NULL
            )
            """
        )
        conn.execute(f"TRUNCATE {TABLE} RESTART IDENTITY")
        with conn.cursor() as cur:
            cur.executemany(
                f"INSERT INTO {TABLE} (source, chunk, embedding) VALUES (%s, %s, %s)",
                [(source, chunk, emb) for (source, chunk), emb in zip(rows, embeddings)],
            )

    print(f"Loaded {len(rows)} chunks into {TABLE}")


if __name__ == "__main__":
    main()
