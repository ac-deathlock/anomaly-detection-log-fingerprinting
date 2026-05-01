"""
src/clustering/numpy_cluster.py
--------------------------------
DBSCAN clustering on cosine distance using NumPy + scikit-learn.

The cosine *similarity* matrix is computed with NumPy (fast matrix multiply
after L2 normalization). The (1 - similarity) distance matrix is passed to
sklearn DBSCAN with metric="precomputed".

Complexity: O(n² · d) for the similarity matrix, where n = number of vectors
and d = embedding dimension. Cap input at ~500 vectors per stream per run to
keep Lambda memory and compute within safe bounds (configured via CLUSTER_BATCH_CAP).

Env vars:
  CLUSTER_EPS          DBSCAN eps on cosine distance (default: 0.15)
  CLUSTER_MIN_SAMPLES  DBSCAN min_samples (default: 2)
  CLUSTER_BATCH_CAP    Maximum vectors to cluster per stream per run (default: 500)
"""
import logging
import os

import numpy as np
from sklearn.cluster import DBSCAN

logger = logging.getLogger(__name__)

EPS: float = float(os.environ.get("CLUSTER_EPS", "0.15"))
MIN_SAMPLES: int = int(os.environ.get("CLUSTER_MIN_SAMPLES", "2"))
BATCH_CAP: int = int(os.environ.get("CLUSTER_BATCH_CAP", "500"))


def decode_vector(raw: bytes | bytearray) -> np.ndarray:
    """Decode a little-endian float32 byte blob back to a 1-D numpy array."""
    return np.frombuffer(raw, dtype="<f4").copy()


def cosine_similarity_matrix(vectors: np.ndarray) -> np.ndarray:
    """
    Compute an (n × n) cosine similarity matrix.

    Rows are L2-normalised first so the similarity is just the dot product.
    """
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    # Avoid divide-by-zero for zero vectors
    normalized = vectors / np.maximum(norms, 1e-10)
    return (normalized @ normalized.T).astype(np.float64)


def cluster_vectors(
    ids: list[str],
    vectors: list[list[float] | np.ndarray],
    eps: float = EPS,
    min_samples: int = MIN_SAMPLES,
) -> list[tuple[str, int]]:
    """
    Cluster *vectors* with DBSCAN on cosine distance.

    Returns a list of ``(id, cluster_label)`` pairs.
    ``cluster_label == -1`` means the point is noise / singleton.

    Input is capped at BATCH_CAP vectors; excess items receive label -1.
    """
    if not ids:
        return []

    capped_ids = ids[:BATCH_CAP]
    capped_vecs = vectors[:BATCH_CAP]
    overflow_ids = ids[BATCH_CAP:]

    if len(capped_ids) < 2:
        results = [(capped_ids[0], -1)] if capped_ids else []
        results += [(oid, -1) for oid in overflow_ids]
        return results

    mat = np.array(capped_vecs, dtype=np.float32)
    similarity = cosine_similarity_matrix(mat)
    # Clamp to [0, 2] to ensure valid distance values
    distance = np.clip(1.0 - similarity, 0.0, 2.0)

    labels: np.ndarray = DBSCAN(
        eps=eps,
        min_samples=min_samples,
        metric="precomputed",
        n_jobs=1,
    ).fit_predict(distance)

    results = list(zip(capped_ids, labels.tolist()))
    results += [(oid, -1) for oid in overflow_ids]
    return results
