"""
tests/test_clustering.py
------------------------
Unit tests for src/clustering/numpy_cluster.py.
No AWS dependencies — pure NumPy/sklearn.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from clustering.numpy_cluster import (  # noqa: E402
    cluster_vectors,
    cosine_similarity_matrix,
    decode_vector,
    BATCH_CAP,
)


# ─────────────────────────────────────────────────────────────────────────────
# cosine_similarity_matrix
# ─────────────────────────────────────────────────────────────────────────────

class TestCosineSimilarityMatrix:
    def test_identical_vectors_score_one(self):
        v = np.array([[1.0, 0.0, 0.0], [1.0, 0.0, 0.0]], dtype=np.float32)
        sim = cosine_similarity_matrix(v)
        assert pytest.approx(sim[0, 1], abs=1e-5) == 1.0

    def test_orthogonal_vectors_score_zero(self):
        v = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32)
        sim = cosine_similarity_matrix(v)
        assert pytest.approx(sim[0, 1], abs=1e-5) == 0.0

    def test_opposite_vectors_score_negative_one(self):
        v = np.array([[1.0, 0.0], [-1.0, 0.0]], dtype=np.float32)
        sim = cosine_similarity_matrix(v)
        assert pytest.approx(sim[0, 1], abs=1e-5) == -1.0

    def test_zero_vector_does_not_raise(self):
        v = np.array([[0.0, 0.0, 0.0], [1.0, 0.0, 0.0]], dtype=np.float32)
        sim = cosine_similarity_matrix(v)
        assert sim.shape == (2, 2)

    def test_symmetric(self):
        rng = np.random.default_rng(42)
        v = rng.random((5, 8)).astype(np.float32)
        sim = cosine_similarity_matrix(v)
        np.testing.assert_allclose(sim, sim.T, atol=1e-5)


# ─────────────────────────────────────────────────────────────────────────────
# decode_vector
# ─────────────────────────────────────────────────────────────────────────────

class TestDecodeVector:
    def test_round_trip(self):
        original = [0.1, 0.2, 0.3, 0.4]
        arr = np.array(original, dtype="<f4")
        decoded = decode_vector(arr.tobytes())
        np.testing.assert_allclose(decoded, original, atol=1e-6)

    def test_returns_copy(self):
        arr = np.array([1.0, 2.0], dtype="<f4")
        decoded = decode_vector(arr.tobytes())
        decoded[0] = 999.0
        assert arr[0] == pytest.approx(1.0)


# ─────────────────────────────────────────────────────────────────────────────
# cluster_vectors
# ─────────────────────────────────────────────────────────────────────────────

def _unit(v: list[float]) -> list[float]:
    """Return L2-normalised vector."""
    arr = np.array(v, dtype=np.float64)
    return (arr / np.linalg.norm(arr)).tolist()


class TestClusterVectors:
    def test_empty_input(self):
        assert cluster_vectors([], []) == []

    def test_single_item_is_noise(self):
        result = cluster_vectors(["a"], [_unit([1.0, 0.0, 0.0])])
        assert result == [("a", -1)]

    def test_two_identical_vectors_cluster_together(self):
        v = _unit([1.0, 2.0, 3.0])
        result = cluster_vectors(["a", "b"], [v, v], eps=0.01)
        labels = {id_: label for id_, label in result}
        assert labels["a"] == labels["b"]
        assert labels["a"] != -1

    def test_orthogonal_vectors_are_noise(self):
        v1 = _unit([1.0, 0.0])
        v2 = _unit([0.0, 1.0])
        result = cluster_vectors(["a", "b"], [v1, v2], eps=0.1)
        labels = dict(result)
        # cosine distance = 1.0, far beyond eps=0.1 → both noise
        assert labels["a"] == -1
        assert labels["b"] == -1

    def test_two_clusters_detected(self):
        # Cluster A: three nearly-identical vectors
        a = _unit([1.0, 0.01, 0.0])
        b = _unit([1.0, 0.02, 0.0])
        c = _unit([1.0, 0.015, 0.0])
        # Cluster B: three nearly-identical vectors pointing elsewhere
        d = _unit([0.0, 1.0, 0.01])
        e = _unit([0.0, 1.0, 0.02])
        f = _unit([0.0, 1.0, 0.015])

        ids = ["a", "b", "c", "d", "e", "f"]
        vecs = [a, b, c, d, e, f]
        result = dict(cluster_vectors(ids, vecs, eps=0.05, min_samples=2))

        # a, b, c must share a label; d, e, f must share a different label
        assert result["a"] == result["b"] == result["c"]
        assert result["d"] == result["e"] == result["f"]
        assert result["a"] != result["d"]
        assert result["a"] != -1

    def test_overflow_beyond_cap_gets_noise_label(self):
        v = _unit([1.0, 0.0])
        n = BATCH_CAP + 5
        ids = [str(i) for i in range(n)]
        vecs = [v] * n
        result = dict(cluster_vectors(ids, vecs))
        # Items beyond BATCH_CAP receive label -1
        for i in range(BATCH_CAP, n):
            assert result[str(i)] == -1

    def test_returns_id_per_item(self):
        v = _unit([1.0, 0.0, 0.0])
        ids = ["x", "y", "z"]
        result = cluster_vectors(ids, [v, v, v])
        result_ids = [r[0] for r in result]
        assert result_ids == ids
