"""kNN-distance anomaly detector (unsupervised, trained on benign traces only).

Score = - mean distance from the action's feature vector to its k nearest BENIGN training actions
(after standardising features). Close to 0 = looks like normal work; very negative = unlike anything
benign agents did. Easy to explain to judges, no hidden state, stable with duplicate rows.
"""
import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler


class KnnDetector:
    def __init__(self, k: int = 10):
        self.k = k

    def fit(self, X):
        self.scaler = StandardScaler().fit(X)
        self.nn = NearestNeighbors(n_neighbors=self.k).fit(self.scaler.transform(X))
        return self

    def decision_function(self, X):
        d, _ = self.nn.kneighbors(self.scaler.transform(np.asarray(X, dtype=float)), n_neighbors=self.k)
        return -d.mean(axis=1)
