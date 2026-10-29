"""
ml_engine.py
============
Isolation Forest anomaly detection engine for NetSentinel's ML core.

The engine wraps scikit-learn's ``IsolationForest`` with a ``StandardScaler``
pre-processing step and provides:

* Online sample buffering and automatic first-fit training.
* Anomaly scoring on a 0-100 scale (higher = more anomalous).
* Model persistence via pickle files.
* Concept-drift detection and triggered retraining.
* Approximate per-feature importance via random perturbation.

If scikit-learn is not installed the module degrades gracefully — all methods
return safe defaults and a warning is logged.

Usage
-----
    from threat_engine.ml_engine import ml_engine   # singleton

    ml_engine.add_training_sample(feature_vector)
    result = ml_engine.predict(feature_vector)
    # result = {'anomaly_score': 12.3, 'is_anomaly': False, ...}
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import threading
import time
from typing import Dict, List, Optional

import numpy as np  # numpy is a core dependency; fail loudly if missing

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional scikit-learn import
# ---------------------------------------------------------------------------
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning(
        "scikit-learn is not installed.  IsolationForestEngine will run in "
        "no-op mode.  Install it with: pip install scikit-learn"
    )

# ---------------------------------------------------------------------------
# Feature names (must match feature_extractor.FEATURE_NAMES)
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    "UCAST",
    "MCAST",
    "BCAST",
    "ARP",
    "GARP",
    "ARP_PROBE",
    "ARP_ANNOUNCE",
    "TCP",
    "UDP",
    "ICMP",
    "ICMPv6",
    "IPv6",
    "SSDP",
    "IPF",
    "ARP_noIP",
    "IP_RESTO",
]

_N_FEATURES = len(FEATURE_NAMES)


# ---------------------------------------------------------------------------
# IsolationForestEngine
# ---------------------------------------------------------------------------

class IsolationForestEngine:
    """Isolation Forest anomaly detection engine.

    Class Attributes
    ----------------
    MODEL_PATH : str
        Default path for the pickled ``IsolationForest`` model.
    SCALER_PATH : str
        Default path for the pickled ``StandardScaler``.
    STATS_PATH : str
        Path for the JSON file holding training statistics.
    MIN_TRAINING_SAMPLES : int
        Minimum number of MAC-window samples required before training starts.
    CONTAMINATION : float
        Expected fraction of anomalies in the training set (~1.8 %).
    DRIFT_THRESHOLD : float
        Anomaly rate above which model drift is declared and retraining is
        triggered.
    FEATURE_NAMES : list of str
        Ordered feature names matching the 16-feature BUM-traffic vector.
    """

    MODEL_PATH:            str   = "database/isolation_forest_model.pkl"
    SCALER_PATH:           str   = "database/isolation_forest_scaler.pkl"
    STATS_PATH:            str   = "database/ml_stats.json"
    MIN_TRAINING_SAMPLES:  int   = 50
    CONTAMINATION:         float = 0.018
    DRIFT_THRESHOLD:       float = 0.15
    FEATURE_NAMES:         List[str] = FEATURE_NAMES

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        """Initialise the engine with empty buffers and no trained model."""
        # Model components
        self.model:   Optional["IsolationForest"]  = None   # type: ignore[name-defined]
        self.scaler:  Optional["StandardScaler"]   = None   # type: ignore[name-defined]
        self.is_trained: bool = False

        # Sample buffer for deferred / triggered training
        self.sample_buffer: List[List[float]] = []

        # Thread safety
        self.training_lock = threading.Lock()

        # Training statistics
        self.stats: Dict = {
            "is_trained":      False,
            "sample_count":    0,
            "last_trained_at": None,
            "contamination":   self.CONTAMINATION,
            "n_estimators":    100,
            "model_path":      self.MODEL_PATH,
            "drift_threshold": self.DRIFT_THRESHOLD,
            "total_predictions": 0,
            "anomalies_flagged": 0,
        }

        logger.info("IsolationForestEngine initialised (sklearn_available=%s)", SKLEARN_AVAILABLE)

    # ------------------------------------------------------------------
    # Sample management & auto-training
    # ------------------------------------------------------------------

    def add_training_sample(self, feature_vector: List[float]) -> None:
        """Append a feature vector to the training buffer.

        When the buffer reaches ``MIN_TRAINING_SAMPLES`` and the model has
        not yet been trained, ``train()`` is called automatically.

        Parameters
        ----------
        feature_vector : list of float
            A 16-element normalized feature vector (in ``FEATURE_NAMES``
            order).
        """
        if not SKLEARN_AVAILABLE:
            return

        if len(feature_vector) != _N_FEATURES:
            logger.warning(
                "Feature vector has %d elements; expected %d.  Skipping.",
                len(feature_vector),
                _N_FEATURES,
            )
            return

        with self.training_lock:
            self.sample_buffer.append(list(feature_vector))
            self.stats["sample_count"] = len(self.sample_buffer)

            if (
                not self.is_trained
                and len(self.sample_buffer) >= self.MIN_TRAINING_SAMPLES
            ):
                logger.info(
                    "Buffer reached %d samples — triggering initial training.",
                    len(self.sample_buffer),
                )
                self.train(self.sample_buffer)

    def train(self, feature_matrix: List[List[float]]) -> None:
        """Fit the StandardScaler and IsolationForest on *feature_matrix*.

        The trained model and scaler are immediately saved to disk.

        Parameters
        ----------
        feature_matrix : list of list of float
            Each inner list is a 16-element feature vector.
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available; training skipped.")
            return

        if len(feature_matrix) < self.MIN_TRAINING_SAMPLES:
            logger.warning(
                "Training matrix has only %d samples (min %d).  Skipping.",
                len(feature_matrix),
                self.MIN_TRAINING_SAMPLES,
            )
            return

        try:
            X = np.array(feature_matrix, dtype=np.float64)

            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            model = IsolationForest(
                contamination=self.CONTAMINATION,
                n_estimators=100,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(X_scaled)

            with self.training_lock:
                self.model    = model
                self.scaler   = scaler
                self.is_trained = True
                self.stats.update({
                    "is_trained":      True,
                    "sample_count":    len(feature_matrix),
                    "last_trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "contamination":   self.CONTAMINATION,
                    "n_estimators":    100,
                })

            self.save_model()
            self._save_stats()
            logger.info(
                "IsolationForest trained on %d samples (contamination=%.3f)",
                len(feature_matrix),
                self.CONTAMINATION,
            )

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Training failed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, feature_vector: List[float]) -> dict:
        """Score a single feature vector for anomaly likelihood.

        The raw Isolation Forest score (in [-1, 1], where -1 is most
        anomalous) is mapped to a 0-100 anomaly scale:

        .. code-block:: text

            anomaly_score = clamp((1 - raw_score) * 50, 0, 100)

        Parameters
        ----------
        feature_vector : list of float
            A 16-element normalized feature vector.

        Returns
        -------
        dict
            ``anomaly_score`` (float, 0-100), ``is_anomaly`` (bool),
            ``isolation_score`` (float, raw sklearn score in −1..1),
            ``confidence`` (float, 0-0.95).

            Returns safe defaults (score=0, is_anomaly=False) when the
            model is not yet trained or sklearn is unavailable.
        """
        _default = {
            "anomaly_score":    0.0,
            "is_anomaly":       False,
            "isolation_score":  1.0,
            "confidence":       0.0,
        }

        if not SKLEARN_AVAILABLE or not self.is_trained:
            return _default

        if len(feature_vector) != _N_FEATURES:
            logger.warning(
                "predict() received vector of length %d; expected %d.",
                len(feature_vector),
                _N_FEATURES,
            )
            return _default

        try:
            X = np.array([feature_vector], dtype=np.float64)
            X_scaled = self.scaler.transform(X)  # type: ignore[union-attr]

            # decision_function returns the raw anomaly score in R;
            # score_samples returns log(average path length) — we want the
            # signed "decision" value that is negative for anomalies.
            raw_score: float = float(self.model.decision_function(X_scaled)[0])  # type: ignore[union-attr]

            # Map to 0-100 scale: raw_score ∈ (−0.5, +0.5) approximately
            anomaly_score: float = float(np.clip((1.0 - raw_score) * 50.0, 0.0, 100.0))
            is_anomaly: bool  = anomaly_score > 60.0
            confidence: float = min(anomaly_score / 100.0, 0.95)

            with self.training_lock:
                self.stats["total_predictions"] += 1
                if is_anomaly:
                    self.stats["anomalies_flagged"] += 1

            return {
                "anomaly_score":   round(anomaly_score, 4),
                "is_anomaly":      is_anomaly,
                "isolation_score": round(raw_score, 6),
                "confidence":      round(confidence, 4),
            }

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Prediction failed: %s", exc, exc_info=True)
            return _default

    # ------------------------------------------------------------------
    # Drift detection & retraining
    # ------------------------------------------------------------------

    def check_model_drift(self, recent_anomaly_rate: float) -> bool:
        """Check whether the observed anomaly rate indicates concept drift.

        Parameters
        ----------
        recent_anomaly_rate : float
            Fraction of recent predictions flagged as anomalies (0.0–1.0).

        Returns
        -------
        bool
            ``True`` if *recent_anomaly_rate* exceeds ``DRIFT_THRESHOLD``,
            suggesting the model should be retrained.
        """
        drift_detected = recent_anomaly_rate > self.DRIFT_THRESHOLD
        if drift_detected:
            logger.warning(
                "Model drift detected: anomaly rate %.2f%% > threshold %.2f%%",
                recent_anomaly_rate * 100,
                self.DRIFT_THRESHOLD * 100,
            )
        return drift_detected

    def retrain_if_needed(self, new_samples: List[List[float]]) -> None:
        """Retrain the model if drift is detected and enough data is available.

        Drift is evaluated by computing the fraction of *new_samples* that the
        current model would classify as anomalous.  If drift is detected **and**
        ``len(new_samples) >= MIN_TRAINING_SAMPLES``, ``train()`` is called with
        the combined buffer + new samples.

        Parameters
        ----------
        new_samples : list of list of float
            Recently collected feature vectors.
        """
        if not SKLEARN_AVAILABLE or not self.is_trained or not new_samples:
            return

        if len(new_samples) < self.MIN_TRAINING_SAMPLES:
            logger.debug(
                "retrain_if_needed: only %d new samples (min %d) — skipping.",
                len(new_samples),
                self.MIN_TRAINING_SAMPLES,
            )
            return

        # Estimate recent anomaly rate
        anomaly_count = sum(
            1 for fv in new_samples if self.predict(fv)["is_anomaly"]
        )
        recent_rate = anomaly_count / len(new_samples)

        if self.check_model_drift(recent_rate):
            # Combine existing buffer with new samples for richer retraining
            with self.training_lock:
                combined = list(self.sample_buffer) + list(new_samples)
            logger.info(
                "Retraining on %d combined samples (drift rate=%.2f%%)",
                len(combined),
                recent_rate * 100,
            )
            self.train(combined)
            # Replace buffer with new samples only (slide the window)
            with self.training_lock:
                self.sample_buffer = list(new_samples)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_model(self) -> bool:
        """Pickle the trained model and scaler to disk.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        if not self.is_trained:
            logger.warning("save_model called but model is not trained yet.")
            return False

        try:
            os.makedirs(os.path.dirname(self.MODEL_PATH) or ".", exist_ok=True)
            os.makedirs(os.path.dirname(self.SCALER_PATH) or ".", exist_ok=True)

            with open(self.MODEL_PATH, "wb") as fh:
                pickle.dump(self.model, fh)

            with open(self.SCALER_PATH, "wb") as fh:
                pickle.dump(self.scaler, fh)

            logger.info("Model saved to %s / %s", self.MODEL_PATH, self.SCALER_PATH)
            return True

        except OSError as exc:
            logger.error("Failed to save model: %s", exc)
            return False

    def load_model(self) -> bool:
        """Load a previously saved model and scaler from disk.

        Returns
        -------
        bool
            ``True`` if both files were found and loaded successfully,
            ``False`` otherwise.
        """
        if not SKLEARN_AVAILABLE:
            return False

        if not os.path.exists(self.MODEL_PATH) or not os.path.exists(self.SCALER_PATH):
            logger.info(
                "No saved model found at %s — will train from scratch.",
                self.MODEL_PATH,
            )
            return False

        try:
            with open(self.MODEL_PATH, "rb") as fh:
                model = pickle.load(fh)

            with open(self.SCALER_PATH, "rb") as fh:
                scaler = pickle.load(fh)

            with self.training_lock:
                self.model      = model
                self.scaler     = scaler
                self.is_trained = True
                self.stats["is_trained"] = True

            logger.info("Model loaded from %s", self.MODEL_PATH)
            return True

        except (OSError, pickle.UnpicklingError, AttributeError) as exc:
            logger.error("Failed to load model: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _save_stats(self) -> None:
        """Persist training statistics as JSON to ``STATS_PATH``."""
        try:
            os.makedirs(os.path.dirname(self.STATS_PATH) or ".", exist_ok=True)
            with self.training_lock:
                payload = dict(self.stats)
            with open(self.STATS_PATH, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        except OSError as exc:
            logger.error("Failed to save ML stats: %s", exc)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return the current engine status as a serialisable dict.

        Returns
        -------
        dict
            Keys: ``is_trained``, ``sample_count``, ``last_trained_at``,
            ``contamination``, ``n_estimators``, ``model_path``,
            ``drift_threshold``.
        """
        with self.training_lock:
            return {
                "is_trained":      self.stats.get("is_trained", False),
                "sample_count":    self.stats.get("sample_count", 0),
                "last_trained_at": self.stats.get("last_trained_at"),
                "contamination":   self.CONTAMINATION,
                "n_estimators":    100,
                "model_path":      self.MODEL_PATH,
                "drift_threshold": self.DRIFT_THRESHOLD,
            }

    def get_feature_importance_approx(self) -> Dict[str, float]:
        """Approximate per-feature importance via random perturbation.

        For each feature a small random perturbation is applied to 10 held-out
        samples drawn from the training buffer.  The average absolute change in
        the raw ``decision_function`` score is used as a proxy for importance.

        Returns
        -------
        dict
            Mapping ``{feature_name: importance_score}`` sorted descending by
            importance.  Returns an empty dict if the model is not trained or
            sklearn is unavailable.
        """
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return {}

        with self.training_lock:
            buffer_copy = list(self.sample_buffer)

        if len(buffer_copy) < 1:
            return {}

        import random  # stdlib — only imported when actually called

        # Use up to 10 samples
        samples = random.sample(buffer_copy, min(10, len(buffer_copy)))
        X = np.array(samples, dtype=np.float64)

        try:
            X_scaled = self.scaler.transform(X)  # type: ignore[union-attr]
            base_scores = self.model.decision_function(X_scaled)  # type: ignore[union-attr]
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Feature importance computation failed: %s", exc)
            return {}

        importance: Dict[str, float] = {}
        perturbation = 0.1

        for idx, name in enumerate(FEATURE_NAMES):
            X_perturbed = X_scaled.copy()
            X_perturbed[:, idx] += perturbation  # nudge feature by 0.1 std

            perturbed_scores = self.model.decision_function(X_perturbed)  # type: ignore[union-attr]
            avg_delta = float(np.mean(np.abs(perturbed_scores - base_scores)))
            importance[name] = round(avg_delta, 6)

        # Sort descending
        importance = dict(
            sorted(importance.items(), key=lambda kv: kv[1], reverse=True)
        )
        return importance


# ---------------------------------------------------------------------------
# Module-level singleton — loaded on import
# ---------------------------------------------------------------------------

ml_engine = IsolationForestEngine()
ml_engine.load_model()
