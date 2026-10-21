"""Adversarial Suffix & Perplexity Anomaly Detector.

Detects automated adversarial jailbreak payloads such as Greedy Coordinate Gradient
(GCG) suffixes, repeated punctuation perturbations, and anomalous token sequences
designed to bypass semantic keyword filters without requiring heavy neural networks.
"""

import re
import time
from typing import Any, Dict, List, Set, Tuple


class AdversarialSuffixDetector:
    """Lightweight statistical detector for automated adversarial jailbreak suffixes."""

    # Top English bigrams based on standard corpus frequency
    COMMON_BIGRAMS: Set[str] = {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
        "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    }

    PUNCT_BURST_PATTERN = re.compile(r"([!@#$%^&*()_+\-=\[\]{};':\",.<>?/\\|~`]{3,})")

    def __init__(self, anomaly_threshold: float = 0.65) -> None:
        self.anomaly_threshold = anomaly_threshold

    def calculate_bigram_anomaly_ratio(self, text: str) -> float:
        """Measure the fraction of character bigrams that are statistically rare in natural text."""
        cleaned = re.sub(r"[^a-zA-Z]", "", text.lower())
        if len(cleaned) < 6:
            return 0.0

        total_bigrams = len(cleaned) - 1
        common_count = sum(
            1 for i in range(total_bigrams) if cleaned[i : i + 2] in self.COMMON_BIGRAMS
        )

        # Expected ratio of common bigrams in natural English is ~0.40 - 0.70
        observed_ratio = common_count / float(total_bigrams)
        if observed_ratio < 0.12:
            # Severely anomalous character transitions (likely GCG or scrambled tokens)
            return min(1.0, (0.15 - observed_ratio) * 6.0 + 0.4)
        return 0.0

    def detect_punctuation_bursts(self, text: str) -> Tuple[bool, int, List[str]]:
        """Detect clusters of non-alphanumeric punctuation bursts common in GCG jailbreaks."""
        matches = self.PUNCT_BURST_PATTERN.findall(text)
        burst_count = len(matches)
        total_burst_chars = sum(len(m) for m in matches)
        is_suspicious = burst_count >= 2 or total_burst_chars >= 8
        return is_suspicious, burst_count, matches

    def analyze(self, text: str) -> Dict[str, Any]:
        """Inspect text and return adversarial suffix analysis and anomaly score."""
        t0 = time.perf_counter()
        bigram_anomaly = self.calculate_bigram_anomaly_ratio(text)
        has_bursts, burst_count, bursts = self.detect_punctuation_bursts(text)

        score = bigram_anomaly
        reasons: List[str] = []

        if has_bursts:
            score += 0.45
            reasons.append(f"Anomalous punctuation burst clusters detected: {bursts[:3]}")

        if bigram_anomaly > 0.3:
            reasons.append("Statistically unnatural character transition distribution (possible GCG token)")

        score = min(1.0, score)
        is_adversarial = score >= self.anomaly_threshold
        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "is_adversarial": is_adversarial,
            "anomaly_score": score,
            "reasons": reasons,
            "latency_ms": latency_ms,
        }
