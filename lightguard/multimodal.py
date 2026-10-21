"""Multimodal & Vision Metadata Prompt Injection Shield.

Detects and neutralizes prompt injections hidden inside image EXIF/metadata,
SVG vector graphics, and document text streams before they reach Vision-Language
Models (VLMs) or document-processing agents.
"""

import re
import time
from typing import Any, Dict, List, Optional

from lightguard.core import LightGuardAgent


class MultimodalShield:
    """Zero-dependency shield against multimodal & metadata indirect prompt injections."""

    def __init__(self, guard: Optional[LightGuardAgent] = None) -> None:
        self.guard = guard if guard is not None else LightGuardAgent()

    def sanitize_svg(self, svg_content: str) -> Dict[str, Any]:
        """Scan and sanitize SVG vector files for embedded scripts or hidden text injections."""
        t0 = time.perf_counter()
        threats: List[str] = []
        is_compromised = False
        sanitized_svg = svg_content

        # 1. Detect and strip <script> tags
        if re.search(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", svg_content, re.IGNORECASE | re.DOTALL):
            threats.append("SVG embedded executable <script> detected")
            is_compromised = True
            sanitized_svg = re.sub(
                r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
                "<!-- [LIGHTGUARD_STRIPPED_SCRIPT] -->",
                sanitized_svg,
                flags=re.IGNORECASE | re.DOTALL,
            )

        # 2. Detect hidden text elements (opacity:0, display:none, font-size:0)
        hidden_pattern = re.compile(
            r"<\s*text\b[^>]*?(?:display\s*=\s*['\"]none['\"]|opacity\s*=\s*['\"]0['\"]|font-size\s*=\s*['\"]0['\"]|visibility\s*=\s*['\"]hidden['\"]).*?>(.*?)</\s*text\s*>",
            re.IGNORECASE | re.DOTALL,
        )
        hidden_matches = hidden_pattern.findall(svg_content)
        for hidden_text in hidden_matches:
            obs = self.guard.process_observation(hidden_text)
            if obs["is_untrusted"]:
                threats.append(f"Malicious hidden SVG text payload: {obs['threat_categories']}")
                is_compromised = True

        sanitized_svg = hidden_pattern.sub(
            "<!-- [LIGHTGUARD_STRIPPED_HIDDEN_TEXT] -->",
            sanitized_svg,
        )

        # 3. Scan all visible text nodes
        text_matches = re.findall(r"<\s*text\b[^>]*>(.*?)</\s*text\s*>", svg_content, re.IGNORECASE | re.DOTALL)
        for t in text_matches:
            obs = self.guard.process_observation(t)
            if obs["is_untrusted"]:
                threats.append(f"Prompt injection in SVG text: {obs['threat_categories']}")
                is_compromised = True

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "is_compromised": is_compromised,
            "threats": threats,
            "sanitized_svg": sanitized_svg,
            "latency_ms": latency_ms,
        }

    def scan_metadata_strings(self, metadata_dict: Dict[str, str]) -> Dict[str, Any]:
        """Scan extracted EXIF/PDF/XMP metadata fields for prompt injection payloads."""
        t0 = time.perf_counter()
        threats: List[str] = []
        is_compromised = False
        clean_metadata: Dict[str, str] = {}

        for key, val in metadata_dict.items():
            if not isinstance(val, str):
                clean_metadata[key] = str(val)
                continue

            obs = self.guard.process_observation(val)
            if obs["is_untrusted"]:
                threats.append(f"Metadata tag '{key}' poisoned: {obs['threat_categories']}")
                is_compromised = True
                clean_metadata[key] = obs["clean_text"]
            else:
                clean_metadata[key] = val

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "is_compromised": is_compromised,
            "threats": threats,
            "clean_metadata": clean_metadata,
            "latency_ms": latency_ms,
        }
