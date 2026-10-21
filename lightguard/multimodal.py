"""Multimodal & Vision Metadata Prompt Injection Shield.

Detects and neutralizes prompt injections hidden inside image EXIF/metadata,
SVG vector graphics, and document text streams before they reach Vision-Language
Models (VLMs) or document-processing agents.
"""

import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from lightguard.core import LightGuardAgent

# Register standard SVG namespaces to avoid ns0: prefixes
ET.register_namespace("", "http://www.w3.org/2000/svg")
ET.register_namespace("xlink", "http://www.w3.org/1999/xlink")


class MultimodalShield:
    """Zero-dependency shield against multimodal & metadata indirect prompt injections."""

    DANGEROUS_TAGS = {
        "script",
        "foreignobject",
        "animate",
        "set",
        "audio",
        "video",
        "embed",
        "object",
        "iframe",
        "meta",
        "link",
        "applet",
        "base",
    }

    def __init__(self, guard: Optional[LightGuardAgent] = None) -> None:
        self.guard = guard if guard is not None else LightGuardAgent()

    def sanitize_svg(self, svg_content: str) -> Dict[str, Any]:
        """Scan and sanitize SVG vector files for embedded scripts, XXE, or hidden text injections."""
        t0 = time.perf_counter()
        threats: List[str] = []
        is_compromised = False
        is_suspicious = False
        is_sanitized = False
        is_rejected = False

        # 1. XXE / DTD Injection Detection
        if re.search(r"<!DOCTYPE[^>]*\b(SYSTEM|PUBLIC|ENTITY)\b", svg_content, re.IGNORECASE):
            threats.append("XXE external entity / DTD declaration detected in SVG")
            is_compromised = True
            is_suspicious = True
            is_sanitized = True
            is_rejected = True
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "is_compromised": is_compromised,
                "is_suspicious": is_suspicious,
                "is_sanitized": is_sanitized,
                "is_rejected": is_rejected,
                "threats": threats,
                "sanitized_svg": "<!-- [LIGHTGUARD_STRIPPED_XXE] -->",
                "latency_ms": latency_ms,
            }

        # Remove XML declaration and comments before parsing
        clean_xml_input = re.sub(r"<\?xml[^>]*\?>", "", svg_content)
        clean_xml_input = re.sub(r"<!DOCTYPE[^>]*>", "", clean_xml_input)

        try:
            # Parse XML tree safely without resolving entities
            parser = ET.XMLParser()
            root = ET.fromstring(clean_xml_input, parser=parser)
        except Exception:
            # Fallback to safe rejection if malformed XML contains dangerous markers
            lower_raw = svg_content.lower()
            if "<script" in lower_raw or "onload" in lower_raw or "javascript:" in lower_raw:
                is_compromised = True
                is_sanitized = True
                is_rejected = True
                threats.append("Malformed SVG containing dangerous script patterns rejected")
                latency_ms = (time.perf_counter() - t0) * 1000.0
                return {
                    "is_compromised": is_compromised,
                    "is_suspicious": is_suspicious,
                    "is_sanitized": is_sanitized,
                    "is_rejected": is_rejected,
                    "threats": threats,
                    "sanitized_svg": "<!-- [LIGHTGUARD_REJECTED_MALFORMED_SVG] -->",
                    "latency_ms": latency_ms,
                }
            # Pure XML parse failure without malicious patterns
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "is_compromised": False,
                "is_suspicious": False,
                "is_sanitized": False,
                "is_rejected": True,
                "threats": ["Invalid XML syntax in SVG content"],
                "sanitized_svg": svg_content,
                "latency_ms": latency_ms,
            }

        def clean_element(elem: ET.Element) -> None:
            nonlocal is_compromised, is_suspicious, is_sanitized

            # Check and sanitize attributes on current element
            attrs_to_remove = []
            for attr_name, attr_val in list(elem.attrib.items()):
                local_attr = attr_name.split("}")[-1].lower()
                val_str = str(attr_val).strip()
                val_lower = val_str.lower()

                # Event handlers (onload, onclick, onerror, etc.)
                if local_attr.startswith("on"):
                    threats.append(f"Executable event handler '{attr_name}' stripped")
                    is_compromised = True
                    is_sanitized = True
                    attrs_to_remove.append(attr_name)

                # Dangerous URI protocols
                elif "href" in local_attr or "src" in local_attr:
                    if val_lower.startswith(("javascript:", "vbscript:", "data:text/html")):
                        threats.append(f"Executable script URI stripped from '{attr_name}'")
                        is_compromised = True
                        is_sanitized = True
                        attrs_to_remove.append(attr_name)

            for a in attrs_to_remove:
                del elem.attrib[a]

            # Check hidden styling
            is_hidden = False
            for k, v in elem.attrib.items():
                k_lower = k.lower()
                v_lower = str(v).lower()
                if k_lower in ("display", "visibility", "opacity", "font-size"):
                    if v_lower in ("none", "hidden", "0", "0px"):
                        is_hidden = True

            style_val = elem.attrib.get("style", "").lower()
            if any(h in style_val for h in ("display:none", "display: none", "opacity:0", "opacity: 0", "visibility:hidden")):
                is_hidden = True

            # Inspect and sanitize text content
            if elem.text and elem.text.strip():
                obs = self.guard.process_observation(elem.text)
                if obs["is_untrusted"]:
                    threat_desc = f"Prompt injection in SVG text: {obs['threat_categories']}"
                    if is_hidden:
                        threat_desc = f"Malicious hidden SVG text payload: {obs['threat_categories']}"
                    threats.append(threat_desc)
                    is_compromised = True
                    is_suspicious = True
                    is_sanitized = True
                    elem.text = obs.get("clean_text") or obs.get("sanitized_observation") or "[SANITIZED_TEXT]"

            # Recursively inspect and filter children
            children_to_remove = []
            comment_placeholders = []
            for child in list(elem):
                child_tag = child.tag.split("}")[-1].lower()
                if child_tag in self.DANGEROUS_TAGS:
                    threats.append(f"SVG embedded executable or dangerous element <{child_tag}> detected")
                    is_compromised = True
                    is_sanitized = True
                    children_to_remove.append(child)
                    marker = "LIGHTGUARD_STRIPPED_SCRIPT" if child_tag == "script" else "LIGHTGUARD_STRIPPED_ELEMENT"
                    comment_placeholders.append(ET.Comment(f" [{marker}] "))
                else:
                    # Check hidden text tag
                    c_hidden = False
                    for k, v in child.attrib.items():
                        if k.lower() in ("display", "visibility", "opacity", "font-size") and str(v).lower() in ("none", "hidden", "0", "0px"):
                            c_hidden = True
                    c_style = child.attrib.get("style", "").lower()
                    if any(h in c_style for h in ("display:none", "display: none", "opacity:0", "opacity: 0", "visibility:hidden")):
                        c_hidden = True

                    if c_hidden and child.text and child.text.strip():
                        obs = self.guard.process_observation(child.text)
                        if obs["is_untrusted"]:
                            threats.append(f"Malicious hidden SVG text payload: {obs['threat_categories']}")
                            is_compromised = True
                            is_suspicious = True
                            is_sanitized = True
                            children_to_remove.append(child)
                            comment_placeholders.append(ET.Comment(" [LIGHTGUARD_STRIPPED_HIDDEN_TEXT] "))
                            continue

                    clean_element(child)

            for c in children_to_remove:
                elem.remove(c)
            for comment in comment_placeholders:
                elem.append(comment)

        clean_element(root)

        # Serialize cleaned SVG tree back to string
        sanitized_svg = ET.tostring(root, encoding="unicode")
        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "is_compromised": is_compromised,
            "is_suspicious": is_suspicious,
            "is_sanitized": is_sanitized,
            "is_rejected": is_rejected,
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
